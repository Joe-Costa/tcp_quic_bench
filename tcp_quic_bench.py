#!/usr/bin/env python3
"""
tcp_quic_bench.py

TCP vs QUIC benchmark tool.

- Server mode: runs TCP and/or QUIC servers.
- Client mode: runs benchmarks against the server.

Modes:
  - throughput: client sends data to server; measures throughput.
  - rtt: client sends small messages and expects echo; measures RTT.

QUIC uses aioquic. Packet loss and latency can be induced via tc netem
on the Linux server side, either externally or using the --netem-* options
(requires root on Linux).
"""

import argparse
import asyncio
import atexit
import os
import platform
import signal
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import List, Optional

# QUIC dependencies
from aioquic.asyncio import serve, connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import StreamDataReceived


# -----------------------------
# Common data structures
# -----------------------------

@dataclass
class ThroughputResult:
    stream_id: int
    bytes_sent: int
    duration: float


@dataclass
class RTTResult:
    stream_id: int
    rtts: List[float]


# -----------------------------
# TCP Congestion Control
# -----------------------------

def set_tcp_congestion_control(algorithm: str = "bbr") -> bool:
    """
    Set TCP congestion control algorithm (Linux only, requires root).
    Returns True if successful, False otherwise.
    """
    if platform.system() != "Linux":
        return False
    if os.geteuid() != 0:
        return False

    try:
        subprocess.run(
            ["sysctl", "-w", f"net.ipv4.tcp_congestion_control={algorithm}"],
            capture_output=True, check=True
        )
        print(f"[tcp] Congestion control set to {algorithm}")
        return True
    except subprocess.CalledProcessError:
        return False


# -----------------------------
# Network Impairment Controller
# -----------------------------

class NetemController:
    """
    Manages tc netem rules for benchmark traffic only.

    Applies network impairments (delay, jitter, loss) to specific ports
    using Linux tc with u32 filters. Requires root privileges on Linux.
    """

    def __init__(self, interface: Optional[str], tcp_port: int, udp_port: int):
        self.interface = interface
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self._applied = False

    def check_prerequisites(self) -> None:
        """Check that we're on Linux with root privileges."""
        if platform.system() != "Linux":
            raise RuntimeError(
                "Network impairment via tc requires Linux. "
                "On other platforms, use external tools or run server on Linux."
            )
        if os.geteuid() != 0:
            raise RuntimeError(
                "Network impairment via tc requires root privileges. "
                "Run with sudo or as root."
            )

    def detect_interface(self) -> str:
        """Auto-detect the default network interface."""
        try:
            # Use ip route to find the default interface
            result = subprocess.run(
                ["ip", "route", "get", "8.8.8.8"],
                capture_output=True, text=True, check=True
            )
            # Parse output: "8.8.8.8 via 192.168.1.1 dev eth0 src ..."
            for part in result.stdout.split():
                if part.startswith("dev"):
                    continue
                # The word after "dev" is the interface
                parts = result.stdout.split()
                if "dev" in parts:
                    idx = parts.index("dev")
                    if idx + 1 < len(parts):
                        return parts[idx + 1]
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

        # Fallback: try common interface names
        for iface in ["eth0", "ens33", "enp0s3", "ens160"]:
            if os.path.exists(f"/sys/class/net/{iface}"):
                return iface

        raise RuntimeError(
            "Could not auto-detect network interface. "
            "Please specify with --netem-iface."
        )

    def _run_tc(self, args: List[str], check: bool = True) -> bool:
        """Run a tc command."""
        cmd = ["tc"] + args
        try:
            subprocess.run(cmd, capture_output=True, text=True, check=check)
            return True
        except subprocess.CalledProcessError as e:
            if check:
                print(f"tc command failed: {' '.join(cmd)}")
                print(f"stderr: {e.stderr}")
            return False

    def apply(self, delay_ms: Optional[int], jitter_ms: Optional[int],
              loss_pct: Optional[float]) -> None:
        """Apply netem rules to benchmark ports."""
        if self.interface is None:
            self.interface = self.detect_interface()

        # Build netem parameters
        netem_params = []
        if delay_ms is not None:
            if jitter_ms is not None:
                netem_params.extend(["delay", f"{delay_ms}ms", f"{jitter_ms}ms"])
            else:
                netem_params.extend(["delay", f"{delay_ms}ms"])
        if loss_pct is not None and loss_pct > 0:
            netem_params.extend(["loss", f"{loss_pct}%"])

        if not netem_params:
            return  # Nothing to apply

        # Clean up any existing rules first
        self._run_tc(["qdisc", "del", "dev", self.interface, "root"], check=False)

        # Add root prio qdisc
        if not self._run_tc(["qdisc", "add", "dev", self.interface,
                             "root", "handle", "1:", "prio"]):
            raise RuntimeError("Failed to add root qdisc")

        # TCP filter and netem (protocol 6 = TCP)
        self._run_tc([
            "filter", "add", "dev", self.interface,
            "protocol", "ip", "parent", "1:0", "prio", "1", "u32",
            "match", "ip", "protocol", "6", "0xff",
            "match", "ip", "dport", str(self.tcp_port), "0xffff",
            "flowid", "1:1"
        ])
        self._run_tc([
            "qdisc", "add", "dev", self.interface,
            "parent", "1:1", "handle", "10:", "netem"
        ] + netem_params)

        # UDP filter and netem (protocol 17 = UDP)
        self._run_tc([
            "filter", "add", "dev", self.interface,
            "protocol", "ip", "parent", "1:0", "prio", "2", "u32",
            "match", "ip", "protocol", "17", "0xff",
            "match", "ip", "dport", str(self.udp_port), "0xffff",
            "flowid", "1:2"
        ])
        self._run_tc([
            "qdisc", "add", "dev", self.interface,
            "parent", "1:2", "handle", "20:", "netem"
        ] + netem_params)

        self._applied = True
        print(f"[netem] Applied to {self.interface}: {' '.join(netem_params)}")
        print(f"[netem] Affecting TCP port {self.tcp_port}, UDP port {self.udp_port}")

    def cleanup(self) -> None:
        """Remove all tc rules."""
        if not self._applied:
            return
        if self.interface:
            self._run_tc(["qdisc", "del", "dev", self.interface, "root"], check=False)
            print(f"[netem] Cleaned up rules on {self.interface}")
        self._applied = False


# Global controller for signal handler access
_netem_controller: Optional[NetemController] = None


def _netem_cleanup_handler(signum=None, frame=None):
    """Signal handler to clean up netem rules."""
    global _netem_controller
    if _netem_controller:
        _netem_controller.cleanup()
        _netem_controller = None
    if signum is not None:
        sys.exit(0)


# -----------------------------
# TCP SERVER
# -----------------------------

async def handle_tcp_throughput(reader: asyncio.StreamReader,
                                writer: asyncio.StreamWriter):
    addr = writer.get_extra_info("peername")
    start = time.perf_counter()
    total = 0
    try:
        while True:
            data = await reader.read(64 * 1024)
            if not data:
                break
            total += len(data)
    finally:
        end = time.perf_counter()
        duration = max(end - start, 1e-9)
        mbps = total * 8 / duration / 1e6
        print(f"[TCP throughput] {addr} -> received {total} bytes "
              f"in {duration:.3f}s ({mbps:.2f} Mbit/s)")
        writer.close()
        await writer.wait_closed()


async def handle_tcp_rtt(reader: asyncio.StreamReader,
                         writer: asyncio.StreamWriter):
    """
    RTT server: echo back any data received.
    Client enforces ping boundaries by send -> wait echo -> next.
    """
    addr = writer.get_extra_info("peername")
    print(f"[TCP rtt] connection from {addr}")
    try:
        while True:
            data = await reader.read(64 * 1024)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()
        print(f"[TCP rtt] connection from {addr} closed")


async def run_tcp_server(host: str, port: int, mode: str):
    handler = handle_tcp_throughput if mode == "throughput" else handle_tcp_rtt
    server = await asyncio.start_server(handler, host, port)
    addr = ", ".join(str(s.getsockname()) for s in server.sockets)
    print(f"[TCP] {mode} server listening on {addr}")
    async with server:
        await server.serve_forever()


# -----------------------------
# QUIC SERVER
# -----------------------------

class BenchmarkQuicServerProtocol(QuicConnectionProtocol):
    """
    QUIC server protocol.

    - throughput: consume data on streams and discard.
    - rtt: echo data back on the same stream.
    """
    def __init__(self, *args, mode: str = "throughput", **kwargs):
        super().__init__(*args, **kwargs)
        self.mode = mode

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            # Throughput mode: just discard
            if self.mode == "throughput":
                # Could count bytes here if you want server-side stats.
                pass

            # RTT mode: immediate echo
            elif self.mode == "rtt":
                self._quic.send_stream_data(
                    event.stream_id, event.data, end_stream=False
                )
                self.transmit()


async def run_quic_server(host: str,
                          port: int,
                          mode: str,
                          cert: str,
                          key: str):
    configuration = QuicConfiguration(
        is_client=False,
        alpn_protocols=["bench"],
        congestion_control_algorithm="bbr",
    )
    configuration.load_cert_chain(cert, key)

    print(f"[QUIC] {mode} server listening on {host}:{port}")
    await serve(
        host,
        port,
        configuration=configuration,
        create_protocol=lambda *args, **kwargs: BenchmarkQuicServerProtocol(
            *args, mode=mode, **kwargs
        ),
    )


# -----------------------------
# TCP CLIENT
# -----------------------------

async def tcp_throughput_stream(
    stream_id: int,
    host: str,
    port: int,
    bytes_to_send: int,
    chunk_size: int = 64 * 1024,
) -> Optional[ThroughputResult]:
    try:
        reader, writer = await asyncio.open_connection(host, port)
    except OSError as e:
        print(f"  Stream {stream_id}: connection failed: {e}")
        return None
    # Use random data to avoid trivial compression by middleboxes.
    payload = os.urandom(chunk_size)

    sent = 0
    start = time.perf_counter()
    while sent < bytes_to_send:
        remaining = bytes_to_send - sent
        buf = payload if remaining >= chunk_size else payload[:remaining]
        writer.write(buf)
        await writer.drain()
        sent += len(buf)
    end = time.perf_counter()

    writer.close()
    await writer.wait_closed()

    duration = max(end - start, 1e-9)
    return ThroughputResult(stream_id=stream_id,
                            bytes_sent=sent,
                            duration=duration)


async def tcp_rtt_stream(
    stream_id: int,
    host: str,
    port: int,
    pings: int,
    message_size: int,
) -> Optional[RTTResult]:
    try:
        reader, writer = await asyncio.open_connection(host, port)
    except OSError as e:
        print(f"  Stream {stream_id}: connection failed: {e}")
        return None
    payload = os.urandom(message_size)
    rtts: List[float] = []

    for _ in range(pings):
        t0 = time.perf_counter()
        writer.write(payload)
        await writer.drain()
        await reader.readexactly(message_size)
        t1 = time.perf_counter()
        rtts.append(t1 - t0)

    writer.close()
    await writer.wait_closed()
    return RTTResult(stream_id=stream_id, rtts=rtts)


# -----------------------------
# QUIC CLIENT
# -----------------------------

async def quic_throughput_stream(
    stream_id: int,
    connection: QuicConnectionProtocol,
    bytes_to_send: int,
    chunk_size: int = 64 * 1024,
) -> ThroughputResult:
    """
    One QUIC stream for throughput.
    """
    payload = os.urandom(chunk_size)
    sent = 0
    quic = connection._quic

    # Allocate a fresh bidirectional stream id for this logical stream_id
    sid = quic.get_next_available_stream_id(is_unidirectional=False)
    start = time.perf_counter()
    try:
        while sent < bytes_to_send:
            remaining = bytes_to_send - sent
            buf = payload if remaining >= chunk_size else payload[:remaining]
            quic.send_stream_data(sid, buf, end_stream=False)
            sent += len(buf)
            connection.transmit()
        # Graceful end-of-stream
        quic.send_stream_data(sid, b"", end_stream=True)
        connection.transmit()
    finally:
        end = time.perf_counter()

    duration = max(end - start, 1e-9)
    return ThroughputResult(stream_id=stream_id,
                            bytes_sent=sent,
                            duration=duration)


class QuicRTTClientProtocol(QuicConnectionProtocol):
    """
    Simple protocol that lets us do RTT pings on a single stream.
    We echo is done by the server; here we just read back what we send.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._streams = {}  # stream_id -> asyncio.Queue of bytes

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            q = self._streams.get(event.stream_id)
            if q is not None:
                # Buffer data for whoever is waiting
                q.put_nowait(event.data)

    async def ping_stream(self, pings: int, message_size: int) -> List[float]:
        quic = self._quic
        sid = quic.get_next_available_stream_id(is_unidirectional=False)
        q: asyncio.Queue = asyncio.Queue()
        self._streams[sid] = q

        rtts: List[float] = []
        payload = b"x" * message_size

        for _ in range(pings):
            t0 = time.perf_counter()
            quic.send_stream_data(sid, payload, end_stream=False)
            self.transmit()
            received = 0
            # Collect exactly message_size bytes from echoed data
            while received < message_size:
                chunk = await q.get()
                received += len(chunk)
            t1 = time.perf_counter()
            rtts.append(t1 - t0)

        # Close stream gracefully
        quic.send_stream_data(sid, b"", end_stream=True)
        self.transmit()
        return rtts


async def run_quic_throughput_client(
    host: str,
    port: int,
    total_bytes: int,
    streams: int,
    alpn: str = "bench",
    insecure: bool = True,
) -> List[ThroughputResult]:
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=[alpn],
        server_name=host,
        congestion_control_algorithm="bbr",
    )
    # For lab benchmarking we usually allow self-signed certs
    if insecure:
        configuration.verify_mode = False

    bytes_per_stream = total_bytes // streams
    remainder = total_bytes % streams

    try:
        async with connect(
            host,
            port,
            configuration=configuration,
            create_protocol=QuicConnectionProtocol,
        ) as client:
            client: QuicConnectionProtocol
            tasks = []
            for i in range(streams):
                # Distribute any remainder to the first streams
                extra = 1 if i < remainder else 0
                bs = bytes_per_stream + extra
                if bs == 0:
                    continue
                tasks.append(
                    quic_throughput_stream(
                        stream_id=i,
                        connection=client,
                        bytes_to_send=bs,
                    )
                )
            results = await asyncio.gather(*tasks)
            # Brief wait for final packets to flush
            await asyncio.sleep(0.1)
        return results
    except OSError as e:
        print(f"  QUIC connection failed: {e}")
        return []


async def run_quic_rtt_client(
    host: str,
    port: int,
    streams: int,
    pings: int,
    message_size: int,
    alpn: str = "bench",
    insecure: bool = True,
) -> List[RTTResult]:
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=[alpn],
        server_name=host,
        congestion_control_algorithm="bbr",
    )
    if insecure:
        configuration.verify_mode = False

    try:
        async with connect(
            host,
            port,
            configuration=configuration,
            create_protocol=QuicRTTClientProtocol,
        ) as client:
            client: QuicRTTClientProtocol
            tasks = []
            for i in range(streams):
                tasks.append(client.ping_stream(pings=pings, message_size=message_size))
            rtts_list = await asyncio.gather(*tasks)

        results = []
        for i, rtts in enumerate(rtts_list):
            results.append(RTTResult(stream_id=i, rtts=rtts))
        return results
    except OSError as e:
        print(f"  QUIC connection failed: {e}")
        return []


# -----------------------------
# CLIENT RUNNERS (TOP LEVEL)
# -----------------------------

async def run_client_throughput(
    protocol: str,
    host: str,
    tcp_port: int,
    quic_port: int,
    total_bytes: int,
    streams: int,
    runs: int,
):
    for run in range(1, runs + 1):
        print(f"\n=== Throughput run {run}/{runs} ({protocol.upper()}) ===")

        if protocol == "tcp":
            tasks = []
            bytes_per_stream = total_bytes // streams
            remainder = total_bytes % streams
            start = time.perf_counter()
            for i in range(streams):
                extra = 1 if i < remainder else 0
                bs = bytes_per_stream + extra
                if bs == 0:
                    continue
                tasks.append(
                    tcp_throughput_stream(
                        stream_id=i,
                        host=host,
                        port=tcp_port,
                        bytes_to_send=bs,
                    )
                )
            results = await asyncio.gather(*tasks)
            end = time.perf_counter()
        else:  # quic
            start = time.perf_counter()
            results = await run_quic_throughput_client(
                host=host,
                port=quic_port,
                total_bytes=total_bytes,
                streams=streams,
            )
            end = time.perf_counter()

        # Filter out failed connections
        results = [r for r in results if r is not None]
        if not results:
            print("  All connections failed!")
            continue

        elapsed = max(end - start, 1e-9)
        total_sent = sum(r.bytes_sent for r in results)
        total_mbps = total_sent * 8 / elapsed / 1e6

        for r in results:
            mbps = r.bytes_sent * 8 / r.duration / 1e6
            print(f"  Stream {r.stream_id}: {r.bytes_sent} bytes "
                  f"in {r.duration:.3f}s ({mbps:.2f} Mbit/s)")

        print(f"  TOTAL: {total_sent} bytes in {elapsed:.3f}s "
              f"({total_mbps:.2f} Mbit/s)")


async def run_client_rtt(
    protocol: str,
    host: str,
    tcp_port: int,
    quic_port: int,
    streams: int,
    pings: int,
    message_size: int,
    runs: int,
):
    for run in range(1, runs + 1):
        print(f"\n=== RTT run {run}/{runs} ({protocol.upper()}) ===")

        if protocol == "tcp":
            tasks = []
            for i in range(streams):
                tasks.append(
                    tcp_rtt_stream(
                        stream_id=i,
                        host=host,
                        port=tcp_port,
                        pings=pings,
                        message_size=message_size,
                    )
                )
            results = await asyncio.gather(*tasks)
        else:
            results = await run_quic_rtt_client(
                host=host,
                port=quic_port,
                streams=streams,
                pings=pings,
                message_size=message_size,
            )

        # Filter out failed connections
        results = [r for r in results if r is not None]
        if not results:
            print("  All connections failed!")
            continue

        all_rtts = []
        for r in results:
            if not r.rtts:
                continue
            avg = statistics.mean(r.rtts)
            sorted_rtts = sorted(r.rtts)
            p95_idx = int(len(sorted_rtts) * 0.95)
            p95 = sorted_rtts[min(p95_idx, len(sorted_rtts) - 1)]
            print(f"  Stream {r.stream_id}: "
                  f"pings={len(r.rtts)}, avg={avg*1000:.3f} ms, "
                  f"min={min(r.rtts)*1000:.3f} ms, "
                  f"max={max(r.rtts)*1000:.3f} ms, "
                  f"p95={p95*1000:.3f} ms")
            all_rtts.extend(r.rtts)

        if all_rtts:
            avg = statistics.mean(all_rtts)
            sorted_all = sorted(all_rtts)
            p95_idx = int(len(sorted_all) * 0.95)
            p95 = sorted_all[min(p95_idx, len(sorted_all) - 1)]
            print(f"  OVERALL: pings={len(all_rtts)}, avg={avg*1000:.3f} ms, "
                  f"min={min(all_rtts)*1000:.3f} ms, "
                  f"max={max(all_rtts)*1000:.3f} ms, "
                  f"p95={p95*1000:.3f} ms")


# -----------------------------
# CLI / MAIN
# -----------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description="TCP vs QUIC benchmark tool (throughput / RTT).",
    )
    subparsers = parser.add_subparsers(dest="role", required=True)

    # Server
    sp_server = subparsers.add_parser("server", help="Run in server mode")
    sp_server.add_argument("--host", default="0.0.0.0",
                           help="Bind address (default: 0.0.0.0)")
    sp_server.add_argument("--tcp-port", type=int, default=5000,
                           help="TCP port (default: 5000)")
    sp_server.add_argument("--quic-port", type=int, default=5001,
                           help="QUIC UDP port (default: 5001)")
    sp_server.add_argument("--protocol", choices=["tcp", "quic", "both"],
                           default="both", help="Which protocol servers to run")
    sp_server.add_argument("--mode", choices=["throughput", "rtt"],
                           default="throughput", help="Server mode")
    sp_server.add_argument("--quic-cert", default="cert.pem",
                           help="QUIC TLS certificate file")
    sp_server.add_argument("--quic-key", default="key.pem",
                           help="QUIC TLS key file")
    # Network impairment options (Linux root only)
    sp_server.add_argument("--netem-iface", default=None,
                           help="Network interface for tc rules (auto-detect if not set)")
    sp_server.add_argument("--netem-delay", type=int, default=None,
                           help="Add network delay in ms (e.g., 50)")
    sp_server.add_argument("--netem-jitter", type=int, default=None,
                           help="Add jitter in ms (requires --netem-delay)")
    sp_server.add_argument("--netem-loss", type=float, default=None,
                           help="Add packet loss percentage (e.g., 2.0)")

    # Client
    sp_client = subparsers.add_parser("client", help="Run in client mode")
    sp_client.add_argument("--server-host", required=True,
                           help="Server hostname or IP")
    sp_client.add_argument("--tcp-port", type=int, default=5000,
                           help="TCP port (default: 5000)")
    sp_client.add_argument("--quic-port", type=int, default=5001,
                           help="QUIC UDP port (default: 5001)")
    sp_client.add_argument("--protocol", choices=["tcp", "quic", "both"],
                           required=True, help="Protocol to benchmark")
    sp_client.add_argument("--mode", choices=["throughput", "rtt"],
                           default="throughput", help="Benchmark mode")
    sp_client.add_argument("--streams", type=int, default=1,
                           help="Parallel streams (connections for TCP, "
                                "streams for QUIC)")
    sp_client.add_argument("--runs", type=int, default=1,
                           help="Number of times to repeat the test")
    # Throughput options
    sp_client.add_argument("--bytes", type=int, default=100 * 1024 * 1024,
                           help="Total bytes per run (throughput mode)")
    # RTT options
    sp_client.add_argument("--pings", type=int, default=100,
                           help="Number of pings per stream (rtt mode)")
    sp_client.add_argument("--message-size", type=int, default=64,
                           help="Ping message size in bytes (rtt mode)")

    return parser.parse_args()


async def main_async():
    args = parse_args()

    if args.role == "server":
        global _netem_controller

        # Set TCP congestion control to BBR (Linux root only, silent fail otherwise)
        set_tcp_congestion_control("bbr")

        # Setup network impairment if requested
        netem_requested = any([
            args.netem_delay is not None,
            args.netem_loss is not None,
        ])
        if netem_requested:
            # Validate jitter requires delay
            if args.netem_jitter is not None and args.netem_delay is None:
                print("Error: --netem-jitter requires --netem-delay")
                return

            controller = NetemController(
                interface=args.netem_iface,
                tcp_port=args.tcp_port,
                udp_port=args.quic_port,
            )
            try:
                controller.check_prerequisites()
                controller.apply(
                    delay_ms=args.netem_delay,
                    jitter_ms=args.netem_jitter,
                    loss_pct=args.netem_loss,
                )
                _netem_controller = controller

                # Register cleanup handlers
                signal.signal(signal.SIGINT, _netem_cleanup_handler)
                signal.signal(signal.SIGTERM, _netem_cleanup_handler)
                atexit.register(_netem_cleanup_handler)
            except RuntimeError as e:
                print(f"Error: {e}")
                return

        tasks = []
        if args.protocol in ("tcp", "both"):
            tasks.append(run_tcp_server(args.host, args.tcp_port, args.mode))
        if args.protocol in ("quic", "both"):
            tasks.append(
                run_quic_server(
                    host=args.host,
                    port=args.quic_port,
                    mode=args.mode,
                    cert=args.quic_cert,
                    key=args.quic_key,
                )
            )
        try:
            await asyncio.gather(*tasks)
        finally:
            if _netem_controller:
                _netem_controller.cleanup()
                _netem_controller = None

    elif args.role == "client":
        # Determine which protocols to run
        if args.protocol == "both":
            protocols = ["tcp", "quic"]
        else:
            protocols = [args.protocol]

        if args.mode == "throughput":
            if args.bytes < args.streams:
                print(f"Error: --bytes ({args.bytes}) must be >= --streams ({args.streams})")
                return
            for protocol in protocols:
                await run_client_throughput(
                    protocol=protocol,
                    host=args.server_host,
                    tcp_port=args.tcp_port,
                    quic_port=args.quic_port,
                    total_bytes=args.bytes,
                    streams=args.streams,
                    runs=args.runs,
                )
        else:
            for protocol in protocols:
                await run_client_rtt(
                    protocol=protocol,
                    host=args.server_host,
                    tcp_port=args.tcp_port,
                    quic_port=args.quic_port,
                    streams=args.streams,
                    pings=args.pings,
                    message_size=args.message_size,
                    runs=args.runs,
                )


def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\nInterrupted, exiting.")


if __name__ == "__main__":
    main()
