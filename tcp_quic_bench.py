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

# Detect best available QUIC congestion control algorithm
def _get_quic_cc_algorithm() -> str:
    """Return 'bbr' if available, otherwise 'reno'."""
    try:
        # Try to import BBR directly - this forces registration
        from aioquic.quic.congestion.bbr import BbrCongestionControl  # noqa: F401
        return "bbr"
    except ImportError:
        return "reno"

QUIC_CC_ALGORITHM = _get_quic_cc_algorithm()


# -----------------------------
# Size parsing
# -----------------------------

def parse_size(s: str) -> int:
    """Parse human-readable size (e.g., '100MB', '1G', '500K') to bytes."""
    s = s.strip().upper()
    units = {'B': 1, 'K': 1024, 'KB': 1024, 'M': 1024**2, 'MB': 1024**2,
             'G': 1024**3, 'GB': 1024**3, 'T': 1024**4, 'TB': 1024**4}
    for suffix, mult in sorted(units.items(), key=lambda x: -len(x[0])):
        if s.endswith(suffix):
            return int(float(s[:-len(suffix)]) * mult)
    return int(s)  # Assume bytes if no suffix


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
    """
    Bidirectional throughput handler.
    Client sends control line: "UPLOAD <bytes>\n" or "DOWNLOAD <bytes>\n"
    """
    addr = writer.get_extra_info("peername")
    try:
        # Read control line
        line = await reader.readline()
        if not line:
            return
        parts = line.decode().strip().split()
        if len(parts) != 2:
            print(f"[TCP throughput] {addr} -> invalid control line: {line}")
            return
        cmd, size_str = parts
        size = int(size_str)

        if cmd == "UPLOAD":
            # Receive data from client
            start = time.perf_counter()
            total = 0
            while total < size:
                data = await reader.read(64 * 1024)
                if not data:
                    break
                total += len(data)
            end = time.perf_counter()
            duration = max(end - start, 1e-9)
            mbps = total * 8 / duration / 1e6
            print(f"[TCP throughput] {addr} -> received {total} bytes "
                  f"in {duration:.3f}s ({mbps:.2f} Mbit/s)")

        elif cmd == "DOWNLOAD":
            # Send data to client
            chunk_size = 64 * 1024
            payload = os.urandom(chunk_size)
            sent = 0
            start = time.perf_counter()
            while sent < size:
                remaining = size - sent
                buf = payload if remaining >= chunk_size else payload[:remaining]
                writer.write(buf)
                await writer.drain()
                sent += len(buf)
            end = time.perf_counter()
            duration = max(end - start, 1e-9)
            mbps = sent * 8 / duration / 1e6
            print(f"[TCP throughput] {addr} -> sent {sent} bytes "
                  f"in {duration:.3f}s ({mbps:.2f} Mbit/s)")

    except Exception as e:
        print(f"[TCP throughput] {addr} -> error: {e}")
    finally:
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

    - throughput: bidirectional data transfer (upload/download).
    - rtt: echo data back on the same stream.
    """
    def __init__(self, *args, mode: str = "throughput", **kwargs):
        super().__init__(*args, **kwargs)
        self.mode = mode
        # Per-stream state for throughput
        self._stream_state: dict[int, dict] = {}

    def _get_stream_state(self, stream_id: int) -> dict:
        if stream_id not in self._stream_state:
            self._stream_state[stream_id] = {
                "buffer": b"",
                "cmd": None,
                "size": 0,
                "bytes_transferred": 0,
                "start_time": None,
            }
        return self._stream_state[stream_id]

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            if self.mode == "throughput":
                self._handle_throughput_event(event)
            elif self.mode == "rtt":
                self._quic.send_stream_data(
                    event.stream_id, event.data, end_stream=False
                )
                self.transmit()

    def _handle_throughput_event(self, event: StreamDataReceived):
        state = self._get_stream_state(event.stream_id)

        # If we haven't parsed the control line yet
        if state["cmd"] is None:
            state["buffer"] += event.data
            if b"\n" in state["buffer"]:
                line, rest = state["buffer"].split(b"\n", 1)
                parts = line.decode().strip().split()
                if len(parts) == 2:
                    state["cmd"] = parts[0]
                    state["size"] = int(parts[1])
                    state["start_time"] = time.perf_counter()

                    if state["cmd"] == "DOWNLOAD":
                        # Send data to client
                        self._send_download_data(event.stream_id, state["size"])
                    else:
                        # UPLOAD: count any remaining buffered data
                        state["bytes_transferred"] = len(rest)
                        if event.end_stream:
                            self._finish_upload(event.stream_id, state)
            return

        # UPLOAD mode: count received data
        if state["cmd"] == "UPLOAD":
            state["bytes_transferred"] += len(event.data)
            if event.end_stream:
                self._finish_upload(event.stream_id, state)

        # DOWNLOAD mode: client ACK received
        elif state["cmd"] == "DOWNLOAD" and event.end_stream:
            del self._stream_state[event.stream_id]

    def _send_download_data(self, stream_id: int, size: int):
        """Send requested bytes to client."""
        chunk_size = 64 * 1024
        payload = os.urandom(chunk_size)
        sent = 0
        while sent < size:
            remaining = size - sent
            buf = payload if remaining >= chunk_size else payload[:remaining]
            end = (sent + len(buf) >= size)
            self._quic.send_stream_data(stream_id, buf, end_stream=end)
            sent += len(buf)
        self.transmit()
        elapsed = time.perf_counter() - self._stream_state[stream_id]["start_time"]
        mbps = sent * 8 / max(elapsed, 1e-9) / 1e6
        print(f"[QUIC throughput] sent {sent} bytes in {elapsed:.3f}s ({mbps:.2f} Mbit/s)",
              flush=True)

    def _finish_upload(self, stream_id: int, state: dict):
        """Finish upload: log stats and send ACK."""
        elapsed = time.perf_counter() - state["start_time"]
        mbps = state["bytes_transferred"] * 8 / max(elapsed, 1e-9) / 1e6
        print(f"[QUIC throughput] received {state['bytes_transferred']} bytes "
              f"in {elapsed:.3f}s ({mbps:.2f} Mbit/s)", flush=True)
        self._quic.send_stream_data(stream_id, b"OK", end_stream=True)
        self.transmit()
        del self._stream_state[stream_id]


async def run_quic_server(host: str,
                          port: int,
                          mode: str,
                          cert: str,
                          key: str):
    configuration = QuicConfiguration(
        is_client=False,
        alpn_protocols=["bench"],
        congestion_control_algorithm=QUIC_CC_ALGORITHM,
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
    num_bytes: int,
    direction: str = "upload",
    chunk_size: int = 64 * 1024,
) -> Optional[ThroughputResult]:
    try:
        reader, writer = await asyncio.open_connection(host, port)
    except OSError as e:
        print(f"  Stream {stream_id}: connection failed: {e}")
        return None

    # Send control line
    cmd = "UPLOAD" if direction == "upload" else "DOWNLOAD"
    writer.write(f"{cmd} {num_bytes}\n".encode())
    await writer.drain()

    if direction == "upload":
        # Send data to server
        payload = os.urandom(chunk_size)
        sent = 0
        start = time.perf_counter()
        while sent < num_bytes:
            remaining = num_bytes - sent
            buf = payload if remaining >= chunk_size else payload[:remaining]
            writer.write(buf)
            await writer.drain()
            sent += len(buf)
        end = time.perf_counter()
        transferred = sent
    else:
        # Receive data from server
        received = 0
        start = time.perf_counter()
        while received < num_bytes:
            data = await reader.read(chunk_size)
            if not data:
                break
            received += len(data)
        end = time.perf_counter()
        transferred = received

    writer.close()
    await writer.wait_closed()

    duration = max(end - start, 1e-9)
    return ThroughputResult(stream_id=stream_id,
                            bytes_sent=transferred,
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

class QuicThroughputClientProtocol(QuicConnectionProtocol):
    """QUIC client protocol for bidirectional throughput testing."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._stream_done: dict[int, asyncio.Event] = {}
        self._stream_bytes: dict[int, int] = {}  # bytes received for download

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            sid = event.stream_id
            # Track bytes received (for download)
            if sid in self._stream_bytes:
                self._stream_bytes[sid] += len(event.data)
            # Signal completion when stream ends
            if event.end_stream and sid in self._stream_done:
                self._stream_done[sid].set()

    async def send_throughput_data(self, num_bytes: int,
                                   chunk_size: int = 64 * 1024) -> int:
        """Upload: send data and wait for server ACK. Returns bytes sent."""
        quic = self._quic
        sid = quic.get_next_available_stream_id(is_unidirectional=False)
        self._stream_done[sid] = asyncio.Event()

        # Send control line
        quic.send_stream_data(sid, f"UPLOAD {num_bytes}\n".encode(), end_stream=False)
        self.transmit()

        # Send data
        payload = os.urandom(chunk_size)
        sent = 0
        while sent < num_bytes:
            remaining = num_bytes - sent
            buf = payload if remaining >= chunk_size else payload[:remaining]
            quic.send_stream_data(sid, buf, end_stream=False)
            sent += len(buf)
            self.transmit()

        # Signal end of stream
        quic.send_stream_data(sid, b"", end_stream=True)
        self.transmit()

        # Wait for server ACK
        try:
            await asyncio.wait_for(self._stream_done[sid].wait(), timeout=60.0)
        except asyncio.TimeoutError:
            print(f"  Warning: timeout waiting for server ACK on stream {sid}")

        del self._stream_done[sid]
        return sent

    async def receive_throughput_data(self, num_bytes: int) -> int:
        """Download: request data from server. Returns bytes received."""
        quic = self._quic
        sid = quic.get_next_available_stream_id(is_unidirectional=False)
        self._stream_done[sid] = asyncio.Event()
        self._stream_bytes[sid] = 0

        # Send control line requesting download
        quic.send_stream_data(sid, f"DOWNLOAD {num_bytes}\n".encode(), end_stream=False)
        self.transmit()

        # Wait for server to send all data (ends stream when done)
        try:
            await asyncio.wait_for(self._stream_done[sid].wait(), timeout=60.0)
        except asyncio.TimeoutError:
            print(f"  Warning: timeout waiting for download on stream {sid}")

        received = self._stream_bytes[sid]

        # Send ACK to server
        quic.send_stream_data(sid, b"", end_stream=True)
        self.transmit()

        del self._stream_done[sid]
        del self._stream_bytes[sid]
        return received


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
    direction: str = "upload",
    alpn: str = "bench",
    insecure: bool = True,
) -> List[ThroughputResult]:
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=[alpn],
        server_name=host,
        congestion_control_algorithm=QUIC_CC_ALGORITHM,
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
            create_protocol=QuicThroughputClientProtocol,
        ) as client:
            client: QuicThroughputClientProtocol

            # Build list of bytes per stream
            bytes_per_stream_list = []
            for i in range(streams):
                extra = 1 if i < remainder else 0
                bs = bytes_per_stream + extra
                if bs > 0:
                    bytes_per_stream_list.append((i, bs))

            # Transfer data on all streams concurrently
            start = time.perf_counter()
            if direction == "upload":
                tasks = [client.send_throughput_data(bs)
                         for _, bs in bytes_per_stream_list]
            else:
                tasks = [client.receive_throughput_data(bs)
                         for _, bs in bytes_per_stream_list]
            bytes_list = await asyncio.gather(*tasks)
            end = time.perf_counter()

        duration = max(end - start, 1e-9)

        # Build results
        results = []
        for (stream_id, _), transferred in zip(bytes_per_stream_list, bytes_list):
            results.append(ThroughputResult(
                stream_id=stream_id,
                bytes_sent=transferred,
                duration=duration,
            ))
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
        congestion_control_algorithm=QUIC_CC_ALGORITHM,
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
    direction: str = "upload",
):
    direction_label = "upload" if direction == "upload" else "download"
    for run in range(1, runs + 1):
        print(f"\n=== Throughput {direction_label} run {run}/{runs} ({protocol.upper()}) ===")

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
                        num_bytes=bs,
                        direction=direction,
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
                direction=direction,
            )
            end = time.perf_counter()

        # Filter out failed connections
        results = [r for r in results if r is not None]
        if not results:
            print("  All connections failed!")
            continue

        elapsed = max(end - start, 1e-9)
        total_transferred = sum(r.bytes_sent for r in results)
        total_mbps = total_transferred * 8 / elapsed / 1e6

        for r in results:
            mbps = r.bytes_sent * 8 / r.duration / 1e6
            print(f"  Stream {r.stream_id}: {r.bytes_sent} bytes "
                  f"in {r.duration:.3f}s ({mbps:.2f} Mbit/s)")

        print(f"  TOTAL: {total_transferred} bytes in {elapsed:.3f}s "
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
    sp_client.add_argument("--bytes", type=str, default="100MB",
                           help="Total bytes per run, e.g. 100MB, 1G (throughput mode)")
    sp_client.add_argument("--direction", choices=["upload", "download", "both"],
                           default="upload", help="Data direction (throughput mode)")
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
            total_bytes = parse_size(args.bytes)
            if total_bytes < args.streams:
                print(f"Error: --bytes ({total_bytes}) must be >= --streams ({args.streams})")
                return

            # Determine which directions to test
            if args.direction == "both":
                directions = ["upload", "download"]
            else:
                directions = [args.direction]

            for protocol in protocols:
                for direction in directions:
                    await run_client_throughput(
                        protocol=protocol,
                        host=args.server_host,
                        tcp_port=args.tcp_port,
                        quic_port=args.quic_port,
                        total_bytes=total_bytes,
                        streams=args.streams,
                        runs=args.runs,
                        direction=direction,
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
