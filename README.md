# tcp_quic_bench

A benchmarking tool for comparing TCP and QUIC protocol performance under various network conditions.

This thing doesn't quite work right now, so...

## Features

- Measure throughput (data transfer speed) and RTT latency (round-trip time)
- Compare TCP connections vs QUIC streams side-by-side
- Apply network impairments (delay, jitter, packet loss) directly from the server
- Support for parallel streams/connections

## Requirements

- Python 3.10+
- aioquic (`pip install aioquic`)
- For QUIC: TLS certificate and key files
- For network impairment: Linux server with root access

## Quick Start

### Generate TLS Certificates (for QUIC)

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=benchmark'
```

### Start the Server

```bash
# Basic server (TCP + QUIC, throughput mode)
python tcp_quic_bench.py server

# RTT mode
python tcp_quic_bench.py server --mode rtt

# With network impairment (Linux root only)
sudo python tcp_quic_bench.py server --netem-delay 50 --netem-loss 1
```

### Run Benchmarks from Client

```bash
# TCP throughput test
python tcp_quic_bench.py client --server-host 192.168.1.100 --protocol tcp --mode throughput

# QUIC RTT test with 4 parallel streams
python tcp_quic_bench.py client --server-host 192.168.1.100 --protocol quic --mode rtt --streams 4

# Large transfer with multiple runs
python tcp_quic_bench.py client --server-host 192.168.1.100 --protocol tcp --mode throughput \
  --bytes 1073741824 --streams 8 --runs 3
```

## Server Options

| Option | Default | Description |
|--------|---------|-------------|
| `--host` | 0.0.0.0 | Bind address |
| `--tcp-port` | 5000 | TCP server port |
| `--quic-port` | 5001 | QUIC server port (UDP) |
| `--protocol` | both | Which servers to run: tcp, quic, or both |
| `--mode` | throughput | Server mode: throughput or rtt |
| `--quic-cert` | cert.pem | TLS certificate file |
| `--quic-key` | key.pem | TLS private key file |

### Network Impairment Options (Linux root only)

| Option | Description |
|--------|-------------|
| `--netem-iface` | Network interface (auto-detected if not set) |
| `--netem-delay` | Add latency in milliseconds |
| `--netem-jitter` | Add jitter in milliseconds (requires --netem-delay) |
| `--netem-loss` | Add packet loss percentage |

Network impairment only affects traffic on the benchmark ports, not other traffic on the server.

## Client Options

| Option | Default | Description |
|--------|---------|-------------|
| `--server-host` | (required) | Server hostname or IP |
| `--tcp-port` | 5000 | TCP server port |
| `--quic-port` | 5001 | QUIC server port |
| `--protocol` | (required) | Protocol to test: tcp, quic, or both |
| `--mode` | throughput | Benchmark mode: throughput or rtt |
| `--streams` | 1 | Number of parallel streams |
| `--runs` | 1 | Number of test iterations |
| `--bytes` | 100MB | Data size (supports K, KB, M, MB, G, GB, T, TB) |
| `--direction` | upload | Data direction: upload, download, or both |
| `--pings` | 100 | Number of pings per stream (rtt mode) |
| `--message-size` | 64 | Ping message size in bytes (rtt mode) |

## Examples

### Compare TCP vs QUIC under packet loss

Server (Linux):
```bash
sudo python tcp_quic_bench.py server --mode throughput --netem-delay 20 --netem-loss 2
```

Client:
```bash
# Run both protocols back-to-back
python tcp_quic_bench.py client --server-host myserver.local --protocol both \
  --mode throughput --bytes 100MB --streams 4
```

### Bidirectional throughput test

Server:
```bash
python tcp_quic_bench.py server --mode throughput
```

Client:
```bash
# Test upload and download in sequence
python tcp_quic_bench.py client --server-host myserver.local --protocol both \
  --direction both --bytes 1GB --streams 4
```

### Measure latency with jitter

Server:
```bash
sudo python tcp_quic_bench.py server --mode rtt --netem-delay 50 --netem-jitter 10
```

Client:
```bash
python tcp_quic_bench.py client --server-host myserver.local --protocol tcp \
  --mode rtt --pings 100 --streams 2
```

### High-throughput test without impairment

Server:
```bash
python tcp_quic_bench.py server --mode throughput
```

Client:
```bash
python tcp_quic_bench.py client --server-host myserver.local --protocol quic \
  --mode throughput --bytes 10G --streams 16 --runs 5
```

## Output

### Throughput Mode

```
=== Throughput upload run 1/1 (TCP) ===
  Stream 0: 50 MB in 0.892s (448.43 Mbit/s)
  Stream 1: 50 MB in 0.887s (451.07 Mbit/s)
  TOTAL: 100 MB in 0.921s (868.62 Mbit/s)

=== Throughput download run 1/1 (TCP) ===
  Stream 0: 50 MB in 0.845s (473.37 Mbit/s)
  Stream 1: 50 MB in 0.851s (470.03 Mbit/s)
  TOTAL: 100 MB in 0.876s (913.24 Mbit/s)
```

### RTT Mode

```
=== RTT run 1/1 (QUIC) ===
  Stream 0: pings=100, avg=52.341 ms, min=50.112 ms, max=71.203 ms, p95=58.921 ms
  OVERALL: pings=100, avg=52.341 ms, min=50.112 ms, max=71.203 ms, p95=58.921 ms
```

## Notes

- BBR congestion control is used when available (requires aioquic with BBR support; falls back to Reno)
- TCP BBR is set via sysctl when server runs as root on Linux
- TCP parallel streams use separate connections; QUIC uses multiple streams over one connection
- Network impairment uses Linux tc/netem and requires root privileges
- The tool cleans up tc rules automatically on exit (Ctrl+C or normal termination)
- QUIC requires valid TLS certificates (self-signed is fine for benchmarking)
