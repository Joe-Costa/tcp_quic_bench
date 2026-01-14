# **Explanation of the TCP vs QUIC Benchmark Tool (for another LLM)**

This section explains the design, flow, and division of responsibilities
in the Python benchmark tool. The explanation assumes the reader
(another LLM) understands asyncio, sockets, QUIC (via aioquic), and
benchmark design patterns.

------------------------------------------------------------------------

# **1. Purpose of the Tool**

The tool benchmarks two transport protocols --- **TCP** and **QUIC** ---
under identical test conditions. It measures two fundamental metrics:

1.  **Throughput** (client → server transfer speed)
2.  **RTT latency** (round-trip echo time)

The comparison is done between:

-   TCP (stream-oriented, kernel-managed)
-   QUIC (user-space protocol over UDP with TLS 1.3)

Because QUIC supports parallel *streams* inside a single connection,
while TCP uses separate connections, the benchmark normalizes "streams"
in both protocols so that:

-   **TCP parallel streams = multiple TCP connections**
-   **QUIC parallel streams = multiple QUIC bidirectional streams in one
    QUIC connection**

Packet loss and latency are NOT simulated in code. They are induced
externally using **tc netem** on the Linux server NIC.

------------------------------------------------------------------------

# **2. Tool Architecture**

The script functions in two roles:

    tcp_quic_bench.py server
    tcp_quic_bench.py client

Each role supports **TCP** and/or **QUIC**, and either **throughput** or
**RTT** mode.

------------------------------------------------------------------------

# **3. Server Architecture**

## **3.1 TCP Server**

The TCP server uses `asyncio.start_server` and provides two handlers:

### Throughput Mode:

-   Reads data until client closes the connection.
-   Measures server-side throughput (optional but logged).
-   Discards the payload.

### RTT Mode:

-   Echoes back whatever the client sends.
-   Client timestamps RTT measurements.

------------------------------------------------------------------------

## **3.2 QUIC Server**

The QUIC server uses `aioquic.asyncio.serve`.

It instantiates a custom QUIC protocol:

### `BenchmarkQuicServerProtocol`

Handles two behaviors:

### Throughput Mode:

-   For every `StreamDataReceived`, it discards the payload (similar to
    TCP throughput mode).

### RTT Mode:

-   Immediately echoes back any received data on the same QUIC stream.

This matches the TCP server behavior, but using QUIC's ordered BIDIR
streams.

QUIC requires TLS cert + key (self-signed acceptable for benchmarking).

------------------------------------------------------------------------

# **4. Client Architecture**

The client connects to the server using either:

-   `asyncio.open_connection()` for TCP
-   `aioquic.asyncio.connect()` for QUIC

Depending on the mode it selects one of two test types:

------------------------------------------------------------------------

## **4.1 Throughput Test (TCP or QUIC)**

The test sends a configured number of bytes (`--bytes`) divided evenly
across parallel streams (`--streams`).

### TCP Throughput:

-   For each stream, create a new TCP connection.
-   Write bytes in a loop until the per-stream budget is exhausted.
-   Time the send duration.
-   Close the connection.

### QUIC Throughput:

-   Open one QUIC connection total.
-   For each stream:
    -   Acquire a fresh QUIC bidirectional stream ID.
    -   Write chunks until the per-stream budget is exhausted.
    -   End stream.
-   QUIC runs all streams over one encrypted UDP 4-tuple.

The client aggregates per-stream throughput and computes total
throughput.

------------------------------------------------------------------------

## **4.2 RTT Test (TCP or QUIC)**

### TCP RTT:

-   For each stream:
    -   Open a TCP connection.
    -   Repeatedly: send `message_size` bytes → wait for exact echo →
        measure RTT.

### QUIC RTT:

-   The client uses `QuicRTTClientProtocol`.
-   For each stream:
    -   Allocate a QUIC stream ID.
    -   Send echo payload.
    -   Wait for response via an `asyncio.Queue` assigned to that QUIC
        stream.
    -   Measure time delta.

The client prints: - per-stream avg/min/max/p95 RTT - global aggregated
RTT stats

------------------------------------------------------------------------

# **5. Parallel Streams**

Parallelism is handled by:

-   **TCP:** multiple independent asyncio tasks, each with its own TCP
    connection.
-   **QUIC:** multiple QUIC streams multiplexed inside one connection.

This tests: - QUIC's native multiplexing - TCP's behavior under multiple
parallel connections - Effects of packet loss & latency (via `tc`) on
stream scheduling

------------------------------------------------------------------------

# **6. External Network Impairments**

Packet loss and latency are NOT simulated inside Python.

Instead, the user applies them with:

    tc qdisc add dev <iface> root netem delay 50ms loss 1%
    tc qdisc change ...
    tc qdisc del ...

Because `tc` is kernel-level, both TCP and QUIC experience the same
impairments, making comparison fair.

------------------------------------------------------------------------

# **7. Run Flow Summary**

## Server-side:

1.  Start TCP and QUIC servers
2.  In throughput mode:
    -   Discard incoming data
3.  In RTT mode:
    -   Echo incoming data

## Client-side:

Depends on mode and protocol.

### Throughput:

    for run in R runs:
        split total bytes across N streams
        start tasks
        send bytes
        measure per-stream and total throughput

### RTT:

    for run in R runs:
        start N stream tasks
        each performs M pings
        collect rtts[]
        compute statistical summaries

------------------------------------------------------------------------

# **8. Key Design Decisions**

-   **aioquic** is used for QUIC because Python has no builtin QUIC
    library.
-   QUIC requires TLS 1.3, so server certificates are mandatory.
-   QUIC RTT uses queues keyed to stream IDs to decouple read flow.
-   Realtime QUIC `connection.transmit()` calls ensure outgoing packets
    flush promptly.
-   TCP uses `reader.readexactly()` for echo RTT correctness.
-   All structuring is asyncio-based to maximize parallelism and avoid
    threads.
-   Throughput uses random payload (`os.urandom`) to avoid potential
    compression by network devices.

------------------------------------------------------------------------

# **9. Intended Use Case**

On **server (Linux)**: - Start TCP and QUIC servers - Apply various
`tc netem` conditions

On **client (Mac)**: - Run benchmark commands e.g.:

    python3 tcp_quic_bench.py client --protocol quic --mode throughput --streams 8 --bytes 1073741824

Then repeat under different network impairment conditions.

------------------------------------------------------------------------

# **10. Summary**

This tool provides a consistent framework for side-by-side comparisons
of TCP vs QUIC behaviors under:

-   baseline network
-   packet loss
-   induced latency
-   jitter (if the user adds it via tc)
-   multiple parallel streams
-   high throughput loads

It isolates **transport protocol behavior** by: - keeping payloads,
stream count, modes, and logic identical - using `tc` to apply
impairments fairly to both protocols - keeping server operations
symmetrical (discard or echo) - using asyncio to ensure concurrency is
identical for TCP and QUIC scenarios
