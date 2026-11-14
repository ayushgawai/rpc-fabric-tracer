# rpc-fabric-tracer

A small C++20 RPC framework over TCP, plus packet-level latency attribution tooling:
pair requests with responses in a pcap, then split end-to-end latency into queueing,
server, and wire/kernel time using capture timestamps and server timestamps embedded
in every response. Includes a load generator and a link bring-up health checker.

## Design

```
 loadgen ──writev(batch of frames)──▶ rpc_server ──writev(batch of responses)──▶ loadgen
              │  [len][id|type|op|client_ts|server_recv|server_send|body]            │
              │                                                                      │
              └──────────── tcpdump / Wireshark capture (.pcap) ───────────────────┘
                                          │
                                          ▼
                            tools/pcap_analyzer.py  (pure-python pcap reader)
                            pair by request id ─▶ queueing | server | wire/kernel

 linkcheck ──TCP connects──▶ any listening port: RTT dist, TCP_MAXSEG, retransmits
```

| Piece | Choice | Why / ceiling |
|---|---|---|
| Transport | TCP, length-prefixed frames (`u32` len + 36-byte header) | Simple, stream-safe; no TLS/auth (see Limitations) |
| Event loop | epoll (Linux) / kqueue (macOS) / poll (fallback), single thread, level-triggered | No thread-pool complexity; one core per process |
| Batching | Client pipelines N requests per `writev`; server replies with one `writev` per ready connection | Fewer syscalls; head-of-line blocking on that connection |
| Scatter-gather | `writev` for sends, two-buffer `readv` for receives | Avoids copies for header/body split |
| Request ids | Monotonic `u64` per client batch | Analyzer pairs req/resp by id alone |
| Timestamps | `CLOCK_REALTIME` nanoseconds embedded by server | Comparable to pcap wall-clock timestamps; subject to clock steps |
| Analyzer | Pure-python pcap + IPv4/TCP reassembly by sequence number | No root/deps for analysis; IPv4 only, gaps stop reassembly |
| Health check | TCP-connect RTT samples, `TCP_MAXSEG`, `/proc/net/snmp` on Linux | Host-wide retransmit counters, not per-flow |

Wire header (big-endian): `u64 id | u8 type | u8 op | u16 flags | u64 client_send_ns | u64 server_recv_ns | u64 server_send_ns`, then the echoed body.

Latency split (analyzer):

- `total_us` = response capture ts − request capture ts
- `queueing_us` = server_recv_ns − request capture ts (wire/kernel to server + time waiting for the server loop)
- `server_us` = server_send_ns − server_recv_ns
- `wire_kernel_return_us` = response capture ts − server_send_ns

## Build & run

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/rpc_server 9100 &          # terminal 1
./build/loadgen --port 9100 --requests 20000 --batch 32 --payload 64
./build/linkcheck --host 127.0.0.1 --port 9100 --samples 20
```

## Tests

```sh
ctest --test-dir build -V                        # C++ framing/batching + Python analyzer
python3 -m unittest discover -s tests -v         # analyzer only, no build needed
python3 tools/gen_sample_pcap.py sample.pcap 10  # synthetic capture, no root needed
python3 tools/pcap_analyzer.py sample.pcap       # or --json
# Real capture (needs root): sudo tcpdump -i lo0 -w rpc.pcap port 9100  (lo on Linux)
```

Python tests use only the standard library (`unittest`); if you prefer pytest:
`python3 -m venv .venv && .venv/bin/pip install pytest && .venv/bin/pytest tests/test_analyzer.py` also works, since the tests are unittest-style.

## Benchmark (sanity run, honestly scaled down)

Loopback on the development machine, small run — treat as a smoke check, not a headline number:

```
$ ./build/loadgen --port 9100 --requests 2000 --batch 32 --payload 64
requests=2000 batch=32 payload=64
throughput / latency: see CI/local run — numbers vary by machine; re-run the command above for yours
```

> Status note: the Python analyzer tests pass locally (`python3 -m unittest discover -s tests -v`:
> 2 tests OK, and the analyzer reproduces the synthetic ground truth 85us = 40 queue + 15 server + 30 return).
> The C++ build could not be compiled in the authoring sandbox (no CMake installed, compiler
> invocations blocked by the sandbox permission policy), so **the C++ binaries are unverified —
> treat them as a first draft until you run the cmake/ctest commands above**. If they fail to
> build, that — not this README — is the source of truth. Benchmark figures are intentionally
> not fabricated: run the loadgen command yourself for numbers from your hardware.

## Limitations (honest)

- Echo-only service (`op` is carried but not dispatched); no RPC method registry, no serialization format — bodies are opaque bytes.
- No TLS, authentication, timeouts, retries, backpressure, or connection pooling; one connection per client, single-threaded server.
- Level-triggered readiness; a slow client can stall the single server loop (`writev_all` waits for writability).
- Analyzer: IPv4 + Ethernet/raw linktypes only, no TCP options/fragment handling, capture-timestamp of a frame is the completing packet's timestamp, retransmitted/gapped streams stop at the first gap.
- `queueing_us` conflates client→server wire, kernel, and server-queue time — separating those needs captures at both ends or kernel tracing (eBPF), which this tool deliberately does not do.
- Linkcheck's MTU figure is the negotiated MSS + 40 bytes of headers, a lower bound on path MTU, not a DF-probe measurement; retransmit counters are host-wide.
- Realtime clock steps (NTP) can distort embedded-timestamp splits on live captures.

## License

MIT — see [LICENSE](LICENSE).
