# Velocity Handshake Fast-Path Benchmark Plan

This document describes how we will measure and regress the Velocity handshake fast-path in local and lab environments. The initial focus is on the parser and UDP receive loop provided by `velocity-core`, with hooks for expanding into full client/server round-trips as the cryptographic stack matures.

## Target metrics

1. **Parser latency (ns/packet)**: time to parse a synthetic `Initial` datagram into a `VelocityPacket`.
2. **UDP loop throughput (packets/s)**: sustained rate at which `run_udp_loop` can ingest and dispatch well-formed packets without drops.
3. **End-to-end handshake CPU time (µs)**: measured once the cryptographic handshake driver is available; target ≤80 µs on resumed paths, ≤300 µs cold on edge-class servers.
4. **Tail latency under loss**: p95 / p99 handshake completion latency with 1% packet loss simulated via `netem`.

## Hardware & OS profiles

| Profile | Hardware | OS | Notes |
|---------|----------|----|-------|
| Dev Laptop | Intel i7-12700H, 32 GB RAM | Windows 11 + WSL2 Ubuntu 24.04 | Development baseline; use `wsl.exe` for Linux measurements. |
| Edge Server | AMD EPYC 7543P, 128 GB RAM | Ubuntu Server 24.04 (5.15 kernel) | Target deployment class for microbenchmarks. |
| ARM Edge | AWS Graviton3 (c7g.4xlarge) | Amazon Linux 2023 | Validates NEON-optimised builds. |

All benchmarks run with CPU frequency scaling locked (`cpupower frequency-set --governor performance`) and turbo disabled when comparing between runs.

## Tooling

- [`criterion`](https://crates.io/crates/criterion) for statistically robust microbenchmarks.
- `perf stat` / `perf record` on Linux, or `vtune` for Windows-specific analysis if required.
- `tc qdisc` + `netem` to inject latency and loss.
- `cargo flamegraph` (via `inferno`) for hotspot inspection.
- Wireshark + `tshark` for capture verification.

## Repository layout

```
benchmarks/
  handshake-bench/         # existing criterion harness (to be extended)
  fast-path-plan.md        # this document
  scripts/
    replay-gen.rs          # (planned) generates synthetic packet traces
    run-fastpath.ps1       # Windows helper
    run-fastpath.sh        # Linux helper
```

## Benchmark commands

### 1. Parser microbench (criterion)

```pwsh
# From the repository root (PowerShell)
cargo bench -p handshake-bench parse_initial
```

```bash
# Linux/WSL variant
cargo bench -p handshake-bench parse_initial
```

The harness will be updated to import `velocity-core::parse_packet` and feed recorded datagrams. Criterion exports mean/median and confidence intervals.

### 2. UDP loop throughput

```bash
# Linux (requires sudo for raw sockets)
sudo ./benchmarks/scripts/run-fastpath.sh --mode udp-loop --duration 30 --bind 0.0.0.0:4443
```

The script pins the benchmark process to a single core (`taskset -c 2`) and uses a companion traffic generator to replay captured datagrams at configurable rates. Packet drops are counted via `/proc/net/snmp`.

A Windows PowerShell equivalent (`run-fastpath.ps1`) will leverage `pktmon` for packet counters and reschedule threads via `Start-Process -ProcessorAffinity`.

### 3. End-to-end handshake latency

Once the Velocity handshake driver is available:

```bash
cargo run -p velocity-server -- --cert certs/hybrid.pem --key certs/hybrid.key --bench-mode
```

```bash
cargo run -p velocity-client -- --target 127.0.0.1:443 --requests 1000 --profile balanced --bench
```

Each client run prints CSV lines: `timestamp_us,phase,cpu_cycles,rtt_us`. Collect them with:

```bash
cargo run -p velocity-client -- --target 127.0.0.1:443 --requests 1000 --profile balanced --bench \
  | tee benchmarks/results/handshake_balanced_local.csv
```

### 4. Loss injection

```bash
sudo tc qdisc add dev lo root netem delay 1ms 0.1ms loss 1%
```

After running the client/server pair, remove the qdisc:

```bash
sudo tc qdisc del dev lo root
```

## Data management

- Raw criterion outputs live under `target/criterion` (ignored by git).
- Summaries and plotted charts are stored in `benchmarks/results/*.csv` and `*.png` with metadata describing git commit hash, compiler version, and hardware profile.
- A `benchmarks/results/README.md` index will track the latest baseline numbers for each profile.

## Validation checklist

1. Verify the packet generator produces frames accepted by `parse_packet` and rejected when lengths are mutated.
2. Confirm CPU pinning is effective via `taskset --cpu-list` (Linux) or `Get-Process -Id $PID | Select-Object ProcessorAffinity` (Windows).
3. Ensure `perf stat` reports consistent cycle counts between runs (<3% variance) before accepting regressions.
4. Capture at least one Wireshark trace per release candidate to confirm on-wire layout matches the spec.
5. Document benchmark environment details (kernel, glibc, rustc version) in `benchmarks/results/metadata.json` for reproducibility.

## Next steps

- Extend `handshake-bench` to import `velocity-core` and expose CLI arguments for packet size sweeps.
- Automate benchmark execution in CI nightly jobs with machine reservations (GitHub Actions self-hosted runners or AWS bare metal).
- Cross-check microbench results with end-to-end measurements once `velocity-crypto` lands to establish correlations between parser cost and handshake latency.
