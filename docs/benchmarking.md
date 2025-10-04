# Benchmarking Guide

VELO tracks handshake performance using the Criterion harness in `benchmarks/handshake-bench`.

## Running locally

```pwsh
# Build benches without execution
cargo bench -p handshake-bench --no-run

# Run with default settings (slower)
cargo bench -p handshake-bench

# Quick smoke (reduced samples)
cargo bench -p handshake-bench -- --sample-size 20 --noplot
```

The suite measures:

- `pqq-supported` – in-memory handshake negotiation (no sockets).
- `fallback-h3` – in-memory downgrade path.
- `pqq-udp-supported` – end-to-end UDP handshake via Tokio sockets.
- `fallback-h3-udp` – UDP downgrade path.
- `https-tls13` – baseline TLS 1.3 handshake over TCP using `tokio-rustls`.

## Recording results

- Benchmark outputs land under `target/criterion/`.
- Copy summaries into `benchmarks/results/*.csv` whenever changes affect performance.
- Document interpretation and hardware specs in this file to keep context.

## Latest snapshot (Intel i7-14700KF, Windows 11, 2025-10-04, Criterion sample-size=20)

| Scenario | Typical (µs) | 95% CI Low (µs) | 95% CI High (µs) | Speedup vs UDP | Speedup vs TLS1.3 |
| -------- | ------------- | --------------- | ---------------- | -------------- | ----------------- |
| pqq-supported | 0.081 | 0.081 | 0.082 | ≈812× | ≈12,100× |
| fallback-h3 | 0.142 | 0.141 | 0.143 | ≈463× | ≈6,860× |
| pqq-udp-supported | 58.420 | 58.109 | 58.781 | 1.0× | ≈15.7× |
| fallback-h3-udp | 60.275 | 59.832 | 60.760 | ≈0.97× | ≈15.2× |
| velocity-turbo | 352.880 | 349.640 | 356.910 | ≈0.17× | ≈2.6× |
| velocity-balanced | 451.210 | 448.970 | 453.910 | ≈0.13× | ≈2.0× |
| velocity-fortress | 602.330 | 598.720 | 606.120 | ≈0.10× | ≈1.5× |
| https-tls13 | 918.930 | 900.420 | 939.770 | ≈0.064× | 1.0× |

The "Typical" column corresponds to Criterion's reported point estimate; the low/high columns capture the 95% confidence interval returned by the harness. Raw results are archived under `benchmarks/results/` for longitudinal analysis. Additional `velocity-*` rows capture the three deployment profiles exposed by `pqq_tls` (turbo/balanced/fortress) to make head-to-head comparisons with TLS during policy tuning.

> The v0.2.0 release restored the expected gap over TLS 1.3 and trimmed ~12% from the UDP handshake path in these measurements. Always validate on dedicated hardware for production-grade baselines.

## Automation

CI (see `.github/workflows/ci.yml`) runs benches in `--no-run` mode to ensure the harness builds. Full runs should be triggered manually or on dedicated performance runners.

## Best practices

- Pin CPU frequency (disable turbo/boost) when comparing runs.
- Close background apps to reduce noise.
- Record compiler version (`rustc --version`) and commit hash in the CSV metadata.
- Update `README.md` when headline metrics change.

Happy benchmarking!
