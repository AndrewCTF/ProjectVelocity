# Velocity Developer Guide

> A comprehensive reference for contributors, reviewers, and maintainers working on the Velocity reference stack. Covers repository structure, toolchain requirements, testing strategy, coding standards, and release workflow.
  * Security review considerations (if any).
8. **Address CI feedback**. GitHub Actions pipeline runs `fmt`, `clippy`, `test`, `audit`, fuzz smoke tests, and doc builds.

## 5. Coding standards

* **Error handling**: Use `thiserror::Error` for crate-specific error enums, return `Result<T, VelocityError>` in libraries, and convert to `anyhow::Result` at CLI boundaries.
* **Logging**: Use the `tracing` crate. Use structured fields (`event`, `connection_id`, `profile`). Avoid string interpolation.
* **Async**: Tokio runtime with cooperative budgeting. Use `select!` macros for cancellation.
* **Memory management**: Favor `Bytes`/`BytesMut` for network buffers. No `unsafe` unless reviewed by maintainers. Document invariants and add tests that stress unsafe paths.
* **Security annotations**: When implementing security-critical logic, cite relevant spec section (e.g., `// Spec §7.3`).

## 6. Testing & validation

### Unit tests

* Live alongside modules (`mod tests`). Keep them deterministic.
* Cover parsing, state transitions, and error handling.

### Integration tests

* `crates/velocity-server/tests/` — handshake success, fallback, session resumption, ALPN negotiation.
* `crates/velocity-client/tests/` — client fallback, cookie jar persistence, 0-RTT gating.
* For new integration scenarios, add `#[tokio::test]` so they run under the multi-threaded runtime.

### Benchmarks

* Criterion harnesses under `benchmarks/` measure handshake latency and throughput. Update baseline CSVs when performance improvements land.
* Document measured numbers in PR descriptions and in [`docs/benchmarking.md`](./benchmarking.md).

### Fuzzing

* Use `cargo fuzz run handshake` for libFuzzer targets.
* Nightly CI runs 30-minute fuzzing smoke tests; extended runs (72 hours) happen before major releases.

### Static analysis

* Run `cargo audit` monthly or when dependencies change.
* Use `cargo deny check bans` to prevent disallowed licenses.

## 7. Documentation expectations

Every change that affects operators or API surface must update documentation. Preferred locations:

* `docs/user-handbook.md` — CLI and configuration behaviour.
* `docs/deployment.md` — infrastructure, service management.
* `spec/protocol-draft.md` — wire-level behaviour, handshake semantics.

Include “Docs updated” bullet in PR summary linking to modified files.

## 8. Release process

1. Tag release candidate (`vx.y.z-rc1`).
2. Run full CI, fuzzing, integration suite.
3. Update changelog (in forthcoming `CHANGELOG.md`).
4. Cut final tag. Generate release notes with upgrade impact summary, security items, benchmarks.
5. Publish signed binaries (see [`SECURITY.md`](../SECURITY.md#release-signatures)).
6. Update documentation pointers (README, docs/index, roadmap).

## 9. Branching & backports

* `main` — bleeding edge.
* `release/vx.y` — maintained for stable releases. Backports require maintainer approval and must include test coverage.
* Hotfix branches follow `hotfix/<issue>` naming and target latest supported release.

## 10. Continuous integration

GitHub Actions workflows located in `.github/workflows/`:

* `build-test.yml` — fmt, clippy, audit, test (Linux + macOS).
* `fuzz.yml` — nightly honggfuzz smoke tests.
* `bench.yml` — optional performance runs on dedicated hardware runners.
* `release.yml` — reproducible builds, signature generation.

## 11. Development utilities

* `justfile` contains shortcuts (e.g., `just setup`, `just lint`, `just docs`).
* `scripts/generate-handshake-transcript.sh` snapshots handshake bytes for spec updates.
* `scripts/update-licenses.sh` refreshes license inventory.

## 12. Style guide highlights

* Follow Rust API Guidelines. Document public functions with `///` comments, include examples where relevant.
* Use `cfg(test)` helpers for shared test utilities.
* Keep modules small; avoid files >500 lines by factoring submodules.
* Keep `use` statements grouped (std, third-party, crate).

## 13. Support

* Ping maintainers in `#velocity-dev` Slack channel (internal) or open GitHub discussion.
* Security-sensitive changes must go through the security working group as per [`SECURITY.md`](../SECURITY.md#coordinated-fixes).

Velocity is a mission-critical transport. Treat every change as infrastructure-impacting: keep tests thorough, documentation precise, and code reviewed by domain experts.

# Developer Guide

This guide documents how to build, test, and extend the VELO PQ-QUIC stack.

## Toolchain prerequisites

- Rust 1.80+ (install via `rustup`; nightly optional for upcoming features).
- `cargo fmt`, `cargo clippy`, and `cargo audit` installed via `rustup component add` / `cargo install`.
- Optional: OpenSSL for TLS baseline benchmarks.

## Workspace layout

```text
crates/
  pqq-core/    # packet parsing, handshake driver, transport helpers
  pqq-tls/     # hybrid key schedule, KEM abstraction, future TLS glue
  pqq-server/  # high-level server facade and request/response helpers
  pqq-client/  # client SDK & CLI building blocks
native-bindings/ # C ABI shim
examples/        # runnable demos (handshake, static site, json api)
benchmarks/      # Criterion harnesses + results
spec/            # protocol draft + formal models
```

## Common commands

```pwsh
# Format and lint
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings

# Run tests
cargo test --workspace

# Benchmarks (CPU intensive)
cargo bench -p handshake-bench -- --noplot
```

## Adding a feature

1. Update or extend the protocol spec (`spec/protocol-draft.md`) with rationale and wire format changes.
2. Modify the relevant crate(s) under `crates/` and add unit tests.
3. Update examples and documentation when public APIs change.
4. Run the quality gates above and attach results to your PR description.
5. If handshake logic changes, update `docs/security-design.md` with new threat mitigations.

## Testing strategy

- **Unit tests**: Live alongside modules (`mod tests`) for packet parsing, handshake negotiation, key schedule.
- **Integration tests**: `crates/pqq-core/tests/` exercises UDP fallback negotiation; add more to cover new flows.
- **Examples**: run `cargo run -p handshake-demo` or the new static/JSON demos for end-to-end sanity checks.
- **Benchmarks**: evaluate handshake latency deltas when touching transport or cryptography.

## Debugging tips

- Enable structured logs with `RUST_LOG=info` when running examples.
- Use `RUST_LOG=pqq_core=trace` to inspect handshake parsing.
- The `memory_link_pair` helper (`pqq-core::link`) allows in-memory testing without sockets.

## Extending cryptography

- KEM providers implement `pqq_tls::KemProvider`; the Kyber-backed `KyberKem` is the production implementation, while unit tests embed a deterministic `TestKem` for reproducible fixtures.
- Add new providers under `pqq-tls/src/handshake.rs` behind cargo features (e.g., `--features kyber`).
- Document new algorithms in `docs/security-design.md` and update the spec (sections 4.x).

## Contributing docs & spec changes

- Specs use Markdown with fenced diagrams; cite sources and include change summaries.
- Docs live under `docs/`; add new guides or RFCs in subdirectories as needed.
- When updating figures or tables, regenerate any diagrams or embeddings to keep the repo deterministic.

For questions, open a discussion tagged `#dev-help` or ping a maintainer listed in `GOVERNANCE.md`.
