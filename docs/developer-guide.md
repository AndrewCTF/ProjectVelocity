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
