# Contributing to VELO

Thanks for helping advance the PQ-QUIC reference implementation! This document outlines how to propose changes, the development workflow, and the expectations for code quality and security.

## Code of conduct

We follow the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct). Be respectful, assume good faith, and prioritise constructive collaboration.

## Project structure recap

- Core crates live under `crates/` (`pqq-core`, `pqq-tls`, `pqq-server`, `pqq-client`).
- FFI glue resides in `native-bindings/`.
- Examples showcasing the API are under `examples/`.
- Benchmark harnesses live in `benchmarks/`.
- Specs, formal models, and deep-dive docs sit in `spec/` and `docs/`.

## Development workflow

1. **Fork & branch** – create a feature branch with a descriptive name (`feature/alpn-ext`, `fix/udp-timeout`).
2. **Design first** – for protocol or security-sensitive changes, open a design discussion issue referencing relevant spec sections.
3. **Keep changes scoped** – smaller, reviewable PRs help maintain velocity and auditability.
4. **Testing matrix** – before submitting a PR, run:
   - `cargo fmt --all`
   - `cargo clippy --workspace --all-targets -- -D warnings`
   - `cargo test --workspace`
   - `cargo bench -p handshake-bench -- --noplot --measurement-time 2` (share results when behaviour changes)
5. **Documentation updates** – update the spec (`spec/protocol-draft.md`), developer docs, and changelog entries when modifying wire formats, APIs, or security properties.
6. **Security review** – tag the `#security` label when touching cryptography, handshake flows, key schedule, ticket logic, or FFI boundaries. Include threat analysis notes in the PR description.

## Coding guidelines

- Prefer safe Rust; any `unsafe` must be justified with comments and guarded by tests.
- Follow the existing formatting and naming conventions (Rust edition 2021, snake_case for functions, CamelCase for types).
- Use descriptive error types (`thiserror` derivations) and propagate context with `?`.
- Keep allocations minimal in hot paths; prefer `Bytes`, slices, and stack-allocated buffers.
- Align code comments with the spec, citing section anchors (e.g., `see spec §4.3`).

## Review checklist

Every PR should include:

- [ ] Tests covering the new behaviour (unit, integration, or benchmarks).
- [ ] Updated documentation/spec references.
- [ ] Security impact summary.
- [ ] Benchmark deltas when touching performance-critical code.
- [ ] Entry in `docs/benchmarking.md` if metrics meaningfully shift.

Two maintainer approvals are required for cryptography or transport changes; other changes need at least one maintainer sign-off.

## Issue triage

- `bug` – functional regressions or crashes; prioritise if handshake security is affected.
- `perf` – performance regressions or optimisation opportunities; include metrics.
- `spec` – documentation and protocol draft updates.
- `good first issue` – scoped tasks suitable for new contributors.
- `help wanted` – larger tasks needing assistance (e.g., formal modelling, congestion control).

## Release cadence

- Monthly pre-release tags (`v0.x.0-alpha.N`) with release notes.
- Quarterly minor releases synchronised with roadmap milestones.
- Security fixes may ship out-of-band with coordinated disclosure (see `SECURITY.md`).

## Questions?

Open a discussion in GitHub Discussions under *#architecture* or ping the maintainers via the `@velo-maintainers` team. For sensitive reports, follow the process in `SECURITY.md`.
