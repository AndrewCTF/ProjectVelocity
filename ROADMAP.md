# VELO Roadmap

This roadmap tracks the march toward a production-ready PQ-QUIC reference implementation. Milestones sync with the system prompt and inform quarterly planning.

## 2025 Q4 – Prototype (v0.1)

- ✅ UDP transport skeleton with ALPN negotiation and fallback metadata.
- ✅ Bench harness covering in-memory and UDP handshakes.
- ✅ Initial spec restructure (protocol overview, handshake details, fallback semantics).
- ✅ Wire the Kyber KEM into network handshake paths and surface transcripts in the spec.
- ✅ Document deployment recipes (reverse proxies, CDN edge nodes) in `docs/deployment.md`.
- ✅ Publish CI pipeline for formatting, linting, testing, and bench smoke tests.
- Scaffold `velocity-crypto` with handshake phase enums and profile descriptors (light/balanced/secure) feeding future hybrid negotiation logic.

## 2025 Q1 – Feature build-out (v0.5)

- Integrate Kyber-768 and Dilithium3 via optional features with deterministic test fixtures.
- ✅ Implement session tickets + 0-RTT resumption (stateless server mode).
- Add connection migration hooks and flow-control scaffolding.
- Expand examples (browser shim, CLI tooling) and ship static/JSON demos (done in this iteration).
- Run interop tests against QUIC reference stacks in downgrade mode.
- Add Encrypted Client Hello (ECH) negotiation path with server policy controls and test coverage.
- Publish first-cut native bindings (`pqq_init`, `pqq_start_server`, `pqq_request`) for downstream C integrations.

## 2025 Q2 – Hardening (v0.9)

- Complete congestion control strategy (BBRv2 + crypto-aware pacing).
- Add fuzzers for packet parsing, handshake transcripts, and certificate parsing (cargo-fuzz harnesses).
- Deliver full formal model for hybrid handshake (Tamarin + ProVerif cross-check).
- CI: integrate `cargo-audit`, sanitizers, and scheduled fuzzing jobs.
- Documentation: tutorial series, operator guides, integration cookbook.
- Stand up ACME-compatible Velocity CA prototype issuing hybrid certificates (ECDSA + Dilithium).
- Capture downgrade/fallback telemetry and surface policy dashboards for ops teams.

## 2025 Q3 – Release candidate (v1.0)

- Finalise API ergonomics (`Server::serve`, `Client::get`, FFI surfaces) and stabilise semver.
- Add governance artefacts (✅) and security disclosure infrastructure (✅ mailbox & PGP key).
- Benchmark parity vs HTTP/3 on real workloads and publish reports.
- Produce Internet-Draft candidate for IETF submission and gather ecosystem feedback.
- Ship `velocity-ssh-bridge` (vshd daemon + ProxyCommand shim) and document OpenSSH pilot deployments.
- Publish migration runbooks for Nginx, Caddy, and Apache built atop native bindings.

## Stretch goals

- Browser prototype (Chromium network stack shim) demonstrating negotiated PQ-QUIC.
- Go bindings for data-plane integration in existing edge stacks.
- Automatic packet padding heuristics based on traffic patterns.

Progress is tracked in GitHub Projects; issues/PRs are labelled with the milestone above. Contributions aligning with roadmap items are especially welcome.
