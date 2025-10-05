# Velocity HTTPS Integration Roadmap

## Context

Velocity today terminates only the post-quantum UDP transport. Legacy HTTPS fallback is delegated to a separate HTTP server (Nginx, Caddy, etc.), which complicates deployment for operators who want a single binary that mirrors Caddy's multi-domain ergonomics, automatic TLS, and host-based routing. This roadmap captures the staged plan to add first-class HTTPS/TLS support, multi-tenant routing, and ACME automation directly inside Velocity.

## Goals

1. **Single-process transport surface**: One Velocity process binds UDP 443 (Velocity QUIC) and TCP 80/443 (HTTP/1.1, HTTP/2, HTTP/3) while sharing certificates and routing logic.
2. **Multi-domain routing**: Declarative configuration that maps hostnames (and optional path globs) to static assets, upstream services, or edge middleware, with hot reload support.
3. **Automatic certificates**: Built-in Let's Encrypt/ACME client offering HTTP-01 and TLS-ALPN-01 challenges, automated renewal, and OCSP stapling.
4. **Operational parity with Caddy**: Simple CLI experience (`velocity serve`), automatic HTTP→HTTPS redirect, structured logging, metrics, safe defaults, and zero-downtime reloads.

## Stage 1 — HTTPS foundation

### Deliverables
- TCP listener integrated into the Velocity runtime with graceful shutdown hooks.
- TLS acceptor powered by `pqq-tls::ServerHandshake`, exposing a `hyper`-based HTTP server for an MVP "Hello" response.
- Shared certificate load path reused by both UDP and TCP stacks.
- Integration test proving a single binary can answer Velocity requests (UDP) and HTTPS requests (TCP) simultaneously.

### Tasks
- [x] Extend `velocity-core` to spawn a TCP accept loop under an async task supervisor.
- [x] Wrap `pqq-tls` primitives into a `TlsAcceptor` abstraction usable by both Velocity streams and hyper.
- [x] Add a feature flag (e.g., `--serve-https`) to the CLI to gate the new listener while the feature stabilizes.
- [x] Author integration test (`tests/https_basic.rs`) verifying mutual operation.

## Stage 2 — Unified routing & config

### Deliverables
- Host-aware router shared between Velocity and HTTPS paths.
- Config schema (YAML/TOML/JSON) supporting host → target mapping (static dir, reverse proxy, custom middleware chain).
- Hot reload and validation pipeline.

### Tasks
- [ ] Define `config/serve-schema.json` and serde models in `velocity-edge`.
- [ ] Implement router that matches on hostname + optional path prefix.
- [ ] Integrate router with Velocity QUIC session handler and HTTPS handler.
- [ ] Add CLI flag `--config` pointing to the new schema, with watcher-backed reload.

## Stage 3 — Automatic certificates

### Deliverables
- ACME client supporting HTTP-01 and TLS-ALPN-01 challenges.
- Secure certificate storage with locking and renewal scheduling.
- OCSP stapling and optional on-disk cache.

### Tasks
- [ ] Evaluate `rustls-acme` or implement custom ACME client over `reqwest`.
- [ ] Implement challenge responder hooks in both HTTP and TLS stacks.
- [ ] Schedule renewals (cron-like async task) with jitter and error backoff.
- [ ] Expose certificate status via CLI and metrics.

## Stage 4 — Polish & observability

### Deliverables
- Structured logging, metrics (Prometheus endpoint), tracing spans across transports.
- CLI UX parity with Caddy (auto redirects, `--email` / `--accept-tos`, `--domain` flags).
- Comprehensive documentation (README updates, quickstart guide, migration doc).
- Benchmark updates comparing Velocity-only vs Velocity+HTTPS throughput.

### Tasks
- [x] Extend `velocity-cli` documentation and examples.
- [x] Update integration tests and CI matrix.
- [x] Publish migration guide in `docs/https-migration.md`.

## Open Questions
- How to securely store ACME account keys and certificates in multi-tenant environments?
- Should we support dynamic configuration via REST/gRPC (like Caddy's API) in addition to static files?
- What is the default behavior when cert issuance fails (retry window, fallback to self-signed, shutdown)?
- Do we expose HTTP/3 on the TCP stack as well, or rely on Velocity QUIC only?

## Next Actions
- Align on this staged plan with maintainers.
- Begin Stage 1 implementation in a feature branch (`feature/https-foundation`).
- Track progress via GitHub issues referencing each stage and task.
