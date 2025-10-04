# Velocity User Handbook

> Comprehensive, production-focused documentation for operators, developers, and security teams adopting the Velocity post-quantum transport stack. Use this handbook as the front door to the entire documentation set. It covers installation, upgrades, runtime configuration, CDN/edge features, troubleshooting, and where to get help.

---

## Table of Contents

1. [Audience & Scope](#audience--scope)
2. [Architecture Overview](#architecture-overview)
3. [Prerequisites & Environment Setup](#prerequisites--environment-setup)
    1. [Supported Platforms](#supported-platforms)
    2. [Toolchain Requirements](#toolchain-requirements)
    3. [Networking & Firewall Considerations](#networking--firewall-considerations)
4. [Download & Installation](#download--installation)
    1. [Release Channels](#release-channels)
    2. [Binary Downloads](#binary-downloads)
    3. [Building From Source](#building-from-source)
5. [Quickstart Workflows](#quickstart-workflows)
    1. [Serve Static Content](#serve-static-content)
    2. [Reverse Proxy an Existing App](#reverse-proxy-an-existing-app)
    3. [Enable the Edge Runtime](#enable-the-edge-runtime)
6. [Configuration Deep Dive](#configuration-deep-dive)
    1. [CLI Flags & Environment Variables](#cli-flags--environment-variables)
    2. [Edge Runtime `edge.yaml`](#edge-runtime-edgeyaml)
    3. [Security Profiles & ALPN Fallback](#security-profiles--alpn-fallback)
    4. [Rate Limiting & WAF Rules](#rate-limiting--waf-rules)
    5. [Certificate & Key Management](#certificate--key-management)
7. [Updating & Release Management](#updating--release-management)
    1. [Versioning Policy](#versioning-policy)
    2. [Upgrade Checklist](#upgrade-checklist)
    3. [Automated Rollouts](#automated-rollouts)
8. [Developer APIs & Integrations](#developer-apis--integrations)
    1. [`velocity-edge` Builder DSL](#velocity-edge-builder-dsl)
    2. [Direct Library Usage (`pqq-*` crates)](#direct-library-usage-pqq--crates)
    3. [Embedding via C Bindings](#embedding-via-c-bindings)
    4. [Framework Recipes (Next.js, FastAPI, Actix, etc.)](#framework-recipes-nextjs-fastapi-actix-etc)
9. [Observability & Operations](#observability--operations)
    1. [Logging & Tracing](#logging--tracing)
    2. [Metrics & Dashboards](#metrics--dashboards)
    3. [Health Checks & Synthetic Probes](#health-checks--synthetic-probes)
10. [Security Hardening & Compliance](#security-hardening--compliance)
    1. [Transport Security Controls](#transport-security-controls)
    2. [Edge Runtime Threat Protections](#edge-runtime-threat-protections)
    3. [Compliance Mapping](#compliance-mapping)
11. [Troubleshooting Playbooks](#troubleshooting-playbooks)
    1. [Handshake Failures](#handshake-failures)
    2. [Performance Regressions](#performance-regressions)
    3. [Edge Runtime Issues](#edge-runtime-issues)
    4. [Certificate & TLS Problems](#certificate--tls-problems)
12. [Frequently Asked Questions](#frequently-asked-questions)
13. [Community & Support](#community--support)
14. [Appendix: Reference Tables](#appendix-reference-tables)

---

## Audience & Scope

This handbook targets:

- **Operators & SREs** running Velocity as an edge, CDN, or reverse proxy service.
- **Application developers** who need to embed Velocity transport, build APIs via the `velocity-edge` runtime, or interact with Velocity-enabled clients.
- **Security teams** evaluating the post-quantum handshake, auditing transport protections, or configuring WAF/rate-limiting policies.
- **Enterprise architects** planning migrations from TLS 1.3 to hybrid PQ transport.

If you are looking for low-level protocol specifications or cryptographic rationale, see `spec/protocol-draft.md` and `docs/security-design.md`. For contributor workflow and coding standards, visit `docs/developer-guide.md`.

## Architecture Overview

Velocity is organized as a Cargo workspace containing transport primitives (`pqq-core`, `pqq-tls`), higher-level client/server facades (`pqq-client`, `pqq-server`), and operational tooling (`velocity-cli`, `velocity-edge`). Key concepts:

- **Hybrid Handshake**: Combines X25519 with Kyber KEM plus Dilithium signatures for post-quantum resilience with classical compatibility.
- **ALPN Negotiation**: Uses `velocity/1` by default and downgrades to `h3` when a peer lacks Velocity support, preserving legacy reach.
- **Edge Runtime**: The `velocity-edge` crate provides a FastAPI-style HTTP runtime with built-in security middleware, templating, rate limiting, and WAF hooks.
- **CLI**: `velocity-cli` bundles static file serving, reverse proxy, certificate management, and runtime toggles for the edge engine.

For deeper architectural diagrams, cross-reference `docs/performance-security-roadmap.md` and `docs/velocity-exploit-hardening.md`.

## Prerequisites & Environment Setup

### Supported Platforms

| Platform | Status | Notes |
| --- | --- | --- |
| Linux (Ubuntu 22.04+, Debian 12+, Fedora 39+, Arch) | ✅ Supported | Requires Rust ≥ 1.80, systemd units provided in `docs/systemd/`. |
| macOS 13+ (Intel & Apple Silicon) | ✅ Supported | Uses Homebrew or MacPorts for dependencies; use `codesign` if distributing binaries. |
| Windows 10/11 (x86_64) | ✅ Supported | Requires PowerShell 7+, `winget` or `choco` for dependencies; UDP port 443 must be open. |
| FreeBSD 13+ | ⚠️ Experimental | Works with Rust toolchain; ALPN fallback verified, but no systemd units. |

### Toolchain Requirements

- **Rust**: Install via `rustup` and sync to the version pinned in `rust-toolchain.toml` (if absent, target stable ≥ 1.80).
- **C Toolchain**: Required when enabling optimized Kyber/Dilithium bindings (`clang` or `gcc`).
- **Tokio-compatible runtime**: Provided by the binaries; ensure `ulimit -n` (open files) is ≥ 65535 for production.
- **Optional**: `jq`, `cbor2json` for decoding handshake payloads; `openssl` or `cfssl` for certificate workflows.

### Networking & Firewall Considerations

- **UDP 443** must be open inbound/outbound. Configure DSCP or QoS if edge nodes sit behind load balancers.
- Plan for **dual-stack IPv4/IPv6**. Velocity records both in fallback metadata.
- **MTU**: If operating across tunnels reduce initial datagram size via `--max-datagram-size` (coming soon) or system-level fragmentation settings.

## Download & Installation

### Release Channels

| Channel | Frequency | Stability | Use Case |
| --- | --- | --- | --- |
| `stable` | Monthly | Highest | Production rollouts. |
| `beta` | Bi-weekly | Medium | Staging/UAT; includes upcoming features. |
| `nightly` | Daily | Experimental | Feature testing, not recommended for production. |

### Binary Downloads

1. Visit **https://projectvelocity.org/downloads** (placeholder) for signed tarballs/zip files.
2. Verify signatures using the release signing key published in `docs/security-design.md`.
3. Extract to `/opt/velocity` (Linux) or `C:\Program Files\Velocity` (Windows).
4. Add the `velocity`, `velo`, `vel`, or `vlo` binary to your `$PATH` or create system-level service definitions.

### Building From Source

```pwsh
# Clone repository
git clone https://github.com/project-velocity/velocity.git
cd velocity

# Optional: select toolchain	rustup override set stable

# Build entire workspace
cargo build --release --workspace

# Copy binaries
cp target/release/velocity /usr/local/bin
```

For Windows, use PowerShell:

```pwsh
Set-Location C:\Velocity
cargo build --release --workspace
Copy-Item target\release\velocity.exe C:\bin\velocity.exe
```

## Quickstart Workflows

### Serve Static Content

```pwsh
velocity serve --root public --self-signed --domain localhost
```

- Serves files from `./public` over UDP 4433.
- Generates a self-signed hybrid certificate stored alongside the root.
- Default ALPN list: `velocity/1`; fallback ALPN: `h3`.

### Reverse Proxy an Existing App

```pwsh
velocity serve \
  --proxy https://localhost:3000 \
  --proxy-connect-timeout 5s \
  --proxy-response-timeout 45s \
  --proxy-stream
```

- Proxies HTTP/HTTPS origins using streaming chunked responses.
- Honors `--proxy-preserve-host` to forward the original `Host` header.
- Logs upstream TLS failures with actionable hints.

### Enable the Edge Runtime

```pwsh
velocity serve --root public --edge-config edge.yaml
```

Example `edge.yaml`:

```yaml
templates_dir: templates
rate_limit:
  limit: 120
  window: 1m
waf:
  enabled: true
  rules:
    - "(?i)<script"
routes:
  - path: /api/hello/{name}
    methods: [GET]
    kind: json
    status: 200
    body:
      message: "Hello, {{ name }}"
  - path: /login
    methods: [POST]
    kind: template
    name: login.html
```

## Configuration Deep Dive

### CLI Flags & Environment Variables

| Flag | Description | Env Var | Default |
| --- | --- | --- | --- |
| `--listen` | UDP bind address. | `VELOCITY_LISTEN` | `0.0.0.0:4433` |
| `--alpn` | Supported ALPN list (comma-separated). | `VELOCITY_ALPN` | `velocity/1` |
| `--fallback-alpn` | Advertised fallback protocol. | `VELOCITY_FALLBACK_ALPN` | `h3` |
| `--fallback-host` | Hostname for fallback path. | `VELOCITY_FALLBACK_HOST` | unset |
| `--cert`/`--key` | PEM chain/private key paths. | `VELOCITY_CERT`, `VELOCITY_KEY` | unset |
| `--max-sessions` | Limit concurrent sessions. | `VELOCITY_MAX_SESSIONS` | unlimited |
| `--edge-config` | Path to edge YAML config. | `VELOCITY_EDGE_CONFIG` | unset |
| `--proxy-*` | Upstream tuning knobs. | Various `VELOCITY_PROXY_*` | See CLI help |
| `--publish-kem` | Advertise Kyber key material. | `VELOCITY_PUBLISH_KEM` | disabled |

Feature flags and hidden options live in `velocity --help`.

### Edge Runtime `edge.yaml`

- **`templates_dir`**: Directory relative to `--root` containing Tera templates.
- **`routes`**: Ordered list; first match wins. Supports `json`, `text`, `template`, and `static_file` handlers.
- **`rate_limit`**: Sliding window per client IP via `limit`/`window`.
- **`waf`**: Toggle default rule set and add custom regex patterns.
- **Custom middleware**: Extend by wrapping `velocity_edge::EdgeApp::builder()` in Rust and registering bespoke middleware.

### Security Profiles & ALPN Fallback

- `turbo`: Prioritizes performance; uses Kyber512 + ChaCha20-Poly1305.
- `balanced`: Default blend of security/performance; Kyber768.
- `fortress`: High-security posture; Kyber1024 + Dilithium3.

ALPN negotiation gracefully falls back to `h3`/TLS 1.3 with explicit metadata so clients can retry automatically. Configure fallback endpoints with `--fallback-host`/`--fallback-port` or programmatically via `ServerConfig::with_fallback`.

### Rate Limiting & WAF Rules

- Rate limiter uses an in-memory `DashMap` with `VecDeque` time windows; ensure nodes have consistent time sources (NTP).
- WAF patterns default to blocking common SQLi/XSS expressions. Add application-specific patterns and test with staging traffic.
- Observe matches by enabling `TRACE` logging (`-vvv`) and filtering `velocity::edge`.

### Certificate & Key Management

- Use hybrid certificates containing both classical (ECDSA/Ed25519) and Dilithium signatures.
- Generate via Velocity CA tooling (see `docs/velocity-ssh-migration.md`) or integrate with existing ACME flows.
- Store private keys in hardware security modules or OS-native key stores; specify via `--key`. Rotate regularly and monitor OCSP/CRL status.

## Updating & Release Management

### Versioning Policy

Velocity uses **semantic versioning** (`MAJOR.MINOR.PATCH`). Breaking protocol changes increment `MAJOR`. Security patches bump `PATCH` with release notes in `CHANGELOG.md`.

### Upgrade Checklist

1. Read the release notes and highlight migrations/API changes.
2. Validate in staging: run `cargo test --workspace` and custom integration suites.
3. Export current configuration, particularly `edge.yaml` and systemd units.
4. Roll out using blue/green deployments or canary by region.
5. Monitor handshake success, fallback rates, and latency.

### Automated Rollouts

- Use GitHub Actions or GitLab CI to pull nightly/stable builds.
- Integrate with infrastructure-as-code (Terraform, Ansible) to distribute binaries and configs.
- Implement health checks (see below) before flipping traffic.

## Developer APIs & Integrations

### `velocity-edge` Builder DSL

```rust
let mut app = velocity_edge::EdgeApp::builder();
app.templates_dir("templates")
   .with_rate_limit(100, std::time::Duration::from_secs(60))
   .get("/hello/{name}", |ctx, req| async move {
       let name = req.param("name").unwrap_or("friend");
       let body = serde_json::json!({ "message": format!("Hello, {}!", name) });
       Ok(velocity_edge::EdgeResponse::json(&body)?)
   });
let edge = app.build()?;
```

- Supports programmatic routing, custom middleware, and full response control.
- Wrap the resulting `EdgeApp` with `pqq_server::Server::serve` using the same closure pattern as the CLI.

### Direct Library Usage (`pqq-*` crates)

- `pqq-core`: Packet framing, handshake driver, low-level APIs.
- `pqq-server`: Async server harness with `Request`/`Response` types and streaming support.
- `pqq-client`: API for initiating Velocity sessions, falling back to TLS where necessary.

See `examples/json-api` and `examples/browser-gateway` for reference implementations.

### Embedding via C Bindings

`native-bindings/` exports `pqq_init`, `pqq_start_server`, and `pqq_request` for C/C++ integration. Consult `docs/integration-guide.md` for ABI stability guarantees and header usage.

### Framework Recipes (Next.js, FastAPI, Actix, etc.)

- **Next.js / Vite**: Run your app on `localhost:3000` and place Velocity in front with `--proxy`. Use `--edge-config` for server-side rendering templates or JSON APIs.
- **FastAPI**: Deploy the Python app on `uvicorn`. Use the edge runtime for static assets and let Velocity proxy API routes with streaming JSON responses.
- **Actix/Axum**: Embed `pqq-server` directly or run alongside and proxy. `velocity-edge` can host auxiliary endpoints while your Rust framework handles business logic.

## Observability & Operations

### Logging & Tracing

- Default logging uses `info`. Increase verbosity (`-v`, `-vv`, `-vvv`) to unlock debug/trace logs.
- Integrate with OpenTelemetry by enabling the `tracing-subscriber` exporter (roadmap item) or piping JSON logs into ELK/Splunk.

### Metrics & Dashboards

- Export handshake success rates, fallback counts, RTT distributions from the planned Prometheus endpoint (`/metrics`).
- For now, tail logs and use `jq` to aggregate handshake events.

### Health Checks & Synthetic Probes

- Expose a synthetic route via `edge.yaml` (e.g., `/healthz`) returning cached status.
- Use the `velocity-fetch` example (`cargo run -p pqq-client --example velocity-fetch`) in cron jobs to verify PQ handshake success.

## Security Hardening & Compliance

### Transport Security Controls

- Enforce strict ALPN ordering to prevent downgrade attacks.
- Enable Encrypted Client Hello (ECH) once available; roadmap tracked in `docs/performance-security-roadmap.md`.
- Rotate session tickets frequently and limit 0-RTT to idempotent operations.

### Edge Runtime Threat Protections

- Default security headers: HSTS, CSP, X-Content-Type-Options, X-Frame-Options.
- WAF regex engine blocks common injection patterns; customize for application context.
- Rate limiter prevents credential stuffing and basic DoS.

### Compliance Mapping

- **PCI DSS**: Disable non-idempotent 0-RTT traffic for payment flows.
- **HIPAA/GDPR**: Document data residency; ensure TLS fallback endpoints meet compliance.
- **FedRAMP**: Use FIPS-validated crypto modules; maintain audit logs for handshake metadata.

## Troubleshooting Playbooks

### Handshake Failures

| Symptom | Likely Cause | Resolution |
| --- | --- | --- |
| Client logs `no common ALPN` | Peer lacks Velocity support | Verify `--fallback-alpn` and monitor fallback telemetry. |
| `handshake error: Framing` | Datagram truncated/MTU issue | Reduce payload size, inspect network fragmentation. |
| `hybrid handshake error: ...` | Kyber/Dilithium mismatch | Ensure both sides run compatible profiles; update binaries. |

### Performance Regressions

- Validate CPU usage: ensure PQ cryptography is hardware-accelerated where available.
- Monitor rate limiter hits; adjust thresholds to prevent throttling legitimate traffic.
- Use `benchmarks/handshake-bench` to compare baseline vs current build.

### Edge Runtime Issues

- **Template not rendering**: Ensure `templates_dir` is correct and file syntax passes Tera checks.
- **404 from edge route**: Confirm route pattern (wildcards, `{param}` names) and HTTP method list.
- **WAF false positives**: Relax regex or disable the rule by commenting in `edge.yaml`.

### Certificate & TLS Problems

- `bad certificate` errors: Recheck PEM order; certificate must include full chain.
- Upstream TLS handshake failures (proxy mode): Use `--proxy-preserve-host` or correct SNI.

## Frequently Asked Questions

**Q: Can I run Velocity alongside HTTP/3 on the same port?**  
A: Yes. Velocity listens on UDP 443 and can fall back to HTTP/3 using the same socket, broadcasting fallback metadata to compatible clients.

**Q: How do I disable 0-RTT?**  
A: Set `HandshakeConfig::max_early_data(0)` in code or use upcoming CLI flag `--disable-0rtt` (see roadmap).

**Q: Does Velocity support QUIC connection migration?**  
A: Connection-ID plumbing exists in `pqq-core`; multi-path and migration support is on the roadmap for v0.9 (see `docs/performance-security-roadmap.md`).

**Q: Where can I report security vulnerabilities?**  
A: Follow the disclosure process in `SECURITY.md`, including the PGP key and triage timeline.

## Community & Support

- **GitHub Discussions**: Feature requests, community Q&A.
- **Matrix/Slack (planned)**: Real-time chat with maintainers.
- **Weekly Office Hours**: Scheduled sessions for enterprise adopters; see `docs/governance.md`.
- **Mailing List**: Subscribe for release announcements and security advisories.

## Appendix: Reference Tables

### Default Ports

| Component | Protocol | Port |
| --- | --- | --- |
| Velocity Server | UDP | 443 (production) / 4433 (default dev) |
| Fallback HTTP/3 | UDP | 443 |
| Velocity Browser Gateway Demo | TCP | 8080 |

### Log Targets

| Target | Description |
| --- | --- |
| `velocity::server` | Core handshake, session lifecycle. |
| `velocity::proxy` | Reverse proxy success/error events. |
| `velocity::edge` | Edge runtime routing, middleware outcomes, WAF hits. |
| `velocity::tls` | Certificates, upstream TLS interactions. |

### Useful Commands

```pwsh
# Format and lint
cargo fmt
cargo clippy --workspace -- -D warnings

# Run comprehensive tests
cargo test --workspace

# Benchmark handshake performance
cargo bench -p handshake-bench

# Start edge runtime with verbose logging
velocity serve --edge-config edge.yaml -vvv
```

---

**Next Steps:**
- Deploy Velocity in staging following the instructions in this handbook.
- Explore advanced topics in `docs/deployment.md`, `docs/integration-guide.md`, and `docs/security-design.md`.
- Contribute improvements via pull requests—start with `CONTRIBUTING.md` for review expectations.
