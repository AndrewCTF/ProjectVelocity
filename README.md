# Velocity Reference Stack

> **Project Velocity** — A production-quality, open-source reference implementation of a post-quantum resilient QUIC transport published at [projectvelocity.org](https://projectvelocity.org).

## Overview

This repository hosts a hybrid classical + post-quantum secure transport protocol nicknamed **Velocity (ALPN `velocity/1`)**. The project targets compatibility with existing HTTPS deployments while introducing ML-KEM (Kyber) based key exchange, ML-DSA backed authentication, and modern privacy protections such as Encrypted Client Hello.

## Repository layout

- `crates/pqq-core` – Core transport, packet framing, congestion control hooks, ALPN negotiation, handshake state machine stubs.
- `crates/pqq-tls` – Hybrid TLS-like handshake engine with ML-KEM KEM, ML-DSA/Ed25519 hybrid signatures, AEAD abstractions, and ticket logic. Directional AEAD keys (ChaCha20-Poly1305) are derived for every successful handshake via the new `SessionCrypto` helper.
	- `src/handshake.rs` ships with the ML-KEM provider by default and uses a deterministic test-only KEM inside unit tests to keep reproducibility without shipping insecure fallbacks.
- `crates/pqq-server` – High-level async server facade exposing HTTP semantics, enforcing ChaCha20-Poly1305 protection on application datagrams once the hybrid handshake completes.
- `crates/pqq-client` – Client SDK and CLI that can initiate Velocity sessions, negotiate ML-KEM + X25519 key material, and transparently encrypt HTTP-style requests.
- `crates/pqq-easy` – High-level API with automatic ML-KEM key discovery, HTTP(S) fallback, and ergonomic helpers so applications can adopt Velocity with HTTPS-like ergonomics.
- `crates/velocity-edge` – Velocity-aware edge runtime with a FastAPI-inspired router, templating (Tera), response helpers, WAF hooks, sliding-window rate limiting, and config-driven CDN behaviors that plug straight into the CLI via `--edge-config`.
- `native-bindings` – C ABI surface for embedding Velocity into existing C-based stacks.
- `examples/handshake-demo` – Tokio-based binary that drives the Initial packet exchange, serves a plaintext HTTP response over Velocity, and demonstrates graceful fallback.
	- The server publishes explicit downgrade metadata (`fallback.host`, `fallback.port`) via the ALPN response so clients know where to retry over HTTP/3/TLS 1.3.
- `examples/static-file-server` – Serves an embedded HTML asset over Velocity and runs an optional demo client.
- `examples/json-api` – Responds with JSON status payloads, illustrating request inspection and response helpers.
- `examples/browser-gateway` – Launches a Velocity content server plus an HTTP gateway so stock browsers can fetch PQ-protected assets via a local proxy.
- `spec/` – RFC-style draft describing Velocity wire protocol details.
- `spec/formal` – Tamarin model sketches verifying the hybrid handshake at a symbolic level.
- `docs/` – Design, security, deployment, and governance documentation. Start with [`docs/index.md`](docs/index.md), review the new [`docs/https-migration.md`](docs/https-migration.md) cutover guide, and follow [`docs/systemd-service.md`](docs/systemd-service.md) for auto-restart deployments.
- `benchmarks/handshake-bench` – Criterion benchmark suite for the current handshake prototype.
- `.github/` – CI workflows, instruction files, issue templates.

## Quickstart

```pwsh
# Build every crate in the workspace
cargo build --workspace

# Run unit tests
cargo test --workspace
```

> **Note:** PQ libraries (ML-KEM/Kyber and ML-DSA) are provided via Rust crates and/or optimized C bindings. Ensure your toolchain is pinned to nightly or stable ≥1.80 once specified in `rust-toolchain.toml`.

## Hands-on demos

- **Velocity static site CLI:**

	```pwsh
	cargo run -p velocity-cli -- serve --root public
	```

	The CLI (available via the `velocity`, `velo`, `vel`, or `vlo` binaries) serves any directory over the Velocity transport with optional self-signed certificate generation and a one-command deploy helper. Run `velocity --help` for the full command set.

	When you need to front an existing app (Vite, Next.js, API servers), enable reverse-proxy mode with `--proxy https://upstream:3000`. The proxy now enforces connect/response timeouts (10s/30s by default), retries cleanly on keep-alive connections, and turns upstream TLS validation failures into clear 502 responses so you immediately see certificate issues without digging through logs. Tune the behaviors with flags like `--proxy-connect-timeout 5s`, `--proxy-response-timeout 45s`, or `--proxy-idle-timeout 2m`, and pass `--proxy-stream` to stream upstream bodies directly to clients via HTTP/1.1 chunked encoding instead of buffering everything in memory.

	Platform-specific bootstrap steps for Debian/Ubuntu, Fedora, macOS, and Windows live in `docs/deployment.md` alongside a sample `systemd` unit.

- **Observability built-in:**

	```pwsh
	cargo run -p velocity-cli -- serve --root public --metrics-listen 127.0.0.1:9300 --log-format json
	```

	Stage 4 of the HTTPS roadmap ships structured logging and a Prometheus exporter. Scrape `/metrics` to feed Grafana/Prometheus dashboards and follow the `docs/systemd-service.md` guide to keep the exporter running under `systemd` with automatic restarts.

- **Easy client auto-discovery:**

	```pwsh
	cargo run -p velocity-cli -- serve --root public --publish-kem
	```

	With `--publish-kem` enabled, applications using `pqq-easy` or the `velocity-fetch` example will automatically discover the server’s ML-KEM public key during the handshake and cache it locally. This mirrors HTTPS ergonomics—no manual key copy/paste is required for the strongest PQ profile. Toggle `server_key_autodiscover(false)` if your deployment requires explicit key pinning.

- **Edge runtime & API DSL:**

	```pwsh
	cargo run -p velocity-cli -- serve --root public --edge-config edge.yaml
	```

	Add an `edge.yaml` alongside your content root to layer dynamic APIs, templated pages, security middleware, and rate limits on top of the static site without writing new Rust binaries. A minimal example:

	```yaml
	templates_dir: templates
	rate_limit:
	  limit: 120
	  window: 1m
	routes:
	  - path: /api/hello/{name}
	    methods: [GET]
	    kind: json
	    status: 200
	    body:
	      message: "Hello from Velocity Edge"
	  - path: /docs
	    methods: [GET]
	    kind: template
	    name: docs.html
	    context:
	      title: Velocity Edge Runtime
	```

	The runtime automatically applies default security headers, blocks common injection attempts via the built-in WAF, and enforces the configured sliding-window rate limit per client IP. Custom handlers can also be registered programmatically using `velocity_edge::EdgeApp::builder()`.

- **Handshake + HTTP demo:**

	```pwsh
	cargo run -p handshake-demo
	```

	The binary spins up an in-process UDP listener, completes a Velocity handshake, serves a minimal HTTP response over the negotiated channel, and then repeats the sequence with a client that downgrades to `h3`.

	The handshake reply is serialized as compact CBOR to minimize round-trip overhead (roughly 3× smaller than the former JSON framing). For debugging, you can decode the payload with tools like `cbor2json` or `pqq_core::cbor_from_slice`. Configure the advertised endpoint using `HandshakeConfig::with_fallback_endpoint(...)`.

- **Custom link handshake sandbox:**

	The `pqq-core::link` module now exposes an in-memory `memory_link_pair` plus `LinkHandshakeDriver` so you can exercise the negotiation logic without binding UDP sockets—useful for browser transport experiments.

	```rust
	use pqq_core::{
	    build_initial_packet,
	    cbor_from_slice,
	    link::{memory_link_pair, LinkHandshakeDriver},
	    HandshakeConfig,
	};

	# async fn demo() {
	let (server, client) = memory_link_pair(4);
	let driver = LinkHandshakeDriver::new(HandshakeConfig::default());
	let driver_ref = &driver;

	let server_task = {
	    let server = server.clone();
	    async move { driver_ref.run_once(server.as_ref()).await.unwrap() }
	};

	let client_task = {
	    let client = client.clone();
	    async move {
	        let initial = build_initial_packet(["pqq/1", "h3"]);
	        client.send_frame(&initial).await.unwrap();
	        let mut buf = [0u8; 256];
	        let len = client.recv_frame(&mut buf).await.unwrap();
	        from_slice(&buf[..len]).unwrap()
	    }
	};

	let (_server_reply, client_reply) = tokio::join!(server_task, client_task);
	println!("negotiated: {:?}", client_reply.resolution);
	# }
	```

- **Browser gateway (HTTP bridge for real browsers):**

	```pwsh
	cargo run -p browser-gateway
	```

	The binary launches a Velocity content server protected by ML-KEM (Kyber) + ChaCha20-Poly1305 and an HTTP gateway bound to `http://127.0.0.1:8080`. Point any browser at the gateway to fetch the PQ-served landing page; the logs show the negotiated ALPN and fallback advice. Because the gateway reuses the Velocity client internally, every browser request is tunneled over the encrypted transport before being converted back into HTTP/1.1 for display.

- **Integration tests:** The `pqq-core` crate now includes `tests/handshake_fallback.rs`, exercising the fallback path under Tokio.

## Benchmarks

Criterion benchmarks live in `benchmarks/handshake-bench`.

```pwsh
cargo bench -p handshake-bench
```

The suite now records five scenarios:

- `pqq-supported` – Pure in-memory handshake parsing & ALPN selection (no socket I/O), useful for measuring core logic; currently ~0.08µs on a desktop Ryzen 7950X.
- `fallback-h3` – In-memory fallback negotiation producing structured downgrade metadata.
- `pqq-udp-supported` – End-to-end UDP-based handshake over Tokio sockets.
- `fallback-h3-udp` – UDP handshake that triggers a downgrade path.
- `https-tls13` – A baseline TLS 1.3 handshake over TCP (using `tokio-rustls`) for quick comparison (~1.1ms in local tests).

Results land under `target/criterion/`. To rebuild the benchmark binary without running it (useful in CI), run:

```pwsh
cargo bench -p handshake-bench --no-run
```

## Formal analysis

High-level Tamarin models for the hybrid key schedule sit in `spec/formal/pq_quic_handshake.spthy`. They serve as scaffolding for proving mutual authentication and forward secrecy once the cryptographic transcript is finalized.

## Status

- [x] Workspace scaffolding
- [x] Minimal HTTP-over-PQ demo *(handshake + plaintext request/response round-trip)*
- [x] Hybrid handshake implementation *(handshake state machine landed; ML-KEM provider enabled by default, ML-DSA wiring pending)*
- [x] ChaCha20-Poly1305 application protection derived from hybrid key schedule
- [x] HTTP/3 fallback integration *(fallback signaling exercised; transport reroute to be built)*
- [x] Benchmarks & formal models *(Criterion harness & Tamarin skeleton committed)*
- [x] Browser gateway demo bridging Velocity to standard HTTP clients

Contributions are welcome! See `CONTRIBUTING.md` for coding standards and review expectations.
