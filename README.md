# Velocity Reference Stack
# Velocity — Post-Quantum Web Transport Reference Stack

Velocity is a production-grade, post-quantum successor to TLS 1.3 + QUIC. The stack delivers a UDP-based secure transport with hybrid cryptography (X25519 + Kyber, Dilithium + classical signatures), graceful fallback to HTTP/3, and a batteries-included developer experience. This repository houses the reference implementation, documentation, formal artifacts, and tooling required to evaluate and deploy Velocity/1 (`ALPN velocity/1`).

## What’s inside

| Area | Highlights |
|------|------------|
| `crates/velocity-core` | QUIC-inspired transport core: packet parsing, congestion hooks, stream mux, connection migration. |
| `crates/velocity-crypto` | Hybrid handshake engine, key schedule, certificate validation, ticket issuance, padding policy enforcement. |
| `crates/velocity-server` | HTTP-native server facade with Axum-compatible handlers, static site glue, reverse proxy engine, observability hooks. |
| `crates/velocity-client` | Client SDK & CLI with sync/async APIs, fallback orchestration, cookie/JAR support, 0-RTT guardrails. |
| `crates/velocity-ssh-bridge` | Transport adapter mapping Velocity streams onto SSH semantics (vshd, vsh-proxy, agent forwarding). |
| `native-bindings/` | C ABI exposing `pqq_init`, `pqq_start_server`, `pqq_request` for embedding in Nginx, Apache, and custom stacks. |
| `spec/` | RFC-style Velocity/1 specification + byte-accurate transcript. |
| `docs/` | Operational guides, deployment patterns, security design, benchmarking playbooks, upgrade notes, troubleshooting. |
| `benchmarks/` | Criterion harnesses, page-load simulations, AF_XDP optional fast-path harness. |
| `formal/` | Tamarin/ProVerif models capturing mutual auth, forward secrecy, and downgrade resistance. |

## Upgrade-at-a-glance

* Hybrid certificates with Dilithium + ECDSA ready for production pilots.
* 0-RTT resumption with replay windows and policy-driven early-data gating.
* Encrypted Client Hello (ECH) support out of the box. DNS SVCB helpers documented in [`docs/security-design.md`](docs/security-design.md).
* Telemetry opt-in streams delivering downgrade diagnostics, handshake percentiles, and PQ validation counters.
* CLI-driven config system with simplified YAML (`serve.simple.yaml`) and granular overrides. See [`docs/user-handbook.md`](docs/user-handbook.md).

## Quickstart

	```pwsh
	# 1. Fetch dependencies and compile everything.
	    methods: [GET]

	# 2. Execute the full test suite.
	    kind: json

	# 3. Run style and safety gates (clippy + audit + fmt).
	    status: 200
	cargo clippy --workspace --all-targets
	cargo audit

	# 4. Launch a local Velocity server with the new simplified config.
	    body:
	```

	> **Toolchain:** Velocity targets stable Rust ≥1.81. The repository pins the toolchain via `rust-toolchain.toml`. PQ crates bundle portable Rust implementations and optional AVX2/NEON backend hooks; enable them with `RUSTFLAGS="-C target-cpu=native"` when benchmarking.

## Minimal end-to-end demo

1. Generate a self-signed hybrid certificate for local testing:

   ```pwsh
   cargo run -p velocity-cli -- cert issue --dns localhost --out certs/localhost
   ```

2. Create a simplified config file `serve.simple.yaml`:

   ```yaml
   server:
     listen: "0.0.0.0:4433"
     tls:
       certificate: "certs/localhost/fullchain.pem"
       private_key: "certs/localhost/privkey.pem"
       require_ech: false
     profiles:
       default: balanced
       permit: [light, balanced, secure]
   content:
     sites:
       - hostname: localhost
         root: "./public"
         index: index.html
   telemetry:
     metrics_listen: "127.0.0.1:9300"
     structured_logs: true
   ```

3. Launch the server:

   ```pwsh
   cargo run -p velocity-cli -- serve --config serve.simple.yaml
   ```

4. Issue a request via the client CLI:

   ```pwsh
   cargo run -p velocity-cli -- client get https://localhost/ --alpn velocity/1 --insecure
   ```

5. Validate fallback by offering HTTP/3 only:

   ```pwsh
   cargo run -p velocity-cli -- client get https://localhost/ --alpn h3
   ```

## Beyond the basics

### Deploy to production with Nginx front door

1. Follow the hardened systemd unit in [`docs/systemd-service.md`](docs/systemd-service.md) to manage the Velocity process.
2. Terminate classical TLS with Nginx while proxying UDP/443 to Velocity using QUIC-aware forwarding (see [`docs/deployment.md`](docs/deployment.md)).
3. Configure automatic certificate renewal via Certbot hooks (script snippets provided in [`docs/deployment.md`](docs/deployment.md#certificate-automation)).
4. Enable observability via Prometheus exporter and OpenTelemetry traces as captured in [`docs/operations.md`](docs/integration-guide.md#observability-surface).

### SSH over Velocity

* `vshd` listens for Velocity connections and tunnels them into OpenSSH.
* `vsh-proxy` exposes a `ProxyCommand` trampoline for legacy SSH clients.
* Migration patterns, host key bridging, and audit log integration live in [`docs/velocity-ssh-migration.md`](docs/velocity-ssh-migration.md).

### Performance instrumentation

* Criterion benchmarks: `cargo bench -p velocity-bench` (instructions in [`docs/benchmarking.md`](docs/benchmarking.md)).
* AF_XDP fast-path harness for edge deployments: see [`docs/performance-security-roadmap.md`](docs/performance-security-roadmap.md#fast-path-engineering).
* Page-load comparison scripts under `benchmarks/page-load/` reproduce Velocity vs HTTP/3 metrics with reproducible CSV output.

## Repository tour

```text
├── adoption/                  # Partner enablement kits and pitch decks
├── bench/                     # Raw benchmark result storage (CSV + markdown summaries)
├── benchmarks/                # Harnesses for handshake microbenchmarks, AF_XDP PoC, browser automation
├── crates/
│   ├── velocity-core/        # Packet framing, congestion control, recovery logic
│   ├── velocity-crypto/      # Hybrid handshake, key schedule, AEAD plumbing
│   ├── velocity-server/      # HTTP adapters, static site runtime, reverse proxy
│   ├── velocity-client/      # Client SDK, CLI, cookie jar, ALPN management
│   ├── velocity-ssh-bridge/  # SSH transport adapter (vshd, vsh-proxy)
│   └── ...
├── docs/                     # Expanded documentation set (start with docs/index.md)
├── examples/                 # Static site, JSON API, browser gateway demos
├── native-bindings/          # C ABI glue and headers
├── spec/                     # Protocol draft + byte-level transcripts + formal notes
└── ...
```

## Staying up to date

1. Review [`ROADMAP.md`](ROADMAP.md) for cutover milestones (Prototype → Pilot → GA).
2. Subscribe to the Velocity changelog by watching releases on GitHub.
3. Join the weekly office hours by following the calendar link in [`docs/outreach.md`](docs/user-handbook.md#community-and-support).

## Contributing and support

* Contribution workflow, code-style, and review requirements: [`CONTRIBUTING.md`](CONTRIBUTING.md).
* Governance model, maintainer roles, and release cadence: [`GOVERNANCE.md`](GOVERNANCE.md).
* Disclosure channel and security triage playbook: [`SECURITY.md`](SECURITY.md).
* Velocity CA issuance policies and ACME extensions: [`docs/ca-operations.md`](docs/deployment.md#velocity-ca-operations).

## License

* Code — [MIT](LICENSE)
* Documentation & specifications — [CC-BY-4.0](LICENSE)

## Next steps

Head to [`docs/index.md`](docs/index.md) for a curated documentation map, including production deployment guides, benchmarking blueprints, and troubleshooting matrices. If you are piloting Velocity with partners, the `adoption/` directory includes pitch decks, risk assessments, and integration checklists to streamline reviews.
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
