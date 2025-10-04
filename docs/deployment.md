# Deployment Guide

This guide outlines how to run the Velocity reference stack in lab or pilot environments.

## Components

- **Server**: `pqq-server` crate (or example binaries) binding to UDP port 443.
- **Client**: `pqq-client` crate or CLI wrappers.
- **Fallback**: HTTP/3 stack (e.g., `quiche`, `nghttp3`) handling downgrade traffic.
- **Observability**: metrics emitted via tracing subscribers; integrate with Prometheus or OpenTelemetry in later milestones.

For live operator updates visit [projectvelocity.org/deploy](https://projectvelocity.org/deploy).

## Quickstart (lab)

1. Build the workspace:
   ```pwsh
   cargo build --workspace --release
   ```
2. Run the handshake demo:
   ```pwsh
   cargo run -p handshake-demo
   ```
3. Exercise static file server:
   ```pwsh
   cargo run -p static-file-server
   ```
4. Query the JSON API demo:
   ```pwsh
   cargo run -p json-api-demo
   ```

### Remote client fetch (Velocity in place of curl)

To retrieve content from a remote Velocity endpoint, compile the client
examples. When the operator enables `--publish-kem`, the helpers automatically
discover and cache the server's ML-KEM public key during the handshake—no manual
copy/paste required. The `velocity-probe` example confirms handshake support,
and `velocity-fetch` performs an HTTP GET over the Velocity transport. Only
provide explicit key material if you run in a fully pinned environment.

```pwsh
# Inspect the handshake outcome and fallback advice
cargo run -p pqq-client --example velocity-probe -- <host:port>

# Fetch a resource. velocity-fetch auto-probes for the server ML-KEM key when
# the operator embeds it in the handshake payload. Supply --kem-b64/--kem-file
# only if the probe reports that no key was published.
cargo run -p pqq-client --example velocity-fetch -- <host:port> https://example.com/

# Optional overrides when the server key is published out-of-band
cargo run -p pqq-client --example velocity-fetch -- <host:port> https://example.com/ \
   --kem-b64 <base64-public-key>
cargo run -p pqq-client --example velocity-fetch -- <host:port> https://example.com/ \
   --kem-file path/to/server_kem_public.bin
```

Enable key publication on the server by passing `--publish-kem` to the CLI
(`cargo run -p velocity-cli --bin velocity -- serve ... --publish-kem`) or by
calling `ServerConfig::publish_kem_public(true)` when embedding the server in
your own binary.

If the server advertises fallback-only service, the fetch example prints the
recommended ALPN/host/port so you can retry with `curl`, `wget`, or another
HTTP client.

### Drop-in application integration (`pqq-easy`)

The `pqq-easy` crate exposes a high-level client that mirrors HTTPS ergonomics.
By default it auto-discovers the ML-KEM key, caches it on disk, and falls back
to HTTPS when the server requests downgrade:

```rust
use pqq_easy::EasyClientConfig;

let config = EasyClientConfig::builder()
   .server_addr("example.com:443")?
   .hostname("example.com")
   .build()?; // auto-discovers the Velocity ML-KEM key
let client = pqq_easy::EasyClient::connect(config)?;
let body = client.fetch_text("/status")?;
```

Disable discovery with `.server_key_autodiscover(false)` if your deployment
requires a pre-pinned key (for example, environments without `--publish-kem`).

## Platform support matrix

Velocity components are written in Rust and build on the major x86_64 and aarch64 operating systems. The table below lists the routinely verified environments and the recommended bootstrap commands.

| Platform | Status | Notes |
| --- | --- | --- |
| Debian 12 (Bookworm) | ✅ Supported | Use the `apt` bootstrap + systemd unit outlined below. |
| Ubuntu 22.04 LTS / 24.04 LTS | ✅ Supported | Identical to the Debian workflow; includes sample `systemd` unit. |
| Fedora 40 | ✅ Supported | Ensure `dnf install clang pkg-config` before building. |
| macOS 14 (Apple Silicon & Intel) | ✅ Supported | Install via Homebrew, use launchd plist (sample coming soon). |
| Windows 11 / Windows Server 2022 | ✅ Supported | Build with the `x86_64-pc-windows-msvc` toolchain via PowerShell.

> **Target architectures:** x86_64 and aarch64 are first-class; armv7 testing is planned. For containerized deployments use the same steps inside the base image (e.g., Debian slim).

### Debian & Ubuntu bootstrap

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev clang cmake
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
source "$HOME/.cargo/env"

# Clone and build Velocity
git clone https://github.com/projectvelocity/velocity.git
cd velocity
cargo build --workspace --release

# Run the CLI static server (self-signed certificate stored under ./public/.velocity/certs)
cargo run -p velocity-cli --bin velocity -- serve --root public --self-signed --listen 0.0.0.0:4433
```

For long-lived services on Debian/Ubuntu, install the sample `systemd` unit from `docs/systemd/velocity.service`:

```bash
sudo install -D docs/systemd/velocity.service /etc/systemd/system/velocity.service
sudo systemctl daemon-reload
sudo systemctl enable velocity
sudo systemctl start velocity
```

The unit expects the workspace at `/opt/velocity` with a deployment bundle in `/opt/velocity/deploy`. Adjust `WorkingDirectory` and `ExecStart` to match your layout.

### Fedora bootstrap

```bash
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y clang pkg-config openssl-devel
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
cargo build --workspace --release
```

### macOS bootstrap

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install rustup
rustup-init -y --default-toolchain stable
source "$HOME/.cargo/env"

# Optional: install launchd helper directory
mkdir -p ~/Library/LaunchAgents
cargo build --workspace --release
```

To run the static server with automatic certificate generation on macOS:

```bash
cargo run -p velocity-cli --bin velocity -- serve --root public --self-signed --listen 0.0.0.0:4433
```

### Windows bootstrap (PowerShell)

```pwsh
winget install --id Rustlang.Rustup --source winget
rustup default stable
git clone https://github.com/velocity-protocol/velocity.git
Set-Location velocity
cargo build --workspace --release

# Start the static site server
cargo run -p velocity-cli --bin velocity -- serve --root public --self-signed --listen 0.0.0.0:4433
```

For Windows services, wrap the CLI with `sc.exe create` or NSSM; a native Windows service host is on the roadmap.

## Configuration knobs

- `HandshakeConfig::with_supported_alpns` – advertise PQ-specific ALPNs.
- `HandshakeConfig::with_fallback_endpoint` – specify downgrade target (`h3`).
- `ServerConfig::from_cert_chain` – placeholder for hybrid certificate loading (future TLS integration).
- `ClientConfig::with_alpns` – set client ALPN preference order.

## Fallback topology

```
         ┌────────────────┐
         │     Client     │
         └────────┬───────┘
            │
            │ Initial (velocity/1, h3)
            ▼
         ┌────────────────┐
         │ Velocity Frontend │
         │  (pqq-server)  │
         └────────┬───────┘
            │
        ┌────────────┴────────────┐
        │                           │
   Velocity session established        Fallback advisory
        │                           │
        ▼                           ▼
    Application handler          HTTP/3 or HTTPS origin
```

Velocity always sends an explicit fallback directive when the client and server
cannot agree on `velocity/1`. Out of the box the handshake driver advertises an
HTTP/3 (`h3`) target on UDP/TCP port 443 so browsers can downgrade straight to
TLS 1.3 + QUIC. If you need a classical TLS or even plain HTTP target instead,
override the ALPN and endpoint via `HandshakeConfig::with_fallback_endpoint` on
both the server and client configuration. For example, setting the fallback to
`http/1.1` or `h2` directs Velocity-aware clients to reconnect over HTTPS on the
host/port you publish. Pair that endpoint with a reverse proxy (NGINX, Envoy,
etc.) to bridge legacy HTTP/1.x traffic when required.

## Certificate strategy

- Pilot deployments can begin with classical certificates; hybrid cert ingestion is on the roadmap.
- For experimental runs, generate self-signed certs and configure browsers/clients to trust the root.
- Documented CSR formats and CA guidance will land alongside Dilithium support.

## Networking considerations

- Ensure UDP 443 is reachable through firewalls/NAT.
- Enable ECMP-friendly connection IDs once migration support lands.
- Set `SO_REUSEADDR` if running multiple instances on the same host (todo: expose binding helper).

## Observability

- Enable structured logging: `RUST_LOG=pqq_server=info,pqq_core=debug`.
- Planned: metrics exporters for handshake latency, fallback rate, and key schedule timings.

## Reverse proxy integration

VELO can sit behind an existing HTTP reverse proxy while terminating PQ-QUIC at the edge.

### NGINX stream pass-through

1. Terminate PQ-QUIC with `pqq-server` bound to `127.0.0.1:4443`.
2. Configure NGINX stream block to fan in UDP 443 traffic:
   ```nginx
   stream {
      upstream velo_udp {
         server 127.0.0.1:4443;
      }

      server {
         listen 443 udp reuseport;
         proxy_pass velo_udp;
         proxy_responses 1;
      }
   }
   ```
3. Enable the HTTP gateway (e.g., `examples/browser-gateway`) to translate browser traffic and relay to PQ-QUIC for legacy clients.

### Envoy/HAProxy pattern

- Use a dedicated UDP listener forwarding to the VELO server’s `SocketAddr`.
- Preserve DCIDs by enabling consistent hashing (Envoy `use_original_dst`, HAProxy `hash-type consistent`) to maintain connection stickiness.
- For dual-stack nodes, expose IPv6 + IPv4 listeners and forward to a single PQ-QUIC instance; the handshake teasing fallback metadata ensures HTTP/3 downgrade continues via the reverse proxy if needed.

## CDN edge pilot recipe

1. Deploy VELO nodes on the edge fleet (close to POPs) with UDP 443 open and HTTP/3 fallback endpoints reachable inside the CDN fabric.
2. Run the `handshake-demo` binary in CI/CD smoke tests to assert PQ/legacy downgrade before promoting a POP.
3. Export the hybrid handshake transcript via `examples/handshake-transcript-dump` and stash the JSON output alongside POP health metrics. This provides quick detection if PQ primitives drift across deployments.
4. Front the PQ-QUIC servers with your CDN load balancer in “UDP proxy” mode and reuse existing TLS cert automation for the fallback origin. The fallback endpoint advertised by VELO should resolve to a classic HTTP/3 cluster.
5. Monitor:
   - PQ accept rate vs. fallback rate.
   - Kyber encapsulation latency (derived from `pqq_server::metrics` once implemented).
   - UDP error counters or NAT binding churn to size state tables appropriately.

## Production readiness checklist (pre-v1)

- [ ] ML-KEM/ML-DSA integration complete.
- [ ] Session tickets with replay mitigation.
- [ ] Congestion control tuned for PQ overhead.
- [ ] CI coverage with sanitizers & fuzzers.
- [ ] Formal verification summary published.

This guide will expand with automation scripts and deployment manifests as the project matures.
