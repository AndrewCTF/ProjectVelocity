# Quick Start Guide

This guide walks through configuring the development environment, running the
existing Velocity components, and understanding how to extend the repository.
All commands assume Windows PowerShell (`pwsh.exe`). Adjust paths accordingly
if you are working from a different shell.

## 1. Prerequisites

- **Rust toolchain**: install Rust using <https://rustup.rs/>. Velocity pins the
  toolchain in `rust-toolchain.toml`; `rustup` will auto-select the correct
  channel (currently stable) when you run Cargo commands.
- **CMake**: not required for the current snapshot, but useful once PQ crypto
  backends that depend on C toolchains are reintroduced.
- **Git**: required for version control operations.

You can verify the toolchain with:

```pwsh
rustup show
cargo --version
```

## 2. Clone and Inspect the Repository

```pwsh
# Replace the URL with your fork if applicable
git clone https://github.com/AndrewCTF/ProjectVelocity.git
cd ProjectVelocity

# Confirm the workspace is clean
git status
```

The workspace currently contains a minimal set of crates with the emphasis on
`velocity-core`.

## 3. Build and Test the Transport Core

```pwsh
# Format code
cargo fmt

# Lint with Clippy (treat warnings as errors)
cargo clippy -p velocity-core --all-targets -- -D warnings

# Run unit tests
cargo test -p velocity-core
```

The tests exercise packet parsing edge cases (length validation, ALPN parsing)
and ALPN negotiation decisions. Add new tests alongside the existing ones in
`crates/velocity-core/src/lib.rs` as features evolve.

## 4. Explore the UDP Handshake Loop

The function `velocity_core::run_udp_handshake_loop` demonstrates how Initial
packets can be parsed from a live UDP socket using Tokio.

Example usage:

```rust
use std::net::SocketAddr;
use velocity_core::{parse_packet, run_udp_handshake_loop, ParsedPacket};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    run_udp_handshake_loop("127.0.0.1:44330", |peer: SocketAddr, packet: ParsedPacket<'_>| {
        println!("received {:?} from {}", packet.header.packet_type, peer);
    }).await
}
```

This loop is intentionally simple: the handler executes synchronously so that
higher-level crates can be introduced later without committing to a particular
asynchronous strategy.

## 5. Understand the Protocol Draft

The living specification resides in `spec/protocol-draft.md`. It documents:

- Packet framing and message vocabulary.
- Hybrid cryptography profiles (`light`, `balanced`, `fortress`).
- ALPN negotiation and fallback semantics.
- Resumption, anti-downgrade strategies, and SSH transport mapping.

Review the draft before making changes to packet layouts or handshake logic to
ensure code and documentation stay aligned.

## 6. Benchmarking (Future Work)

The Criterion harness at `benchmarks/handshake-bench` contains scaffolding for
measuring handshake performance. Once the hybrid handshake crate is available,
run:

```pwsh
cargo bench -p handshake-bench
```

Results will appear under `target/criterion/`. Update the benchmark harness with
additional scenarios (e.g., fallback to HTTP/3, resumed sessions) as the transport
stack evolves.

## 7. Contributing

1. Create a feature branch from the active development branch.
2. Make changes, keeping documentation (`docs/`) up to date.
3. Ensure `cargo fmt`, `cargo clippy`, and relevant tests pass.
4. Submit a pull request summarising changes, tests, and any open questions.

Refer to `CONTRIBUTING.md` for the full checklist and code review expectations.

## 8. Troubleshooting

| Symptom | Resolution |
|---------|------------|
| `cargo build` fails due to missing crates | Ensure you removed any lingering references to removed third-party patches (`third_party/paste` has been deleted). Run `cargo metadata` to confirm the workspace only contains `velocity-core`. |
| Tests fail after modifying packet parsing | Double-check payload length calculations and connection ID bounds. The unit tests cover typical failure cases; extend them when introducing new constraints. |
| Need more context on handshake bytes | Read `spec/handshake-bytes.md` for transcripts once they are regenerated after protocol changes. |

Keep this guide updated as the project grows. Every new feature or crate should
come with documentation updates so contributors can ramp up quickly.
