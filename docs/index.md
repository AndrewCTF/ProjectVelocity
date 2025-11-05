# Velocity Documentation Hub# Velocity Documentation Hub



This folder collects the primary documentation artifacts for the VelocityVelocity ships with an extensive documentation suite to help operators, developers, security teams, and partner integrators adopt the protocol confidently. This hub is your navigation surface—every guide, reference, and whitepaper is indexed here with target audiences and prerequisites.

protocol reference stack. It is structured to help new contributors, protocol

authors, and integrators understand the current repository layout, how to build## 1. Orientation

and test the code, and what remains on the near-term roadmap.

| Document | Audience | Why you should read it |

- [Overview](#overview)|----------|----------|------------------------|

- [Quick Start](#quick-start)| [User Handbook](./user-handbook.md) | Platform engineers, SREs, early adopters | End-to-end walkthrough covering installation, simplified configs, CLI usage, telemetry, troubleshooting, and FAQ. |

- [Repository Map](#repository-map)| [Deployment Guide](./deployment.md) | Infrastructure teams | Production playbooks: single-node pilots, HA clusters, load-balancer steering, certificate automation, disaster recovery. |

- [Build, Lint, and Test](#build-lint-and-test)| [Developer Guide](./developer-guide.md) | Contributors, auditors | Workspace layout, build matrix, linting, test suites, fuzzing, coding conventions, API stability guarantees. |

- [Benchmarking Plan](#benchmarking-plan)| [Integration Guide](./integration-guide.md) | Full-stack engineers, product teams | Reverse proxy patterns, Service Mesh interop, embedding Velocity into existing HTTP pipelines, SaaS integration checklists. |

- [Protocol Highlights](#protocol-highlights)| [Upgrade Guide](./upgrade-guide.md) | Release managers | Semver policy, migration testing, blue/green deployment strategy, rollback procedures. |

- [SSH Migration Summary](#ssh-migration-summary)

- [Next Steps](#next-steps)## 2. Security & Cryptography



---* [Security Design](./security-design.md) — Hybrid cryptography rationale, threat model analysis, certificate policy, PQ signature validation flows, incident response hooks.

* [Velocity Exploit Hardening](./velocity-exploit-hardening.md) — Memory-safety posture, sandboxing recommendations, hardening flags, kernel tuning, red-team scenarios.

## Overview* [Velocity SSH Migration](./velocity-ssh-migration.md) — SSH transport mapping, host key bridging, PAM integration, audit logging, staged rollout plan.

* [HTTPS Migration Guide](./https-migration.md) — Browser compatibility roadmap, Nginx/Envoy front-door configuration, fallback monitoring.

Velocity is an experimental, post-quantum secure transport designed to replace* [HTTPS Roadmap](./https-roadmap.md) — Quarter-by-quarter initiatives to converge browsers on Velocity, CA ecosystem milestones, compatibility gates.

TLS 1.3 + QUIC. The current snapshot emphasises the bare essentials: a minimal

Rust crate (`velocity-core`) that parses Velocity packet headers, performs ALPN## 3. Operations & Performance

negotiation, and exposes a UDP handshake loop suitable for future handshake

work. Supporting documents such as the evolving protocol draft live under* [Benchmarking Playbook](./benchmarking.md) — Reproducing handshake microbenchmarks, page-load trials, AF_XDP fast-path tests, CSV interpretation, Grafana dashboards.

`spec/`.* [Performance & Security Roadmap](./performance-security-roadmap.md) — Targets for latency, throughput, CPU budgets, privacy enhancements, kernel bypass adoption.

* [Operations Manual](./operations.md) — Day-2 operations: metrics, alerting, SLOs, log schema, telemetry pipelines, incident handling.

The broader project goals (hybrid PQ handshake, HTTP adapters, SSH transport)* [Systemd Service Guide](./systemd-service.md) — Hardened unit files, journal integration, auto-restart strategies, controlled rollout.

are documented in `ROADMAP.md` and the `spec/protocol-draft.md` working draft.* [Docker & Local Sandbox](./docker-local.md) — Container-based development environment, Compose topology, troubleshooting.

This folder complements those documents with task-oriented guidance.

## 4. Governance, Compliance, and Community

## Quick Start

* [Velocity Governance](../GOVERNANCE.md) — Maintainer roles, approval workflow, security review cadence.

The instructions below assume the Rust toolchain pinned in `rust-toolchain.toml`* [Contribution Guidelines](../CONTRIBUTING.md) — Coding standards, review expectations, CI requirements.

(stable channel). Commands are presented using PowerShell syntax to match the* [Security Policy](../SECURITY.md) — Vulnerability disclosure instructions, triage SLAs, signing keys.

Windows development environment.* [Roadmap](../ROADMAP.md) — Release milestones, spec revisions, adoption programs.



```pwsh## 5. Specialized Guides

# (Optional) ensure the pinned toolchain is installed

rustup show* [Deployment Appendix](./deployment.md#appendices) — Terraform snippets, Ansible roles, AWS/GCP/Azure reference architectures.

* [Upgrade Runbooks](./upgrade-guide.md#runbooks) — Stepwise procedures for each supported version family.

# Format the code base and run warnings-as-errors checks* [Troubleshooting Matrices](./user-handbook.md#troubleshooting) — Symptom-driven diagnosis for handshake failures, performance regressions, certificate alarms.

cargo fmt* [CA Operations](./ca-operations.md) — Velocity CA issuance workflows, ACME extensions, certificate transparency integration.

cargo clippy -p velocity-core --all-targets -- -D warnings* [Formal Verification Notes](../spec/formal/README.md) — Summaries of Tamarin/ProVerif models, proof obligations, coverage.



# Execute the unit tests for the transport core## 6. How to use this hub

cargo test -p velocity-core

```1. **Start with the User Handbook** to get a mental model of the CLI and config. The handbook links directly to quickstart scripts and sandbox environments.

2. **Pick a track** (operations, security, integration, developer) and follow recommended reading order within each track.

If the tooling completes without errors, the skeleton is ready for further3. **Document readiness checklists** from each guide roll up into [`docs/troubleshooting.md`](./user-handbook.md#readiness-checklists) so you can validate pilot readiness.

extension. At this stage only `velocity-core` is part of the workspace.4. **Bookmark status dashboards** described in [`docs/operations.md`](./operations.md#observability) to continuously watch downgrade ratios, PQ validation failures, and handshake latency.



## Repository Map> **Tip:** Every document in this site begins with a change-log section summarizing the last three revisions. Link directly to anchors like `#configuration-matrix` to embed Velocity guidance into your internal docs.



The key paths relevant to this documentation snapshot are:If a topic is missing, open an issue tagged `docs` with the expected audience, outcomes, and timelines. Documentation is versioned alongside code—check commit history when preparing audits or compliance reviews.


| Path | Description |
|------|-------------|
| `Cargo.toml` | Cargo workspace root (currently limited to `velocity-core`). |
| `crates/velocity-core/` | Minimal transport crate with UDP loop, packet parsing, ALPN helpers. |
| `docs/` | Documentation hub (this folder). |
| `spec/protocol-draft.md` | RFC-style living draft describing Velocity/1 handshake and wire formats. |
| `benchmarks/handshake-bench/` | Criterion harness prepared for future handshake benchmarking. |
| `README.md` | High-level project summary pointing to this documentation set. |

Additional directories (e.g., `native-bindings/`, `examples/`) exist from the
long-term roadmap but may not yet contain functional code. They remain as
placeholders to align with the expected repository layout once higher level
crates are reintroduced.

## Build, Lint, and Test

Velocity targets stable Rust. The commands below represent the recommended
workflow before submitting changes:

1. **fmt**: `cargo fmt`
2. **clippy**: `cargo clippy -p velocity-core --all-targets -- -D warnings`
3. **tests**: `cargo test -p velocity-core`

When additional crates are added, expand the commands to `--workspace`. Until
then, keeping the focus on the single crate keeps the development loop fast.

If you modify packet parsing logic or ALPN helpers, consider adding new test
cases inside `crates/velocity-core/src/lib.rs` (unit tests live at the bottom of
the file). Keep tests deterministic so CI can run them in isolation without
network access.

## Benchmarking Plan

The `benchmarks/handshake-bench` crate is scaffolded for future Criterion-based
microbenchmarks. Once the hybrid handshake is implemented, run:

```pwsh
cargo bench -p handshake-bench
```

The harness already separates in-memory and UDP-based handshakes, as well as
baseline TLS 1.3 comparisons. For now the benchmark may not compile while other
crates are absent; re-enable it after the handshake code lands.

## Protocol Highlights

For a deep dive into handshake messaging, PQ profiles, and fallback behaviour,
consult `spec/protocol-draft.md`. The highlights relevant to this snapshot are:

- ALPN token: `velocity/1`
- Packet header format closely follows QUIC with destination/source connection
  IDs and payload length.
- Security profiles: `light`, `balanced`, `fortress`, each combining X25519 with
  Kyber and Dilithium variants.
- Fallback strategy: clients advertise `velocity/1` alongside HTTP/3; servers
  respond with structured fallback directives when Velocity cannot be negotiated.

The `velocity-core` crate provides the parsing primitives necessary to interpret
Initial packets and extract ALPN payloads without pulling in the full transport
stack.

## SSH Migration Summary

`docs/ssh-migration.md` outlines how the Velocity transport can act as a drop-in
replacement for SSH’s TCP transport. Key points:

- `vsh-proxy` acts as an OpenSSH `ProxyCommand`, establishing Velocity sessions
  before forwarding SSH traffic.
- `vshd` bridges Velocity streams into `sshd`, preserving existing
  authentication methods.
- Hybrid certificates issued by the Velocity CA are cross-signed into SSH host
  certificates; clients verify both classical and Dilithium signatures.

These notes will be expanded alongside the development of `velocity-ssh-bridge`.

## Next Steps

Short-term goals tracked on the roadmap include:

1. Implementing header protection and connection ID recycling in `velocity-core`.
2. Landing the `velocity-crypto` crate with hybrid handshake state machine.
3. Wiring up example applications (static file server, JSON API) and updating
   this documentation accordingly.

Contributors are encouraged to update this folder whenever new features land,
keeping the documentation aligned with implementation reality.
