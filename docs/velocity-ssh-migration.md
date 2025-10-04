# Velocity SSH Migration Strategy

*Version: Draft 2025-09-30 — aligns with Velocity protocol draft v0.1*

Migrating existing SSH infrastructure to the Velocity transport requires a staged plan that preserves operational continuity, maintains security guarantees, and limits changes to user workflows. This document outlines an actionable strategy for introducing Velocity as the transport substrate beneath OpenSSH, libssh, and compatible tooling.

## Goals

1. **Transparent user experience**: keep the familiar `ssh user@host` workflow, reusing existing key material whenever possible.
2. **Incremental rollout**: permit gradual enablement starting with opt-in pilots, progressing to Velocity-by-default, and finally Velocity-only deployments.
3. **Hybrid assurance**: ensure that Velocity connections maintain forward secrecy and post-quantum security while still allowing classical fallbacks during the transition.
4. **Operational visibility**: provide telemetry and logging so administrators can monitor adoption, spot downgrade attempts, and diagnose failures quickly.

## Architecture overview

Velocity introduces a thin transport shim that runs alongside existing SSH daemons:

- `velocity-ssh-bridge`: Rust crate that exposes `connect_vsh(host, cfg)` returning an `AsyncRead + AsyncWrite` pair. It negotiates the Velocity handshake using the `velocity-client` crate, establishes a dedicated control stream, and proxies SSH bytes with minimal buffering.
- `vsh-proxy`: CLI installed on clients. It implements the `ProxyCommand` interface so that users can add a single stanza to `~/.ssh/config`:
  ```
  Host velocity-example
    ProxyCommand vsh-proxy %h %p
  ```
  The proxy attempts Velocity first, optionally reusing cached PSK tickets for 0-RTT reconnections. If negotiation fails, it falls back to TCP while emitting downgrade telemetry.
- `vshd`: System service that listens on UDP 443 (Velocity) and bridges authenticated sessions into the local `sshd` via `ProxyUseFd` or a UNIX domain socket. It enforces per-session policies (e.g., disallowing 0-RTT for agent forwarding streams) and records cryptographic material for audit trails.

## Migration phases

1. **Discovery (Weeks 0–2)**
   - Deploy `vsh-proxy` to a subset of willing users.
   - Stand up `vshd` on alternate ports (e.g., UDP 4422) behind a load balancer. Configure DNS SRV records advertising Velocity capability without disrupting existing TCP endpoints.
   - Collect telemetry on success/failure rates, handshake durations, and fallback occurrences. Initial targets: ≥95% Velocity success within pilot groups.

2. **Parallel adoption (Weeks 3–6)**
   - Enable Velocity on the canonical SSH hostname while keeping TCP on port 22. Clients attempt Velocity first, falling back transparently when necessary.
   - Rotate host certificates to Velocity-issued hybrids. Each certificate bundles the existing host key fingerprint alongside a Dilithium signature signed by the Velocity CA. Document the new fingerprint format: `host ed25519 AAAA... @velocity d1lith1um...`.
   - Update configuration management (Ansible, Chef, Puppet) to install Velocity certificates, configure `vshd`, and manage firewall openings (UDP 443).
   - Begin issuing Velocity-only session tickets to compatible clients, reducing handshake latency on reconnects.

3. **Velocity-by-default (Weeks 7–10)**
   - Mark TCP transport as legacy. Clients display warnings when falling back, encouraging upgrades.
   - Tighten security policies: enforce ECH in the Velocity handshake, require Dilithium signatures on fallback records, and deny 0-RTT for interactive shells until replay protections are fully validated.
   - Expand telemetry collection to central observability stacks. Metrics of interest include handshake success rate, fallback reason distribution, RTT histograms, and agent-forwarding session counts.

4. **Velocity-required (Weeks 11+)**
   - Disable TCP listeners for tenants that have met readiness criteria. Provide bastion hosts capable of Velocity↔TCP translation for legacy tooling.
   - Enforce policy checks: clients lacking Velocity support must use emergency `--legacy` flags producing temporary audit noise.
   - Schedule periodic red-team exercises focusing on downgrade and replay attempts to validate defences.

## Key management

- **Certificates**: The Velocity CA issues hybrid certificates that bind SSH host keys to Dilithium public keys. Certificates include validity windows aligned with existing SSH key rotation policies (e.g., 90 days) to encourage hygiene.
- **Known hosts**: Extend the known-hosts format to include Velocity hashes. An example entry:
  ```
  velocity.example.com ssh-ed25519 AAAAC3... @velocity sha256:Zq1... profile=balanced
  ```
  SSH clients warn if the Velocity hash is missing or mismatched, mirroring today’s host key change prompts.
- **Client authentication**: User keys remain unchanged. The Velocity transport carries the standard SSH authentication exchange without modification, ensuring compatibility with hardware tokens and agent forwarding.

## Telemetry & observability

- `vshd` emits structured logs (`JSON Lines`) for each session: negotiated profile, handshake duration (µs), resumption flag, fallback reason, and client software version. Logs integrate with Fluent Bit or Vector for shipping to observability backends.
- `vsh-proxy` records local metrics exposed via Prometheus on `localhost:9898` (opt-in). Counters track Velocity success, fallback counts, replay rejections, and agent-forwarding streams.
- An aggregated dashboard correlates Velocity adoption with security posture improvements (e.g., share of sessions protected by PQ signatures).

## Risk mitigation

- **Downgrade awareness**: Signed fallback records allow operators to trace when clients resort to TCP, distinguishing deliberate policy decisions from adversarial interference.
- **Replay safeguards**: `vshd` enforces single-use tickets for privileged channels (agent forwarding, port forwarding). Tickets include replay windows (default 5 minutes) and IP binding hints.
- **Failure isolation**: The shim can be bypassed per-host (`ProxyCommand none`) if operational issues arise. Rollback instructions consist of disabling Velocity listeners and reloading firewall rules.
- **Compliance**: Audit logs include Dilithium signature verification status, enabling compliance teams to prove PQ assurances during assessments.

## Success criteria

- ≥99% of interactive SSH sessions use Velocity within three months of launch.
- Measurable reduction (≥40%) in median reconnect time due to 0-RTT resumption.
- Zero critical security regressions as validated by quarterly penetration tests.
- Positive operator feedback on observability tooling and minimal user disruption during the migration.

This plan evolves alongside the Velocity reference implementation. Feedback from early adopters will inform tooling improvements, documentation updates, and the refinement of operational runbooks stored under `docs/`.
