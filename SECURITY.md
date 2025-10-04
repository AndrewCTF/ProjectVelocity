# Security Policy

The VELO team is committed to shipping a PQ-QUIC reference implementation that is safe to deploy and easy to audit. Security research is welcome—please follow the process below when reporting vulnerabilities.

## Supported versions

| Version branch | Supported? | Notes |
| -------------- | ---------- | ----- |
| `main`         | ✅         | Active development and nightly CI coverage. |
| Release tags (`v0.x.y`) | ✅ | Supported until superseded by the next tag or security patch. |
| Pre-release snapshots | ⚠️ | Evaluated case by case; please flag regressions but expect rapid iteration. |

Older releases are not supported; upgrade to the latest tag to receive fixes.

## Reporting a vulnerability

1. Email **security@projectvelocity.org** with an encrypted report.
2. Include:
   - Impact assessment and reproduction steps.
   - Affected commit hash or release tag.
   - Suggested mitigations if available.
   - Requested disclosure timeline (default 90 days).
3. Expect acknowledgment within **48 hours** and a triage decision within **7 days**.

Please avoid filing public issues for security-sensitive problems until we coordinate a fix.

## Responsible disclosure timeline

- Day 0: Report received, triage acknowledgment sent.
- Day 7: Mitigation strategy shared with reporter.
- Day 30: Fix developed, patches reviewed, regression tests added.
- Day 45: Coordinated release with assigned CVE (if applicable) and public advisory.
- Day 90: Default disclosure deadline; may be accelerated if the issue is actively exploited.

We may request additional time for complex cryptographic issues but strive to publish fixes quickly.

## Bounty program

While not yet formalised, we intend to sponsor high-impact findings via the OpenSSF Criticality framework. Stay tuned for updates on the bug bounty launch in `ROADMAP.md`.

## Hardening commitments

- Mandatory code review by two maintainers for handshake, key schedule, or FFI changes.
- Continuous integration runs `cargo audit`, `cargo clippy`, `cargo test`, and fuzzing smoke tests.
- Formal verification artefacts (Tamarin/ProVerif) accompany protocol changes.
- Security documentation (`docs/security-design.md`) tracks assumptions, mitigations, and remaining risks.

Thank you for helping us secure PQ-QUIC for the wider Internet.
