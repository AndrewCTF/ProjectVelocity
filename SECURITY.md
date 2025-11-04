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

## Known Vulnerabilities (Current Status as of v0.3.3)

### Critical Dependencies - All Fixed ✅

All critical dependency vulnerabilities have been resolved as of November 2025:

1. **protobuf 2.28.0** (RUSTSEC-2024-0437) - ✅ **FIXED**
   - **Issue**: Uncontrolled recursion can crash on malicious input
   - **Resolution**: Upgraded prometheus 0.13 → 0.14 (now uses protobuf >=3.7.2)
   - **Fixed in**: velocity-cli v0.3.2

2. **rustls 0.20.9** (RUSTSEC-2024-0336) - **HIGH SEVERITY 7.5** - ✅ **FIXED**
   - **Issue**: Potential infinite loop based on network input
   - **Resolution**: Upgraded tokio-rustls 0.23 → 0.26 (now uses rustls 0.23.34)
   - **Fixed in**: handshake-bench v0.2.0

3. **ring 0.16.20** (RUSTSEC-2025-0009) - ✅ **FIXED**
   - **Issue**: AES functions may panic with overflow checking
   - **Resolution**: Upgraded via tokio-rustls (now uses ring 0.17.14)
   - **Fixed in**: handshake-bench v0.2.0

### Unmaintained Dependencies (Medium Priority)

- **paste 1.0.15** - Used by pqcrypto-mldsa (evaluating migration path)
- **unic-* crates** - Used by tera template engine (considering alternatives)

### Fixed Vulnerabilities

- ✅ **7 critical unwrap/expect panics** in production code (fixed v0.3.3)
- ✅ **Poison-unsafe mutex handling** in telemetry (fixed v0.3.3)
- ✅ **FFI CString interior null vulnerabilities** (fixed v0.3.3)

## Security Audit Summary (November 2025)

Our comprehensive security audit reviewed:

- **60+ unwrap() calls** - Fixed critical production paths
- **100+ expect() calls** - Documented or replaced with error handling
- **14 unsafe blocks** - In progress: adding safety documentation (3/14 complete)
- **20+ vulnerability categories** - Systematic review and remediation
- **FFI boundary** - Hardened with NULL checks and ownership documentation
- **Input validation** - Path traversal protection verified
- **CI/CD hardening** - Added `cargo-audit` to prevent regressions

## Hardening commitments

- Mandatory code review by two maintainers for handshake, key schedule, or FFI changes.
- Continuous integration runs `cargo audit`, `cargo clippy`, `cargo test`, and fuzzing smoke tests.
- Formal verification artefacts (Tamarin/ProVerif) accompany protocol changes.
- Security documentation (`docs/security-design.md`) tracks assumptions, mitigations, and remaining risks.
- **NEW**: Automated dependency vulnerability scanning in CI (cargo-audit)
- **NEW**: Systematic security audits every release cycle

## Post-Quantum Security Guarantees

Velocity implements hybrid post-quantum cryptography:

- **Key Exchange**: X25519 + ML-KEM (Kyber512/768/1024)
- **Signatures**: Ed25519/ECDSA + ML-DSA (Dilithium2/3)
- **Forward Secrecy**: Ephemeral keys for every handshake
- **Replay Protection**: Anti-replay windows for 0-RTT resumption
- **Downgrade Protection**: ALPN negotiation with mandatory security levels

### Cryptographic Recommendations

1. Use at least the `balanced` security profile (Kyber768)
2. Rotate session ticket keys every 24-48 hours
3. Set short ticket lifetimes (< 12 hours for production)
4. Disable 0-RTT for state-changing operations
5. Enable strict transport security to prevent downgrades

Thank you for helping us secure PQ-QUIC for the wider Internet.
