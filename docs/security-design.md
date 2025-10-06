# Velocity Security Design

> Definitive reference for Velocity’s security posture, cryptographic design, and operational safeguards. Aligns with the threat model defined in the system prompt and the Velocity/1 protocol draft.

---

## 1. Change log

| Date | Revision | Notes |
|------|----------|-------|
| 2025-10-06 | 1.0 | Rebuilt document to cover Velocity/1 hybrid handshake, certificate policy, telemetry, and incident response. |

## 2. Security goals

1. **Post-quantum confidentiality** — Hybrid construction preserves secrecy even if either classical or PQ primitive fails.
2. **Mutual authenticity** — Certificates and optional client auth rely on Dilithium + classical signatures.
3. **Downgrade awareness** — Every fallback event is surfaced with structured telemetry.
4. **Replay resistance** — 0-RTT guarded by server-side replay windows and method whitelists.
5. **Operational visibility** — Metrics and logs expose cryptographic anomalies promptly.

## 3. Threat model summary

| Adversary | Capability | Mitigation |
|-----------|------------|------------|
| Passive | Record traffic, attempt retrospective decryption | Hybrid key exchange, short ticket lifetime, encrypted transcript. |
| Active MITM | Modify packets, inject handshake messages, attempt downgrade | Transcript binding, profile commitments, PQ signature validation, ALPN enforcement. |
| Malicious client | Flood server, attempt replay, misuse 0-RTT | Retry tokens, proof-of-work hooks, replay window tracking, method gating. |
| Compromised CA | Issue fraudulent certs | PQ extension cross-check, CT logging roadmap, policy requiring PQ validation. |
| Insider | Access ticket secrets or logs | Secret rotation, access controls, log redaction. |

## 4. Cryptographic architecture

* **Key exchange**: X25519 + Kyber (profile-specific). Combined via HKDF as described in [`spec/protocol-draft.md`](../spec/protocol-draft.md#7-key-schedule).
* **Signatures**: Dilithium 2/3 in certificate extension + classical ECDSA/Ed25519. Both MUST validate.
* **AEAD**: ChaCha20-Poly1305 default, AES-128-GCM optional when both advertise support.
* **Transcript hash**: SHA-512 for all handshake transcripts.
* **Session tickets**: AEAD-sealed with HKDF-derived keys. Rotation ≤24h.

## 5. Hybrid certificates

Hybrid certificates embed PQ metadata in extension `1.3.6.1.4.1.56565.1.1` encoded as CBOR:

```cbor
{
	"pq_sig_alg": "dilithium3",
	"pq_signature": h'...bytes...',
	"profile": "balanced",
	"policy": {"require_ech": true, "allow_0rtt": false}
}
```

Operational requirements:

* PQ signature MUST verify; otherwise abort with `CERT_PQ_VALIDATION_FAILED`.
* Classical-only chains permitted only when policy flag `allow_classical_fallback` enabled.
* Certificate rotations maintain overlap (≥24h) to avoid fallback spikes.

## 6. Downgrade resilience

* Profile commitments stored in tickets; lower renegotiated profile triggers telemetry and optional abort.
* ALPN selection bound to transcript; MITM tampering fails Finished verification.
* Metric `velocity_downgrade_events_total{reason="<code>"}` fuels alerts.

## 7. 0-RTT safeguards

* Tickets contain `max_early_data`, `allowed_methods`, and `ticket_nonce`.
* Replay window tracked via salted Bloom filters keyed by `ticket_id` + `client_ip_hash`.
* Default policy denies non-idempotent methods; override with explicit config.

## 8. Telemetry for security events

| Event | Log fields | Metric |
|-------|------------|--------|
| PQ validation failure | `event="pq_validation_failed"`, `subject_cn`, `profile` | `velocity_pq_validation_failures_total` |
| Downgrade | `event="downgrade"`, `reason`, `requested_alpn`, `fallback_alpn` | `velocity_downgrade_events_total` |
| 0-RTT replay | `event="0rtt_replay"`, `ticket_id`, `client_ip_hash` | `velocity_0rtt_replay_rejections_total` |
| Retry issued | `event="retry_issued"`, `token_age_ms`, `client_ip_hash` | (log only) |

## 9. Key management

* Ticket secrets rotate via `velocity-cli tickets rotate`; store in HSM/KMS.
* Certificate private keys restricted to `velocity` user, permissions `0600`.
* Logs redact IP addresses by default (hash with rotating salt).

## 10. Optional anti-abuse controls

* Configure proof-of-work challenges in Retry tokens (`anti_abuse.proof_of_work`).
* Enable rate limiting via edge runtime middleware (see `docs/deployment.md#appendix-c-edge-runtime-schema`).

## 11. Security operations

1. Monitor metrics; alert thresholds defined in [`docs/operations.md`](./operations.md#alerting).
2. On incident, capture diagnostics with `velocity-cli admin diagnostics --dump` and follow [`SECURITY.md`](../SECURITY.md#incident-response).
3. Document key rotations and downgrades in change management system.

## 12. Future enhancements

* PQ certificate transparency with Merkle proofs.
* Hardware-backed ticket secrets.
* Automated downgrade chaos testing.

# Security Design

This document summarises the security posture of VELO's PQ-QUIC stack, aligning implementation choices with the threat model in the system prompt.

## Threat model recap

- **Passive adversary** capturing traffic for future quantum decryption.
- **Active MITM** capable of modifying handshake messages, replaying packets, and probing downgrade paths.
- **Resource-constrained DoS actor** sending bogus Initial packets to exhaust CPU/bandwidth.

Assumptions: certificate authorities may be partially compromised; endpoints can rotate secrets; client device compromise is out of scope.

## Cryptographic primitives

- **Hybrid key exchange**: X25519 + ML-KEM-768 (via `KemProvider`). The production build requires the `mlkem` feature; unit tests rely on a deterministic test provider to keep fixtures reproducible without weakening shipped binaries.
- **Signatures**: ML-DSA-65 (planned) with optional ECDSA for transitional deployments. Placeholder hooks live in `pqq-tls::handshake` to attach signature verification once certificates arrive.
- **AEAD**: ChaCha20-Poly1305 preferred, AES-128-GCM as optional path with hardware acceleration.
- **Hashing**: SHA-256 via HKDF for key schedule derivations.

