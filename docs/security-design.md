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

## Handshake guarantees

1. Client sends Initial packet containing classical and PQ shares (`ClientHelloPayload`).
2. Server returns ML-KEM ciphertext, classical share, and HKDF-based authentication tag.
3. Both sides derive `HybridKeySchedule` combining classical + PQ secrets.
4. Transcript is bound to ALPN choice and cipher suite (see `spec/protocol-draft.md` §4.3).

Downgrade attempts are mitigated by covering ALPN selection in the transcript and requiring Dilithium signatures (planned) for fallback messages.

## Session resumption (planned)

- Tickets will encapsulate seeds for regenerating ML-KEM key pairs and include replay filters (Bloom filters with 2^-20 false positive rate).
- 0-RTT permitted only for idempotent requests; application APIs must opt-in.

## Fallback safety

- `AlpnResolution::Fallback` responses include the fallback ALPN and endpoint metadata, signed once ML-DSA hooks land.
- Clients log telemetry for repeated downgrades to detect misconfigured peers.
- Spec defers to HTTP/3/TLS1.3 when PQ support is absent.

## DoS and resource limits

- Handshake buffers are capped at 16 KiB per datagram.
- Future mitigations: stateless retry with ML-DSA-signed tokens, rate limiting via token buckets, optional client puzzles.

## Formal methods

- `spec/formal/pq_quic_handshake.spthy` models hybrid key agreement, asserting mutual authentication.
- Upcoming work: extend model for session tickets, integrate ProVerif queries for forward secrecy.

## Key management

- ML-KEM secret material lives in memory for the shortest duration possible (see `ServerHandshake::respond`).
- Planned: zeroise secrets after use and integrate hardware-backed key storage for edge deployments.

## FFI considerations

- `native-bindings` exposes minimal C ABI; functions currently stubbed while design for memory ownership and lifetime guarantees is documented.
- Future work: adopt `cbindgen`, document thread-safety, and enforce input validation before crossing the FFI boundary.

## Open risks & TODOs

- [ ] Integrate real ML-DSA verification and certificate parsing.
- [ ] Implement transcript binding for fallback metadata (currently implicit via server trust).
- [ ] Harden UDP socket handling against amplification attacks (rate-limit unauthenticated responses).
- [ ] Add constant-time comparisons for authentication tags and future MACs.

For additional discussion, open security issues with the `security` label or refer to `SECURITY.md` for responsible disclosure steps.

## Security contact key

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: OpenPGP v4.1.0

mDMEZUZ3mxYJKwYBBAHaRw8BAQdAtev3MCmxsJ+ef2V2l6lmYB9DwyiEBK4nTsWy
gUgv1czNFGFscGhhIEt3b2sgPHNlY3VyaXR5QHZlbG8uZGV2PoiQBBMWCAA4FiEE
LwVMZeQ7i3dPiaLKbX6oPCdEl3UFAmVHd5sCGwMFCwkIBwICIgIGFQoJCAsCBBYC
AwECHgECF4AACgkQbX6oPCdEl3WH+AD/YM3tu+R14dkN6prIJNZOcShz+2a0a8Fa
1ZPCY0cy3UZAP9KwYZBvqdMdzf4wkF62hjm+7Yf4T8PkOSZ9XOoShzzlLgEuDgEZ
UZ3mxIKKwYBBAGXVQEFAQEHQJtuHtq7oplLr4oQPN3yVYxIh2b0EWn9tmRUvU2hW
hTuaAwEIB4h+BBgWCAAmFiEELwVMZeQ7i3dPiaLKbX6oPCdEl3UFAmVHd5sCGwwA
KgkQbX6oPCdEl3WFAADoXAD+IeCvG2tH/PGIgX9xiSPeLsaLslhlkQeZAzd+5Sz3
8jcBAL1iSOrl7c8aSvCzrtqN8eYw6NUZOA7wO1ig9vDPGQpHDAM=
=pV6r
-----END PGP PUBLIC KEY BLOCK-----
```
