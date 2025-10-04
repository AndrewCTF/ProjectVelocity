# Velocity Performance & Security Roadmap

_Last updated: 2025-10-04_

This memo captures actionable guidance for making Velocity the de-facto post-quantum successor to HTTPS. The recommendations synthesize recent public research and benchmark data and map directly onto our implementation backlog.

## Key research takeaways

- **Hybrid PQ handshakes incur modest latency if tuned carefully.** AWS reports only ~0.25 ms client / 0.23 ms server CPU overhead and ~2.3 kB of additional handshake data when combining X25519 with Kyber, especially when assembly-optimized code is used and long-lived connections are pooled [AWS24].
- **PQC-ready QUIC stacks show manageable impact when Kyber/Dilithium are used, while heavyweight schemes (e.g., SPHINCS+) create unacceptable handshake inflation.** A 2024 IFIP Networking study measured only minor handshake elongation for Kyber-family KEMs integrated into production QUIC libraries [Kempf24].
- **Naïve PQC integration can bloat TLS handshakes up to 7×; careful encoding and message coalescing cut the overhead by 40–60%.** Cross-platform benchmarks emphasize aggressive serialization optimizations, hybrid key scheduling, and re-usable session state as mandatory for high-volume deployments [Abbasi25].

## Implementation priorities

1. **Wire-efficiency**
   - Use the compact ALPN and handshake codecs landed in `pqq-core` (Oct 2025) to trim Initial packets and reply frames.
   - Follow up with certificate compression (CBOR or HPKE-based container) to address the 40–60% bandwidth reduction target from [Abbasi25].
   - Keep CBOR fallback paths for legacy peers, but prefer binary codecs for Velocity-native clients.

2. **Crypto selection & acceleration**
   - Default to ChaCha20-Poly1305 on low-end CPUs; auto-upgrade to AES-256-GCM when hardware support is detected (implemented in `pqq-tls` via `cpufeatures`, Oct 2025).
   - Upstream Kyber/Dilithium SIMD intrinsics to cut hybrid handshake times in line with [AWS24] measurements.
   - Track additional lattice KEM acceleration techniques (e.g., NTT batching) from [Kempf24].

3. **Session lifecycle**
   - Encourage long-lived pooled connections in client libraries; document recommended `max_connection_age` / pooling defaults aligned with [AWS24].
   - Harden anti-downgrade state (planned): cache highest-profile ALPN negotiated per peer and reject unexpected fallback requests.

4. **Edge & constrained devices**
   - Expose `SecurityProfile::Turbo` (Kyber512/Dilithium2) for IoT-class deployments; ship a profile tuning guide referencing the 12× variance observed in [Abbasi25].
   - Add deterministic padding controls so operators can trade bandwidth for side-channel resistance.

5. **Observability**
   - Emit per-handshake metrics (cipher, PQ profile, serialized byte counts) to validate that the codec changes continue hitting the 40–60% reduction goal.

## References

- [AWS24] _How to tune TLS for hybrid post-quantum cryptography with Kyber_, AWS Security Blog, 2024. <https://aws.amazon.com/blogs/security/how-to-tune-tls-for-hybrid-post-quantum-cryptography-with-kyber/>
- [Kempf24] Marcel Kempf et al., _A Quantum of QUIC: Dissecting Cryptography with Post-Quantum Insights_, IFIP Networking 2024. <https://arxiv.org/abs/2405.09264>
- [Abbasi25] Maryam Abbasi et al., _A Practical Performance Benchmark of Post-Quantum Cryptography Across Heterogeneous Computing Environments_, Cryptography 2025. <https://www.mdpi.com/2410-387X/9/2/32>
