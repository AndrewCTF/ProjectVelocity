---
title: Velocity Protocol Draft (velocity/1)
description: Architectural draft describing the Velocity post-quantum transport (ALPN `velocity/1`).
status: Implementation-aligned living document (Velocity/1 reference profile)
---

# Velocity Protocol Draft — ALPN `velocity/1`

*This draft supersedes all prior documentation for Velocity/1. It consolidates the protocol architecture, cryptographic profile, transport parameters, and fallback behaviours required for interoperable implementations. The text is maintained alongside the reference implementation and updated on every release.*

## Table of contents

1. [Status of this Document](#status-of-this-document)
2. [Terminology and Notation](#2-terminology-and-notation)
3. [Architecture Overview](#3-architecture-overview)
4. [Packet Vocabulary](#4-packet-vocabulary)
5. [Cryptographic Components](#5-cryptographic-components)
6. [Handshake Flow](#6-handshake-flow)
7. [Key Schedule](#7-key-schedule)
8. [Hybrid Certificates and Authentication](#8-hybrid-certificates-and-authentication)
9. [ALPN Negotiation and Fallback](#9-alpn-negotiation-and-fallback)
10. [Session Resumption and 0-RTT](#10-session-resumption-and-0-rtt)
11. [Transport Parameters](#11-transport-parameters)
12. [Versioning and Extension Policy](#12-versioning-and-extension-policy)
13. [Operational Guidance](#13-operational-guidance)
14. [Security Considerations](#14-security-considerations)
15. [Privacy Considerations](#15-privacy-considerations)
16. [IANA Considerations](#16-iana-considerations)
17. [References](#17-references)
18. [Appendix A — Error Code Registry](#appendix-a--error-code-registry)
19. [Appendix B — Reference Transcript](#appendix-b--reference-transcript)

## Status of this Document

This is an informative yet normative reference for Velocity/1. The living nature of the document means sections may be revised between releases; version tags in the repository capture the specification snapshot applicable to that release. Implementers targeting long-lived deployments SHOULD pin to a tagged revision.

## 2. Terminology and Notation

* Normative language **MUST**, **SHOULD**, **MAY** follows [RFC 2119].
* Binary field descriptions use triangular brackets (e.g., `<uint32>`).
* ASCII literals appear in double quotes. Hexadecimal literals are `0x` prefixed.
* Velocity’s on-wire version number for Velocity/1 is `0x56553100` (`"VU1\0"`).
* QUIC terminology (stream, connection ID, packet number) retains its conventional meaning.

## 3. Architecture Overview

Velocity is a secure transport built on top of UDP. It embraces QUIC’s latency profile while embedding a post-quantum (PQ) hybrid handshake. The reference stack consists of:

1. **velocity-core** — packet parsing, stream mux/demux, congestion-control hooks, connection migration support.
2. **velocity-crypto** — orchestrates the hybrid handshake, manages certificates, derives keys, and encodes session tickets.
3. **velocity-server** / **velocity-client** — expose high-level HTTP APIs, CLI tooling, and integration with legacy services.
4. **velocity-ssh-bridge** — adapts SSH payloads onto Velocity streams to provide accelerated and PQ-safe remote shells.
5. **Velocity CA** — optional Certificate Authority sample implementing hybrid issuance flows.

## 4. Packet Vocabulary

Velocity packets follow a QUIC-like framing model while incorporating PQ metadata and explicit downgrade detection bits.

### 4.1 Packet Header Layout

```
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|L|R|  Packet Type | Connection ID Length |   Version (32)   ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

* **L** — long-header flag. Set for handshake packets (Initial, ServerInitial, Handshake, Retry).
* **R** — reserved bit, MUST be zero when sent, ignored on receipt.
* **Packet Type** — 6-bit enumeration (see Table 1).
* **Connection ID Length** — 8-bit unsigned integer (0–20 bytes).
* **Version** — 32-bit identifier. Velocity/1 uses `0x56553100`.

Following the common header, long-header packets carry the Destination Connection ID, Source Connection ID, Packet Number Length, and Packet Number fields. Short-header packets (Application, ACK_ONLY, PATH_* frames) omit the Source Connection ID and encode the packet number using the same truncated form as QUIC.

#### Table 1 — Packet Types

| Value | Name             | Description |
|-------|------------------|-------------|
| 0x00  | `INITIAL`        | Client’s opening flight (ClientHello, parameters, PQ shares).
| 0x01  | `SERVER_INITIAL` | Server’s response (certificate chain, PQ response, parameters).
| 0x02  | `HANDSHAKE`      | Finished messages and handshake completion.
| 0x03  | `RETRY`          | Stateless retry token when address validation fails.
| 0x04  | `APPLICATION`    | Protected short-header application packets.
| 0x05  | `ACK_ONLY`       | Acknowledgement-only packet with ACK frames.
| 0x06  | `PATH_CHALLENGE` | Probes for connection migration.
| 0x07  | `PATH_RESPONSE`  | Response to path challenge.

### 4.2 Frames

Velocity defines the following core frames:

* `STREAM` — carries bidirectional or unidirectional stream data with offset and fin semantics.
* `ACK` — acknowledges packet receipt ranges. Implements delay reporting for adaptive RTT.
* `CRYPTO` — transports handshake transcripts.
* `SETTINGS` — negotiates parameters including AEAD suites, padding policy, telemetry opt-in, DATAGRAM size.
* `NEW_SESSION_TICKET` — issues PQ-hybrid tickets.
* `CONNECTION_CLOSE` — terminates the connection with an error code and reason.

Extensions registered in `docs/extension-registry.md` MAY introduce additional frames. Unknown frame types with the high bit clear MUST be ignored.

## 5. Cryptographic Components

Velocity’s PQ profile is deliberately opinionated to simplify interop and auditing:

* **Key Exchange** — Hybrid secret `HKDF-Extract(0, x25519 || kyber)` using X25519 and Kyber (512/768/1024 depending on profile).
* **Authentication** — Hybrid certificate chain containing both classical signatures (ECDSA P-256 or Ed25519) and PQ signatures (Dilithium 2 or 3).
* **AEAD** — ChaCha20-Poly1305 by default. AES-128-GCM is negotiated when both peers advertise `preferred_aead = aes_128_gcm`.
* **Hashing** — SHA-512 transcript hash (Velocity/1 baseline). Implementations MAY expose SHA-256 only for transitional compatibility with light-profile clients.
* **Randomness** — Implementations MUST use a CSPRNG seeded with ≥256 bits of entropy. PQ components SHOULD reseed prior to each Kyber key generation.

## 6. Handshake Flow

The handshake completes in one round-trip under normal conditions. A textual flow diagram is provided in Figure 1.

```
Client                                            Server
------                                            ------
Initial (ClientHello, Params, PQ Public)   ->
                                            <-   ServerInitial (HybridCert, PQ Ciphertext, Settings)
Handshake (ClientFinished, Ticket Request) ->
Protected Application Data                 <->   Protected Application Data
```

### 6.1 Client Initial

ClientHello contains:

1. Protocol version and ALPN list ordered by preference.
2. Client parameters: supported security profiles, max UDP payload size, telemetry opt-in hint, acceptable AEADs, padding policy.
3. Optional Encrypted Client Hello (ECH) payload referencing DNS-advertised configs.
4. Optional resumption ticket.
5. Ephemeral X25519 public key and Kyber public key.

Clients MUST pad the first Initial packet to at least 1200 bytes. They MAY include HTTP request metadata in `STREAM` frames encrypted with derived 0-RTT secrets if a ticket is presented.

### 6.2 Server Initial

The server validates anti-replay tokens, selects a profile, and emits `SERVER_INITIAL` containing:

1. The selected profile (`light`, `balanced`, `secure`).
2. Transport parameters (see Section 11).
3. Hybrid certificate chain transported via CERT frames.
4. Server X25519 public key and Kyber ciphertext that encapsulates the server share.
5. EncryptedExtensions covering ECH acceptance, telemetry policy, HTTP origin metadata.
6. `ServerFinished` HMAC over the transcript.

Servers MAY precede this with `RETRY`. Clients MUST echo the token once.

### 6.3 Client Handshake

The client validates both classical and PQ signatures, verifies transport parameters, derives handshake secrets, and emits `HANDSHAKE` with:

* `ClientFinished` HMAC.
* `NewSessionTicketRequest` indicating desired early data allowance.

After sending `ClientFinished`, the client may transmit encrypted application data. The first `APPLICATION` packet MUST set the ACK delay exponent to match negotiated values.

### 6.4 Migration and Address Validation

Velocity retains QUIC-style connection migration. Servers emit `PATH_CHALLENGE` frames when a new path is detected. Clients answer with `PATH_RESPONSE` and MUST validate server challenges before marking the path active.

### 6.5 Downgrade Guards

Both peers compute a `profile_commitment = HKDF-Expand(handshake_secret, "velocity profile", 8)` and stash it in session tickets. Upon resumption, the lower of the stored and newly negotiated profile is logged; if lower than policy minimum, the connection is aborted.

## 7. Key Schedule

Let `ss_classical` be the X25519 shared secret and `ss_pq` the Kyber shared secret. Velocity derives keys as:

```
shared_secret   = HKDF-Extract(0, ss_classical || ss_pq)
early_secret    = HKDF-Extract(0, resumption_psk || 0)
handshake_secret = HKDF-Extract(shared_secret, transcript_hash(CH || SH))
master_secret    = HKDF-Extract(handshake_secret, transcript_hash(CH || SH || CF))
```

Where `CH`, `SH`, and `CF` denote ClientHello, ServerInitial, and ClientFinished transcripts respectively. Traffic secrets follow QUIC-style labels:

```
client_hs_key = HKDF-Expand(handshake_secret, "velocity hs client", key_len)
server_hs_key = HKDF-Expand(handshake_secret, "velocity hs server", key_len)
client_app_key = HKDF-Expand(master_secret, "velocity app client", key_len)
server_app_key = HKDF-Expand(master_secret, "velocity app server", key_len)
```

Nonces derive from packet numbers using XOR with IVs. Implementations MUST NOT reuse nonces.

## 8. Hybrid Certificates and Authentication

Hybrid certificates embed Velocity metadata as a CBOR map inside extension OID `1.3.6.1.4.1.56565.1.1` with keys:

* `pq_sig_alg` — `dilithium2` or `dilithium3`.
* `pq_signature` — raw Dilithium signature bytes.
* `profile` — negotiated profile hint.
* `policy` — optional bitfield (requires ECH, disallow 0-RTT, etc.).

Clients MUST validate both signature suites. If PQ validation fails, the connection aborts with `CERT_PQ_VALIDATION_FAILED`.

## 9. ALPN Negotiation and Fallback

ALPN selection follows TLS conventions. Example client offer: `velocity/1`, `h3`, `http/1.1`. The server selects `velocity/1` when supported; otherwise it selects a fallback and replies using QUIC+TLS. Velocity clients MUST support fallback to HTTP/3 to maintain compatibility with legacy infrastructure.

Servers MUST attach a downgrade reason to telemetry streams. Reasons include `no_hybrid_cert`, `policy_disabled`, `client_profile_unsupported`, `maintenance_window`.

## 10. Session Resumption and 0-RTT

Servers issue **Velocity Tickets** containing:

* Ticket ID (96 bits).
* Profile scope.
* Max early data bytes.
* Expiration timestamp.
* Client CID hint.
* ALPN scope.

Tickets are AEAD-sealed using HKDF-derived keys rotated every 12 hours. Clients presenting 0-RTT data MUST mark HTTP requests as idempotent (GET, HEAD, OPTIONS). Servers enforce replay windows with salted Bloom filters.

A **Fallback Ticket** is optionally issued to support TLS 1.3 resumption when downgraded. It encodes the Velocity profile commitment to detect downgrade-aware fallbacks.

## 11. Transport Parameters

| Parameter Name            | Encoding | Description |
|---------------------------|----------|-------------|
| `preferred_aead`          | varint   | `0` = ChaCha20-Poly1305, `1` = AES-128-GCM. |
| `preferred_profile`       | varint   | `0` = light (Kyber512), `1` = balanced (Kyber768), `2` = secure (Kyber1024). |
| `padding_policy`          | varint   | `0` = none, `1` = fixed (pad to 1400), `2` = cover (use policy budget). |
| `telemetry_opt_in`        | bool     | Telemetry stream permission. |
| `max_datagram_frame_size` | varint   | Maximum DATAGRAM size. |
| `cc_hint`                 | varint   | Congestion hint: `0`=BBRv2, `1`=CUBIC, `2`=Reno. |
| `ech_accept`              | bool     | Indicates ECH was accepted. |
| `extension_registry_id`   | varint   | Negotiated extension bundle index. |

## 12. Versioning and Extension Policy

* Wire changes require a new ALPN token and version constant.
* Frame extensibility follows QUIC rules. Unknown frames with the high bit clear are ignored.
* Cryptographic agility is limited: new PQ primitives or signature suites require Velocity/2.
* Extension identifiers are published in `docs/extension-registry.md`.

## 13. Operational Guidance

Operators SHOULD:

1. Expose UDP/443 and ensure load balancers respect Destination Connection IDs.
2. Provision hybrid certificates with overlapping validity windows.
3. Deploy Encrypted Client Hello (ECH) via HTTPS DNS records.
4. Rotate ticket encryption keys every ≤24 hours.
5. Monitor downgrade ratios, PQ validation failures, and RTT percentiles.

## 14. Security Considerations

* Retry tokens defend against source spoofing. Implement proof-of-work for high-risk deployments.
* Profile commitments detect downgrade attempts.
* PQ signatures prevent long-term compromise even if classical algorithms fail.
* Padding policies mitigate traffic analysis; cover traffic incurs bandwidth overhead documented in `docs/performance.md`.

## 15. Privacy Considerations

Telemetry frames omit IP addresses, substituting salted hashes. Session tickets avoid embedding user identifiers and expire within 24 hours by default.

## 16. IANA Considerations

Velocity requests provisional ALPN `velocity/1` and OID `1.3.6.1.4.1.56565.1.1` for hybrid certificate metadata.

## 17. References

* [RFC 2119] Key words for use in RFCs to Indicate Requirement Levels.
* [RFC 8446] The Transport Layer Security (TLS) Protocol Version 1.3.
* [RFC 9000] QUIC: A UDP-Based Multiplexed and Secure Transport.
* [RFC 9001] Using TLS to Secure QUIC.
* [RFC 9114] HTTP/3.
* NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard.
* NIST FIPS 204 — Module-Lattice-Based Digital Signature Standard.

## Appendix A — Error Code Registry

| Code Name                        | Value | Description |
|----------------------------------|-------|-------------|
| `ALPN_REQUIRED`                  | 0x01  | Peer requires Velocity but it was not offered. |
| `CERT_PQ_VALIDATION_FAILED`      | 0x02  | PQ signature validation failed. |
| `PROFILE_POLICY_VIOLATION`       | 0x03  | Negotiated profile below policy minimum. |
| `ECH_REQUIRED`                   | 0x04  | Server requires ECH. |
| `EARLY_DATA_REJECTED`            | 0x05  | 0-RTT rejected due to replay or policy. |
| `TELEMETRY_POLICY_MISMATCH`      | 0x06  | Telemetry opt-in mismatch between peers. |

## Appendix B — Reference Transcript

See `spec/handshake-bytes.md` for a byte-accurate transcript generated by the integration harness. Implementers SHOULD confirm new stacks reproduce the transcript up to expected randomness before interoperability testing.

## 2. Terminology

- **Client / Server**: endpoints initiating or accepting a Velocity connection.
- **ALPN**: Application-Layer Protocol Negotiation value exchanged during the TLS-compatible handshake. Velocity registers `velocity/1` and advertises HTTP/3 (`h3`) as the primary fallback.
- **Profile**: configuration tuple (light, balanced, secure) that specifies ML-KEM parameter set, ML-DSA variant, AEAD preference, and padding strategy.
- **CID**: Connection Identifier as in QUIC. Destination CID (DCID) and Source CID (SCID) lengths are explicit in the packet header.
- **ECH**: Encrypted Client Hello per draft-ietf-tls-esni, mandatory by default for Velocity.
- **Hybrid secret**: concatenation of classical and PQ key shares used as input key material for HKDF.
- **Ticket**: stateless resumption blob containing PQ-safe PSK data.
- **V-SSH**: Velocity transport adapter for SSH described in Section 9.

All mathematical expressions employ KaTeX syntax. Concatenation is denoted `\Vert`, byte strings by lowercase italics, and secrets by uppercase labels.

## 3. Protocol architecture

Velocity reuses QUIC’s UDP framing philosophy but replaces the TLS 1.3 handshake with a hybrid flow defined here. The architecture comprises:

1. **Transport core** (`velocity-core`): maintains UDP sockets, parses packet headers, exposes dispatcher traits, and powers congestion/migration logic. The core defines a compact reference frame layout (Section 5) to unblock benchmarking and fuzzing before full QUIC compatibility lands.
2. **Cryptographic state machine** (`velocity-crypto`): performs hybrid handshake flights, AEAD key derivation, and session ticket issuance atop the parsed packets.
3. **Application adapters** (`velocity-server`, `velocity-client`, `velocity-ssh-bridge`): integrate the transport into HTTP semantics and SSH forwarding.

The protocol operates on UDP port 443 by default. Servers may additionally expose an experimental port (e.g., 8443) for lab trials whilst production traffic uses 443 to maximise middlebox compatibility. Velocity’s long-term goal is a QUIC-compatible framing; the prototype permits experimental packets to accelerate development of the crypto and fallback logic.

### 3.1 Profiles

Velocity defines three operational profiles:

- **Light**: ML-KEM-512 + ML-DSA-44 + ChaCha20-Poly1305 + SHA-256 transcript hash. Optimised for mobile/edge devices with limited CPU.
- **Balanced** (default): ML-KEM-768 + ML-DSA-65 + ChaCha20-Poly1305 with opportunistic AES-GCM when AES-NI is available. Transcript hashed with SHA-384.
- **Secure**: ML-KEM-1024 + ML-DSA-87 + AES-256-GCM + SHA-512. Deployments use this in high-assurance environments where CPU cost is acceptable.

Profiles are negotiated during the handshake via a `velocity_profile` extension that lists the client’s supported tuples. Servers select the strongest mutually supported profile and reflect it back in EncryptedExtensions.

## 4. Handshake overview

The Velocity handshake is a one-RTT flow with a stateless retry option. Message flights mirror TLS 1.3 semantics but embed PQ artefacts directly in transport frames to ease implementation. The figure below summarises the progression.

| Flight | Direction | Contents | Notes |
|--------|-----------|----------|-------|
| 1 | Client → Server | Initial packet containing ClientHello, X25519 share, ML-KEM public key, optional PSK ticket, ECH outer layer | Client may attach optimistic application data flagged as idempotent; data is encrypted under PSK keys if offered. |
| 2 | Server → Client | ServerInitial with Retry token (optional), ServerHello, ML-KEM ciphertext, ML-DSA signature, profile confirmation, AEAD choice, session ticket seeds | Retry tokens require MACed proof-of-address, enabling anti-spoof and DoS throttling. |
| 3 | Client → Server | Handshake flight with Finished message and first 1-RTT frames | Client verifies hybrid certificate, derives keys, confirms handshake. |
| 4 | Server → Client | 1-RTT application data, NewSessionTicket frames, optional fallback ticket | Server confirms keys and enables resumption. |

### 4.1 Key schedule

Velocity derives symmetric keys by hashing classical and PQ secrets together. Let $s_{x}$ be the X25519 shared secret, and $s_{k}$ the ML-KEM shared secret produced by decapsulation. Define the hybrid input key material as:

$$
IKM_{hybrid} = s_{x} \Vert s_{k} \Vert transcript\_hash
$$

The transcript hash prefixes the deterministic HKDF inputs with the handshake context, hardening against transcript truncation. Keys follow the TLS 1.3 schedule with profile-dependent hash functions. For the balanced profile (SHA-384):

$$
PRK_{early} = HKDF\_Extract(0^{384}, IKM_{hybrid})
$$

From this, the handshake keys are derived:

$$
secret_{handshake} = HKDF\_Expand(PRK_{early}, "velocity hs", 48)
$$

Application traffic keys stem from `secret_{handshake}`:

$$
key_{client} = HKDF\_Expand(secret_{handshake}, "velocity ap client key", 32)
$$

$$
key_{server} = HKDF\_Expand(secret_{handshake}, "velocity ap server key", 32)
$$

Per-direction IVs (12 bytes) are derived similarly. Nonces are computed by XOR-ing a packet counter into the high-order 64 bits of the IV. Session ticket keys are derived from a separate secret labelled `"velocity ticket"`, ensuring replay state isolation.

### 4.2 Certificates and authentication

Velocity mandates hybrid certificates. Each certificate chain must contain both classical and PQ signatures at the leaf. For the balanced profile, the leaf certificate carries:

- Standard X.509 fields signed with ECDSA P-256.
- A custom extension `1.3.6.1.4.1.57355.1.1` containing a Dilithium3 signature over the TBSCertificate. The extension also advertises the Dilithium public key and signature algorithm identifier.

Clients verify both signatures. Failure of either signature aborts the handshake. OCSP stapling remains mandatory; Velocity additionally requires PQ-signed SCTs (Signed Certificate Timestamps) when CT logs support them. Client certificates follow the same hybrid pattern when mutual auth is enabled.

### 4.3 Stateless retry

Servers may respond to the initial handshake with a Retry packet. The token encodes:

```
struct RetryToken {
    u32 issued_at_unix;
    u128 anti_replay_nonce;
    u16 profile_hint;
    u8 client_ip_prefix[8]; // First 64 bits of the client's IP (IPv4 mapped)
    u8 mac[32];             // HMAC-SHA-256 over the previous fields
}
```

Tokens are encrypted with a server secret rotated hourly. Clients must echo the token verbatim; forged tokens fail MAC verification. Retry protects against amplification and reflection attacks without requiring server-side state.

## 5. Packet framing and parsing

Velocity employs a compact long-header format during experimentation. The `velocity-core` crate defines the canonical layout used in tests and early deployments. The header fields are:

| Field | Size | Description |
|-------|------|-------------|
| `packet_type` | 1 byte | Encodes `Initial`, `Handshake`, `OneRtt`, `Retry`. |
| `version` | 4 bytes | Big-endian protocol version (`0x564C4331` for draft builds). |
| `dcid_len` / `scid_len` | 1 byte each | Length of the Destination and Source Connection IDs. |
| `payload_len` | 2 bytes | Length of the encrypted payload. |
| `dcid` / `scid` | variable | Connection identifiers. |
| `payload` | variable | Frames and crypto material. |

Packets exceeding 1350 bytes are rejected to maintain generosity for path MTU discovery while keeping tests deterministic. The parser validates length fields before handing payloads to the handshake engine. Section 5 of this draft aligns with the shipped unit tests in `velocity-core` to guarantee consistent behaviour across crates.

### 5.1 Frame types

Payloads contain typed frames. Draft implementations understand:

- `STREAM_OPEN` (type 0x00): open a bidirectional stream with priority hints.
- `STREAM_DATA` (0x01): data with offset and FIN flag.
- `ACK` (0x02): acknowledgements for received packet numbers.
- `CRYPTO` (0x03): handshake fragments containing TLS-encoded structures.
- `PROFILE` (0x20): profile negotiation data.
- `TELEMETRY` (0x30): optional debugging transcript, disabled by default in production builds.

Later drafts will align these frame identifiers with QUIC’s existing registry to simplify interoperability efforts.

### 5.2 Error handling

Malformed packets trigger a `FRAME_ENCODING_ERROR`, logged with the failing CID for observability. The transport drops the packet and continues. Three consecutive malformed packets from the same peer escalate to connection closure with error code `0x77` (`VELOCITY_PROTOCOL_VIOLATION`).

## 6. ALPN negotiation and fallback

Negotiation happens within the TLS-compatible handshake. Clients construct an ordered ALPN preference list. Example client advertisement:

```
client_alpns = ["velocity/1", "h3", "http/1.1"]
profiles = ["balanced", "light"]
```

Servers respond with their supported ALPNs. The decision process obeys:

1. If both sides offer `velocity/1`, Velocity is selected.
2. Otherwise, pick the first protocol in the server’s list that also appears in the client list. The server MUST append a signed fallback payload (Section 6.2).
3. If no overlap exists, abort with `ALPN_MISMATCH`.

### 6.1 Negotiation transcript binding

ALPN choices and profile selections are included in the handshake transcript hash prior to the `Finished` MAC. Any attempt to tamper with the negotiated protocol invalidates the handshake.

### 6.2 Structured fallback record

When Velocity cannot proceed, the server returns a CBOR-encoded `FallbackRecord` in the EncryptedExtensions:

```
struct FallbackRecord {
    text selected_alpn;    // e.g., "h3"
    text authority_hint;   // host:port used for redelegation
    text reason;           // human-readable
    bool retry_velocity;   // whether client should retry later
    bytes signature;       // Dilithium signature over the record
}
```

Clients verify the signature using the same hybrid certificate chain before initiating the classical fallback. Signed fallbacks create an auditable paper trail and power downgrade detection tooling.

## 7. Session resumption and 0-RTT

Velocity supports stateless resumption via hybrid session tickets. Each ticket contains:

- `ticket_nonce` (96-bit random value)
- `ticket_secret` (seed for PSK derivation)
- `profile` and `alpn` hints
- `replay_window` (timestamp + window size)
- `client_ip_hash` (HMAC of client IP prefix for telemetry)

Tickets are encrypted and authenticated with `AEAD_AES_256_GCM` under a server secret rotated daily. Derivation is:

$$
PSK = HKDF\_Expand(HKDF\_Extract(0^{256}, ticket\_secret), "velocity resumption", 32)
$$

Clients presenting a ticket may send early data if the associated application layer authorises it. Servers maintain a replay filter (cuckoo filter or rotating bloom filter) keyed by `ticket_nonce`. Early data is only processed if the filter indicates no duplicate.

### 7.1 0-RTT transaction limits

Applications must flag idempotent requests; the Velocity server rejects early data lacking `Idempotent: true` metadata by issuing an `EARLY_DATA_REJECTED` frame. Clients then resubmit the request after the 1-RTT handshake completes.

### 7.2 Dual-ticket issuance

Every successful Velocity handshake emits two tickets:

1. A Velocity ticket containing the PQ PSK.
2. A fallback TLS 1.3 ticket enabling HTTP/3 resumption should Velocity be temporarily unavailable.

Tickets carry a telemetry bitfield reporting whether the previous session used Velocity or fallback, enabling progressive deployment analytics.

## 8. Privacy and metadata protection

Velocity treats metadata confidentiality as a first-class requirement.

1. **Encrypted Client Hello (ECH)**: default-on. Clients cache ECH configs distributed via DNS HTTPS records (`SVCB/HTTPS`). Servers reject outer ClientHellos lacking the ECH extension unless operating in compatibility mode (for bootstrapping).
2. **Padding**: Clients pad Initial packets to 1200 bytes. Subsequent packets employ adaptive padding that rounds payloads up to the nearest 16-byte block and adds a jitter component derived from `$HKDF\_Expand(secret_{handshake}, "velocity pad", 2)`.
3. **Cover traffic**: Servers optionally send dummy packets to meet policy targets (e.g., 5% cover bandwidth). Cover packets carry an empty frame set with a reserved packet type `0xF`, discarded silently by receivers.
4. **Connection migration**: The protocol inherits QUIC’s migration support. New path validation packets reuse the hybrid key schedule to avoid revealing the classical secret in isolation.

## 9. SSH transport mapping

Velocity’s adoption plan includes a transport shim for SSH named **V-SSH**. The goal is to keep SSH semantics untouched while replacing the underlying TCP transport.

### 9.1 Architecture

- `velocity-ssh-bridge` crate exposes a `connect_vsh` API that negotiates Velocity, opens a control stream, and exposes `AsyncRead + AsyncWrite` traits compatible with libssh/OpenSSH.
- `vshd` (Velocity Shell Daemon) integrates with existing `sshd` deployments via the `ProxyUseFd` mechanism or an agent socket. It validates Velocity session tickets, ensures handshake completion, and then forwards the byte stream into the SSH subsystem.
- `vsh-proxy` provides a drop-in `ProxyCommand` for clients: `ProxyCommand vsh-proxy %h %p`. The shim handles ticket caching, PSK resumption, and telemetry back to operators.

### 9.2 Key handling

Host keys remain classical (Ed25519, RSA) but are signed by the Velocity CA, which issues hybrid Velocity certificates binding the SSH host key fingerprint to a Dilithium signature. Known-Hosts entries are extended with a Velocity hash annotated as `@velocity` alongside the classical fingerprint. Clients refuse connections if the Velocity hash is missing after a configurable grace period.

### 9.3 Channel mapping

Each SSH channel maps to a dedicated Velocity stream. Multiplexing permits concurrent SCP, shell, and port-forwarding flows with QUIC-like priorities. Agent forwarding requests create additional streams flagged as sensitive; the transport enforces shorter idle timeouts and disables 0-RTT for those streams to avoid replay exposures.

### 9.4 Migration path

Deployment proceeds in three phases:

1. **Parallel pilot**: Operators enable Velocity on alternate ports (e.g., 4422/UDP). `vsh-proxy` attempts Velocity first, falling back to TCP if negotiation fails.
2. **Default-on**: After telemetry shows stable success rates, operators switch default SSH endpoints to Velocity while leaving TCP accessible via explicit opt-out flags.
3. **Velocity-required**: Policies enforce Velocity-only connections. Clients lacking Velocity support must upgrade or use bastion hosts that translate.

## 10. Security considerations

Velocity’s security posture hinges on careful handling of hybrid cryptography and telemetry:

- **Forward secrecy**: Fresh X25519 and ML-KEM key pairs are generated per connection. Servers precompute ML-KEM encapsulations to meet latency targets while ensuring reuse never occurs.
- **Post-quantum resilience**: Even if classical secrets are compromised, ML-KEM decapsulation protects confidentiality. The hybrid derivation ensures that breaking either side alone does not reveal `IKM_{hybrid}`.
- **Downgrade prevention**: Fallback records are Dilithium-signed. Operators monitor logs for fallback spikes; clients remember downgrade reasons and enforce cooldowns before retrying `velocity/1`.
- **Replay safety**: Tickets embed timestamp windows; servers reject tickets older than the configured limit (default 12 hours) or belonging to unexpected IP prefixes. Bloom filter false positives are capped at $2^{-18}$ by tuning capacity and depth.
- **Telemetry privacy**: Optional telemetry is opt-in, anonymised via k-anonymity buckets, and never includes raw IP addresses.
- **Side-channel defence**: Implementations avoid branch- or memory-based side channels in ML-KEM/ML-DSA operations and provide constant-time tag comparisons (see `pqq-tls` precedent, now mirrored in `velocity-crypto`).

## 11. Implementation notes for v0.1

The v0.1 milestone aims to deliver basic interoperability between reference client and server stacks. The following checkpoints guide implementation:

1. **Transport core**: `velocity-core` provides packet parsing, ALPN negotiation helpers, and the UDP receive loop used by the server. Unit tests cover successful parses, malformed length handling, and ALPN decisions.
2. **Handshake state machine**: `velocity-crypto` will consume `VelocityPacket` values and implement the hybrid HKDF schedule described earlier. Initial versions may tunnel TLS structures inside the `CRYPTO` frame for easier reuse of rustls components.
3. **Fallback harness**: Integration tests stand up a Velocity server and a fallback HTTP/3 endpoint. Clients exercise both paths, verifying that fallback records are signed and recorded.
4. **Benchmark harness**: `benchmarks/handshake-bench` measures parser throughput (ns/packet), handshake CPU time, and network RTT impact using `criterion` and `linux-perf` counters. Scripts run under WSL2 and Linux edge hosts.
5. **SSH pilots**: `velocity-ssh-bridge` exposes stub APIs. Early tests run OpenSSH regression suites through the Velocity transport to surface corner cases in channel multiplexing.

## 12. Future work and open questions

- **QUIC alignment**: Map Velocity frame identifiers and transport parameters onto existing QUIC registries to simplify future standardisation. Evaluate whether a new QUIC version (`0x56564345`) or GREASE strategy best suits deployment.
- **Browser integration**: Prototype Velocity support in Chromium via a network service experiment, focusing on handshake telemetry and fallback UX. Determine how to expose Velocity adoption metrics in DevTools.
- **Kernel bypass**: Explore AF_XDP/DPDK integration for high-throughput deployments. Define capability signalling during handshake so clients can adapt expectations.
- **Formal verification**: Model the hybrid handshake in Tamarin; verify mutual authentication and forward secrecy properties. Publish models in `/formal`.
- **CA operations**: Finalise ACME extensions and CT log integration for hybrid certificates. Produce compliance guidance for enterprise PKI teams.
- **Telemetry governance**: Formalise the opt-in policy, anonymisation protocol, and data retention schedule in `/docs/governance.md`.