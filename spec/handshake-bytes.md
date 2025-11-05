# Fast-Hybrid Handshake Byte Layout

This note freezes the byte-level format for the **Fast-Hybrid 1-RTT** and **0-RTT resume** handshakes used by the upgrade kit. Field sizes are fixed unless marked as `varint`. Integers are encoded in network byte order. Variable-length vectors use the QUIC-style `varint-len || value` encoding.

Assumptions:
- Classical share: X25519 (32 bytes).
- PQ share: Kyber512 (public key 800 bytes, ciphertext 768 bytes).
- All MACs and transcript hashes use SHA-384 outputs (48 bytes).

## 1. ClientHello (Fast-Hybrid 1-RTT)

| Offset | Field | Size | Encoding | Notes |
| ------:| ----- | ---- | -------- | ----- |
| 0 | `magic` | 4 | ASCII `"VH1\0"` | Identifies the Fast-Hybrid v1 message. |
| 4 | `version` | 2 | uint16 | Draft version (e.g., `0x0001`). |
| 6 | `flags` | 1 | bitfield | Bit0: early-data-present, Bit1: resumption-present, Bit2: retry-cookie-present. Remaining bits reserved (set 0). |
| 7 | `cipher_suite` | 2 | uint16 | Mirrors TLS cipher IDs; default `0x1303` (ChaCha20-Poly1305+SHA384). |
| 9 | `kem_suite` | 2 | uint16 | `0x0200` for Kyber512 hybrid profile. |
| 11 | `client_random` | 32 | opaque | Entropy for transcript binding. |
| 43 | `client_nonce` | 32 | opaque | Anti-replay nonce for tickets. |
| 75 | `x25519_public` | 32 | opaque | Raw Montgomery u-coordinate. |
| 107 | `kyber_public` | 800 | opaque | Kyber512 public key. |
| 907 | `auth_hint_len` | varint | length of `auth_hint`. | Required = proof-of-possession token. |
| ... | `auth_hint` | variable | opaque | HKDF label tying bootstrapped key material (e.g., DNS-signed hash). |
| ... | `retry_cookie_len` | varint (present if flag Bit2=1) | length | Retry token supplied by server. |
| ... | `retry_cookie` | variable | opaque | Server-provided address validation token. |
| ... | `psk_identity_len` | varint (present if Bit1=1) | length | Resume ticket identity. |
| ... | `psk_identity` | variable | opaque | Ticket contents (<= 256 bytes). |
| ... | `binder_len` | varint (present if Bit1=1) | length | HMAC over transcript using ticket secret. |
| ... | `binder` | variable | opaque | 32-byte HMAC-SHA384 output. |
| ... | `early_data_len` | varint (present if Bit0=1) | length | Early payload. |
| ... | `early_data` | variable | opaque | Encrypted HTTP request fragment or padded placeholder. |

### Minimal ClientHello Example

The following hex blob shows a ClientHello without early data or resumption. Values: version `0x0001`, cipher `0x1303`, KEM `0x0200`, empty auth hint.

```
56483100 0001 00 1303 0200
c24b8a4fb2d9a92ef64a34d9b8f9c761a2d38fb5a9b4510ff58c5abc4a4bbf11
0f5c4a37f5faf6224d5cc7c824fe9a793cb1d8d7a64012c2332a15e87422d6d1
3d2f73d4c8e01839c1cbe132c4d929c12da3c85b46776ca3de8d251e1b95e6f8
<800 bytes kyber pk...>
00
```

The trailing `00` is a single-byte varint zero indicating `auth_hint_len = 0`.

## 2. ServerFlight (Fast-Hybrid 1-RTT)

| Offset | Field | Size | Encoding | Notes |
| ------:| ----- | ---- | -------- | ----- |
| 0 | `magic` | 4 | ASCII `"VH1\1"` | Server flight marker. |
| 4 | `version` | 2 | uint16 | Echoed protocol version. |
| 6 | `flags` | 1 | bitfield | Bit0: resumption_accepted, Bit1: retry-issued, Bit2: ticket-present. |
| 7 | `selected_cipher` | 2 | uint16 | Mirrors client field. |
| 9 | `selected_kem` | 2 | uint16 | Mirrors client field. |
| 11 | `x25519_public` | 32 | opaque | Server ephemeral share. |
| 43 | `kyber_ciphertext` | 768 | opaque | Kyber512 encapsulation to client key. |
| 811 | `fs_mac` | 48 | opaque | HMAC-SHA384 over transcript using derived finished key. |
| 859 | `ticket_len` | varint (present if Bit2=1) | length | Size of encrypted ticket blob. |
| ... | `ticket` | variable | opaque | ≤ 256 bytes. |
| ... | `retry_token_len` | varint (present if Bit1=1) | length | Size of retry cookie to echo on next attempt. |
| ... | `retry_token` | variable | opaque | Token minted for address validation. |
| ... | `max_early_data` | 2 | uint16 | Optional limit (bytes); omitted if zero. |

### Minimal ServerFlight Example

This example accepts the proposed cipher, issues no ticket, and sets `max_early_data=16384`.

```
56483101 0001 01 1303 0200
9e4bc27cf61ad3a0f4c2bfe21aef0e2b9d3a8b9a71b23bffbaf5bb4170d558c1
<768 bytes kyber ct...>
5d3f2f8026f610d5ab52a84f0d7a4590285139a62962bd11a1e99f757ef0bed05de6eb8d1adf40f94b4d4eb2fcd648a9
4000
```

Here `4000` encodes `max_early_data = 0x4000 = 16384` as a two-byte field appended because the value is non-zero while `ticket_len` and `retry_token_len` are zero-length varints.

## 3. Resume ClientHello (0-RTT)

The resume format reuses the base ClientHello with the following requirements:
- `flags` Bit1 **must** be set.
- `psk_identity` carries a 224-byte encrypted ticket (varint length `0xfd 0xe0`).
- `binder` is always 48 bytes (HMAC-SHA384) and MUST immediately follow the ticket vector.
- `early_data` SHOULD be present and encrypted with PSK-generated AEAD keys.

An example snippet for the resume section:

```
fd e0                                       # varint = 224-byte ticket
<224 bytes ticket>
30                                           # binder length = 48
<48 bytes HMAC>
28                                           # early data length = 40
<40 bytes ciphertext>
```

## 4. Transcript Hashing

For MAC computation, the transcript is the concatenation of the raw byte encodings above (no framing changes). The Finished MAC is `HMAC-SHA384(finished_key, transcript_hash)`, where `transcript_hash = SHA384(ClientHello || ServerFlight)`.

## 5. Size Summary

| Message | Bytes (min) | Bytes (max typical) |
| ------- | ----------- | ------------------- |
| ClientHello fresh | 75 + 32 + 32 + 800 + 1 ≈ **940 bytes** | + ticket + early data ≤ 1400 bytes (fits single UDP datagram). |
| ServerFlight | 43 + 768 + 48 + 2 ≈ **861 bytes** | + ticket + retry ≤ 1200 bytes. |
| Combined cold handshake | **≤ 1,801 bytes** | Budget leaves headroom for UDP/IP overhead while staying < 4 KB on wire. |

The layout meets the target budgets: total payload < 2 KB for the fast path and resumed flows add ≤ 300 bytes (ticket + binder + finished MAC reuse).
