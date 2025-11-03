udp-mitm — simple UDP MITM proxy for testing AEAD/transport tampering

Usage examples:

# forward localhost:7000 -> localhost:7001 without tampering
cargo run -p udp-mitm -- --listen 127.0.0.1:7000 --server 127.0.0.1:7001

# forward and tamper byte 10 by XORing with 0xff
cargo run -p udp-mitm -- --listen 127.0.0.1:7000 --server 127.0.0.1:7001 --tamper-offset 10 --tamper-xor 255

Notes:
- Start your server bound to the server address (7001 in examples) and configure the client to talk to the proxy listen address (7000).
- The proxy learns the client address from the first packet it receives that is not from the server address.
