use criterion::{black_box, criterion_group, criterion_main, Criterion};
use velocity_core::parse_packet;

fn build_datagram(payload: &[u8]) -> Vec<u8> {
    let mut datagram = Vec::new();
    datagram.push(0x0u8); // Initial packet type
    datagram.extend_from_slice(&1u32.to_be_bytes()); // version
    datagram.push(8); // dcid len
    datagram.push(8); // scid len
    datagram.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    datagram.extend_from_slice(&[0u8; 8]); // dcid
    datagram.extend_from_slice(&[1u8; 8]); // scid
    datagram.extend_from_slice(payload);
    datagram
}

fn bench_parse_packet(c: &mut Criterion) {
    let payload = b"ALPN\0velocity/1";
    let datagram = build_datagram(payload);

    c.bench_function("parse_packet", |b| {
        b.iter(|| {
            let parsed = parse_packet(black_box(&datagram)).expect("parse");
            black_box(parsed.payload());
        })
    });
}

criterion_group!(benches, bench_parse_packet);
criterion_main!(benches);
