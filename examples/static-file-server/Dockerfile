# Multi-stage build for the Velocity static file server example
FROM rust:1.82 AS builder
WORKDIR /app

# Cache dependencies
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY examples ./examples
COPY native-bindings ./native-bindings
COPY benchmarks ./benchmarks
RUN cargo fetch

# Build release binary for the static file server
RUN cargo build --release -p static-file-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/velocity

# Copy the binary and static assets from the builder image
COPY --from=builder /app/target/release/static-file-server /usr/local/bin/static-file-server
COPY --from=builder /app/examples/static-file-server/static ./static

ENV VELOCITY_BIND_ADDR=0.0.0.0:4443 \
    VELOCITY_STATIC_ROOT=/opt/velocity/static \
    VELOCITY_DISABLE_EMBEDDED_CLIENT=1

EXPOSE 4443/udp

CMD ["static-file-server"]
