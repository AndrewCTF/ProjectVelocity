FROM rust:1.82-slim as builder

WORKDIR /app
COPY . /app

# Build minimal velocity-cli binary and the pqq-client example used for in-container testing
RUN apt-get update && apt-get install -y pkg-config libssl-dev build-essential ca-certificates && \
    cargo build --release -p velocity-cli && \
    cargo build --release -p pqq-client --example velocity-fetch || true

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/velocity /usr/local/bin/velocity
# Copy the in-repo client example so we can run the velocity-fetch probe from inside the container
COPY --from=builder /app/target/release/examples/velocity-fetch /usr/local/bin/velocity-fetch
COPY deployment/docker/serve.simple.yaml /etc/velocity/serve.simple.yaml
COPY public /srv/www
WORKDIR /srv/www

EXPOSE 4433/udp 8443/tcp 9300

CMD ["/usr/local/bin/velocity", "serve", "--config", "/etc/velocity/serve.simple.yaml"]
