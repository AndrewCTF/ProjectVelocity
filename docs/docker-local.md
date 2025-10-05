# Velocity Docker Sandbox

This guide walks through running the Velocity reference server inside Docker so you can
exercise the post-quantum transport locally (no domain required) while keeping an HTTPS
fallback online for legacy clients and browser checks.

## Prerequisites

- Docker Engine 24+ (or Docker Desktop on macOS/Windows)
- `docker compose` plugin (standard on recent installs)
- Rust toolchain if you want to run the local `velocity-fetch` example

## Build and launch

From the repository root:

```powershell
cd docker
docker compose build
```

The multi-stage build compiles the `velocity` CLI with `cargo` and bakes a minimal container
image containing:

- Velocity UDP listener on `0.0.0.0:4433`
- HTTPS preview listener on `0.0.0.0:8443`
- Self-signed cert for `localhost`
- ML-KEM public key publication enabled
- Simple static site under `/srv/site`

Start the stack:

```powershell
docker compose up
```

The container maps the following host ports:

- UDP `4433` → Velocity transport
- TCP `8443` → HTTPS fallback/preview

## Verify the Velocity handshake

Open a new terminal (outside Docker) and run the PQ client example. The demo ships with a
`ping.txt` helper so the response stays under the current frame size limit while we finish
chunked responses:

```powershell
cargo run -p pqq-client --example velocity-fetch -- `
  127.0.0.1:4433 `
  https://localhost:8443/ping.txt `
  --alpn velocity/1
```

Expected output:

```
Velocity probe: Supported("velocity/1")
Velocity request succeeded
-----------------------
HTTP/1.1 200 OK
...
pong
```

If the probe reports a fallback, confirm the container is running and the UDP port is
available (Windows and macOS sometimes need firewall consent for UDP).

## Preview listener caveat

The "HTTPS preview" listener currently reuses the hybrid PQ handshake over TCP so it is not
yet compatible with stock TLS clients (`curl`, browsers, etc.). Treat it as a developer
probe and continue using `velocity-fetch` against `https://localhost:8443/...` until the
classical TLS downgrade path is wired in. The port remains exposed so you can observe the
handshake flow and collect logs.

## Customizing content

Mount your own site by pointing the compose volume to another path:

```yaml
    volumes:
      - ../my-site:/srv/site:ro
```

The entrypoint regenerates the folder if it does not exist. Change ports or fallback target
via environment variables in `docker/docker-compose.yml`.

## Tear down

```powershell
docker compose down
```

This stops and removes the container but leaves the built image in your local cache so
subsequent `up` calls start quickly.
