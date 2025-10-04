# Integration Guide

This guide helps existing stacks embed VELO via Rust APIs or the native bindings.

## Rust server integration

```rust
use pqq_server::{Server, ServerConfig, Response};
use pqq_server::Request;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let server = Server::bind(
        "0.0.0.0:443",
        ServerConfig::from_cert_chain("certs/hybrid.pem", "certs/hybrid.key")
            .with_alpn(["pqq/1"])
            .with_fallback("h3", "legacy.example", 443),
    )
    .await?;

    server
        .serve(|request: Request| async move {
            if let Some(line) = request.http_request_line() {
                if line.target == "/ping" {
                    return Response::text("pong");
                }
            }
            Response::text("fallback")
        })
        .await?;

    Ok(())
}
```

## Rust client integration

```rust
use pqq_client::{Client, ClientConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = Client::new(
        ClientConfig::default()
            .with_server(("example.com", 443).into())
            .with_alpns(["pqq/1", "h3"]),
    );

    match client.connect_or_fallback().await? {
        pqq_client::HandshakeOutcome::Established(session) => {
            let response = session
                .send_request_string(b"GET /ping HTTP/1.1\r\nHost: example.com\r\n\r\n")
                .await?;
            println!("response: {}", response);
        }
        pqq_client::HandshakeOutcome::Fallback(res) => {
            println!("Downgrade to {} suggested", res.fallback.unwrap().alpn);
        }
        pqq_client::HandshakeOutcome::Unsupported(_) => {
            println!("Server lacks compatible ALPNs");
        }
    }

    Ok(())
}
```

## C bindings (experimental)

The native bindings now expose "easy" helpers that wrap the async Rust stack with
simple JSON configuration blocks.

```c
#include "pqq.h"

static const char *SERVER_CFG = "{\
  \"bind\":\"127.0.0.1:0\",\
  \"profile\":\"balanced\",\
  \"static_text\":\"Hello Velocity!\"\
}";

static const char *CLIENT_CFG_TEMPLATE = "{\
  \"server_addr\":\"127.0.0.1:%u\",\
  \"hostname\":\"localhost\",\
  \"server_key_base64\":\"%s\",\
  \"path\":\"/\"\
}";

int main(void) {
    pqq_init();

    PqqOwnedSlice server_resp = {0};
    if (pqq_easy_start_server(SERVER_CFG, &server_resp) != 0) {
        fprintf(stderr, "failed to launch easy server\n");
        return 1;
    }

    // parse JSON with your favourite library; here we rely on sscanf for brevity
    unsigned port = 0;
    char kem_b64[512] = {0};
    sscanf((const char *)server_resp.data,
           "{\"port\":%u,%*[^\"]\"kem_public_base64\":\"%511[^\"]",
           &port,
           kem_b64);
    pqq_owned_slice_release(&server_resp);

    char client_cfg[1024];
    snprintf(client_cfg, sizeof(client_cfg), CLIENT_CFG_TEMPLATE, port, kem_b64);

    PqqOwnedSlice client_resp = {0};
    if (pqq_easy_request(client_cfg, &client_resp) != 0) {
        fprintf(stderr, "request failed\n");
        return 1;
    }

    printf("response: %s\n", (const char *)client_resp.data);
    pqq_owned_slice_release(&client_resp);

    pqq_stop_server((uint16_t)port);
    return 0;
}
```

Both helpers return JSON envelopes. Always release `PqqOwnedSlice` buffers with
`pqq_owned_slice_release` once you have copied/parsed their contents. The legacy
`pqq_start_server`/`pqq_request` pair remains available for lower-level control.

### Python shim

`native-bindings/shims/python/pqq_easy.py` wraps the C API with `ctypes`. It
exposes `EasyServer`/`EasyClient` classes that accept dictionaries and return
Python dicts.

See the README in that directory for a concrete REPL snippet that spins up the
server and client pair.

### Node.js shim

`native-bindings/shims/node` packages the same helpers via `ffi-napi`. Install
dependencies with `npm install` inside the shim directory, then run the inline
demo in `README.md` to verify the easy round-trip from JavaScript.

## Testing integrations

- Run unit tests (`cargo test --workspace`) after linking to ensure handshake behaviour remains intact.
- Use the Criterion harness (`cargo bench -p handshake-bench`) to compare latency before/after integration.
- Extend `examples/` with scenario-specific demos to simplify regression testing.

## Observability hooks

- The server uses `tracing`; integrate with `tracing-subscriber` or forward to OpenTelemetry as needed.
- Structured handshake responses include fallback metadata; log them to detect downgrade trends.

Questions? Reach out via Discussions or open an integration issue tagged `integration`.
