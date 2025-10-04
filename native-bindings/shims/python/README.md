# Python shim for pqq-native easy API

This directory contains a lightweight `ctypes` wrapper that turns the
JSON-configurable C ABI into ergonomic Python helpers.

## Quick start

```bash
# Ensure the Rust library is built
cargo build -p pqq-native --release

# Use the shim from a Python REPL
python - <<'PY'
from pqq_easy import EasyServer, EasyClient

server = EasyServer({
    "bind": "127.0.0.1:0",
    "profile": "balanced",
    "static_text": "Hello Velocity!",
})

client = EasyClient({
    "server_addr": server.address,
    "hostname": "localhost",
    "server_key_base64": server.kem_public_base64,
})

print(client.get("/"))
server.close()
PY
```

The shim auto-loads `pqq_native` from `target/release/`. Override the path by
calling `load_library(<path>)` before constructing the helpers.

## API surface

- `load_library(path: Optional[str]) -> ctypes.CDLL`
- `easy_start_server(lib, config_dict) -> dict`
- `easy_request(lib, config_dict) -> dict`
- `EasyServer` / `EasyClient` convenience classes

Returned dictionaries mirror the JSON payloads produced by the Rust layer.
Remember to call `EasyServer.close()` (or `pqq_stop_server`) to free resources.
