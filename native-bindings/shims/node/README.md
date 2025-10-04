# Node.js shim for pqq-native easy API

This package wraps the Velocity easy C API using `ffi-napi`, providing a
minimal JavaScript interface for experiments and scripting.

## Usage

```bash
# Install dependencies
npm install

# Build the Rust library
cargo build -p pqq-native --release

# Run a quick demo
node - <<'JS'
const { EasyServer, EasyClient } = require('./index');

const server = new EasyServer({
  bind: '127.0.0.1:0',
  profile: 'balanced',
  static_text: 'Hello Velocity!'
});

const client = new EasyClient({
  server_addr: server.address,
  hostname: 'localhost',
  server_key_base64: server.kem_public_base64
});

client.get('/')
  .then(res => {
    console.log(res);
    server.close();
  })
  .catch(err => {
    console.error(err);
    server.close();
  });
JS
```

The shim resolves `pqq_native` from `target/release`. Use `loadLibrary(<path>)`
if your shared library lives elsewhere.

Returned objects mirror the JSON payloads from the Rust layer; for more control
call `easyStartServer`/`easyRequest` directly.
