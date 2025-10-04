# Native FFI Easy Demo

This directory demonstrates the `pqq_easy_*` C helpers that wrap the Velocity
Rust stack in a JSON-configurable surface.

## Files

- `easy_demo.c` – launches an in-process Velocity server with
  `pqq_easy_start_server`, parses the JSON response to recover the listening
  port and KEM public key, and issues a `pqq_easy_request` against it.

## Building

Build the demo against the `pqq-native` library (the header lives in
`native-bindings/include/pqq.h`):

```bash
cc easy_demo.c -I../../native-bindings/include -L../../target/debug -lpqq_native -o easy_demo
./easy_demo
```

Update the include/library paths as needed for your environment. The demo
prints the JSON envelopes returned by each helper and cleans up buffers with
`pqq_owned_slice_release`.
