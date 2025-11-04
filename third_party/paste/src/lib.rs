// Local shim crate to replace the unmaintained `paste` crate by re-exporting
// compatible macros from `pasty` where applicable. This keeps the external
// API surface small and lets downstream crates that depend on `paste` build
// without pulling the unmaintained package.

pub use pasty::*;
