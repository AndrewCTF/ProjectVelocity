const path = require('path');
const fs = require('fs');
const ffi = require('ffi-napi');
const ref = require('ref-napi');
const Struct = require('ref-struct-napi');

const voidPtr = ref.refType(ref.types.void);
const uint8Ptr = ref.refType(ref.types.uint8);

const PqqOwnedSlice = Struct({
  data: uint8Ptr,
  len: ref.types.size_t,
  release: voidPtr,
  release_ctx: voidPtr,
});

function resolveLibrary(explicitPath) {
  if (explicitPath && fs.existsSync(explicitPath)) {
    return explicitPath;
  }
  const env = process.env.PQQ_NATIVE_LIB;
  if (env && fs.existsSync(env)) {
    return env;
  }
  const releaseRoot = path.resolve(__dirname, '../../../target/release');
  const debugRoot = path.resolve(__dirname, '../../../target/debug');
  const candidates = [];
  if (process.platform === 'win32') {
    candidates.push(path.join(releaseRoot, 'pqq_native.dll'));
    candidates.push(path.join(debugRoot, 'pqq_native.dll'));
  }
  if (process.platform === 'darwin') {
    candidates.push(path.join(releaseRoot, 'libpqq_native.dylib'));
    candidates.push(path.join(debugRoot, 'libpqq_native.dylib'));
  }
  if (process.platform !== 'win32' && process.platform !== 'darwin') {
    candidates.push(path.join(releaseRoot, 'libpqq_native.so'));
    candidates.push(path.join(debugRoot, 'libpqq_native.so'));
  }
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return candidates[0];
}

function loadLibrary(explicitPath) {
  const libPath = resolveLibrary(explicitPath);
  if (!fs.existsSync(libPath)) {
    throw new Error(`pqq_native shared library not found at ${libPath}`);
  }
  const lib = ffi.Library(libPath, {
    pqq_init: ['void', []],
    pqq_easy_start_server: ['int32', ['string', ref.refType(PqqOwnedSlice)]],
    pqq_easy_request: ['int32', ['string', ref.refType(PqqOwnedSlice)]],
    pqq_owned_slice_release: ['void', [ref.refType(PqqOwnedSlice)]],
    pqq_stop_server: ['int32', ['uint16']],
  });
  lib.pqq_init();
  return lib;
}

function sliceToString(lib, slice) {
  if (slice.len === 0 || slice.data.isNull()) {
    return '';
  }
  const buf = ref.reinterpret(slice.data, slice.len, 0);
  const text = buf.toString('utf8');
  lib.pqq_owned_slice_release(slice.ref());
  return text;
}

function easyStartServer(lib, config) {
  const slice = new PqqOwnedSlice();
  const code = lib.pqq_easy_start_server(JSON.stringify(config), slice.ref());
  if (code !== 0) {
    throw new Error(`pqq_easy_start_server failed (${code})`);
  }
  return JSON.parse(sliceToString(lib, slice));
}

function easyRequest(lib, config) {
  const slice = new PqqOwnedSlice();
  const code = lib.pqq_easy_request(JSON.stringify(config), slice.ref());
  if (code !== 0) {
    throw new Error(`pqq_easy_request failed (${code})`);
  }
  return JSON.parse(sliceToString(lib, slice));
}

class EasyServer {
  constructor(config, lib = loadLibrary()) {
    this.lib = lib;
    this.info = easyStartServer(this.lib, config);
  }

  get port() {
    return this.info.port;
  }

  get address() {
    return `127.0.0.1:${this.port}`;
  }

  get kemPublicKey() {
    return this.info.kem_public_base64;
  }

  close() {
    this.lib.pqq_stop_server(this.port);
  }
}

class EasyClient {
  constructor(config, lib = loadLibrary()) {
    this.lib = lib;
    this.config = { ...config };
  }

  async get(path = '/') {
    const payload = { ...this.config, path };
    return easyRequest(this.lib, payload);
  }
}

module.exports = {
  loadLibrary,
  easyStartServer,
  easyRequest,
  EasyServer,
  EasyClient,
  PqqOwnedSlice,
};
