//! C ABI surface for PQ-QUIC.
//!
//! These bindings expose a minimal deployment harness so C applications can
//! spin up a Velocity server and issue handshake probes or HTTP-style
//! fallbacks without having to embed Rust code directly.

use once_cell::sync::OnceCell;
use pqq_client::{Client, ClientConfig, HandshakeOutcome};
use pqq_core::{HandshakeConfig, HandshakeResponse};
use pqq_easy::{EasyClient, EasyClientConfig, EasyError, EasyServerBuilder, EasyServerHandle};
use pqq_server::{Request, Response, Server, ServerConfig};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::ffi::{c_char, c_void, CStr, CString};
use std::net::SocketAddr;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::ptr;
use std::sync::{Arc, Mutex, MutexGuard, Once};
use std::time::Duration;
use tokio::runtime::Runtime;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use url::Url;

const ERR_PANIC: i32 = -900;

type ReleaseCallback = unsafe extern "C" fn(*const u8, usize, *mut c_void);
type HandlerCallback = unsafe extern "C" fn(
    payload: *const u8,
    payload_len: usize,
    handshake_json: *const c_char,
    out_response: *mut PqqOwnedSlice,
    user_data: *mut c_void,
) -> i32;

#[repr(C)]
pub struct PqqOwnedSlice {
    pub data: *const u8,
    pub len: usize,
    pub release: Option<ReleaseCallback>,
    pub release_ctx: *mut c_void,
}

impl Default for PqqOwnedSlice {
    fn default() -> Self {
        Self {
            data: ptr::null(),
            len: 0,
            release: None,
            release_ctx: ptr::null_mut(),
        }
    }
}

impl PqqOwnedSlice {
    unsafe fn into_vec(mut self) -> Result<Vec<u8>, HandlerError> {
        if self.data.is_null() {
            if self.len == 0 {
                return Ok(Vec::new());
            }
            return Err(HandlerError::EmptyResponse);
        }
        let slice = std::slice::from_raw_parts(self.data, self.len);
        let mut out = Vec::with_capacity(slice.len());
        out.extend_from_slice(slice);
        if let Some(release) = self.release {
            release(self.data, self.len, self.release_ctx);
        }
        self.data = ptr::null();
        self.len = 0;
        self.release = None;
        self.release_ctx = ptr::null_mut();
        Ok(out)
    }
}

unsafe extern "C" fn release_vec_buffer(_ptr: *const u8, _len: usize, ctx: *mut c_void) {
    if !ctx.is_null() {
        let _ = Box::from_raw(ctx as *mut Vec<u8>);
    }
}

fn write_owned_slice(out: *mut PqqOwnedSlice, data: Vec<u8>) {
    if out.is_null() {
        return;
    }
    unsafe {
        let mut vec = data;
        let ptr = vec.as_mut_ptr();
        let len = vec.len();
        let boxed = Box::new(vec);
        let raw = Box::into_raw(boxed);
        (*out).data = ptr;
        (*out).len = len;
        (*out).release = Some(release_vec_buffer);
        (*out).release_ctx = raw as *mut c_void;
    }
}

fn respond_with_error(out: *mut PqqOwnedSlice, code: i32, message: &str) -> i32 {
    if out.is_null() {
        return code;
    }
    let payload = match serde_json::to_vec(&ErrorResponse {
        status: "error",
        error: message,
    }) {
        Ok(bytes) => bytes,
        Err(_) => json!({"status": "error", "error": "serialization"})
            .to_string()
            .into_bytes(),
    };
    write_owned_slice(out, payload);
    code
}

fn respond_with_easy_error(out: *mut PqqOwnedSlice, err: EasyError) -> i32 {
    let code = easy_error_code(&err);
    let message = err.to_string();
    respond_with_error(out, code, &message)
}

fn guard_slice<F>(out: *mut PqqOwnedSlice, f: F) -> i32
where
    F: FnOnce() -> i32,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(code) => code,
        Err(_) => {
            tracing::error!(target: "pqq_native::ffi", "panic caught at FFI boundary");
            respond_with_error(out, ERR_PANIC, "panic in velocity bindings")
        }
    }
}

#[allow(dead_code)]
fn guard_i32<F>(f: F) -> i32
where
    F: FnOnce() -> i32,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(code) => code,
        Err(_) => {
            tracing::error!(target: "pqq_native::ffi", "panic caught at FFI boundary");
            -900
        }
    }
}

fn guard_unit<F>(f: F)
where
    F: FnOnce(),
{
    let _ = catch_unwind(AssertUnwindSafe(f));
}

fn lock_guard<'a, T>(mutex: &'a Mutex<T>, name: &str) -> MutexGuard<'a, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            tracing::warn!(target: "pqq_native::mutex", mutex = name, "poisoned mutex recovered via into_inner");
            poisoned.into_inner()
        }
    }
}

fn easy_error_code(err: &EasyError) -> i32 {
    match err {
        EasyError::MissingServerAddress => -101,
        EasyError::InvalidAddress(_) => -102,
        EasyError::MissingServerKey => -103,
        EasyError::Base64Decode(_) => -104,
        EasyError::Io(_) => -105,
        EasyError::RuntimeCreation(_) => -106,
        EasyError::Request(_) => -107,
        EasyError::Serde(_) => -108,
        EasyError::UnknownProfile(_) => -109,
        EasyError::MissingCachedKey { .. } => -110,
        EasyError::FallbackDisabled => -111,
        EasyError::FallbackHttp(_) => -112,
        EasyError::FallbackStatus { .. } => -113,
        EasyError::FallbackExhausted => -114,
        EasyError::AutodiscoveryFailed(_) => -115,
    }
}

/// # Safety
///
/// Callers must ensure `slice` points to a valid [`PqqOwnedSlice`] previously
/// populated by this library. After this call the slice is reset to empty.
#[no_mangle]
pub unsafe extern "C" fn pqq_owned_slice_release(slice: *mut PqqOwnedSlice) {
    guard_unit(|| unsafe {
        if slice.is_null() {
            return;
        }
        let slice_ref = &mut *slice;
        if let Some(release) = slice_ref.release.take() {
            if !slice_ref.data.is_null() {
                release(slice_ref.data, slice_ref.len, slice_ref.release_ctx);
            }
        }
        slice_ref.data = ptr::null();
        slice_ref.len = 0;
        slice_ref.release_ctx = ptr::null_mut();
    });
}

#[derive(Debug)]
enum HandlerError {
    Serialization,
    CString,
    Callback(i32),
    EmptyResponse,
}

#[derive(Clone, Copy)]
struct CallbackEntry {
    func: HandlerCallback,
    user_data: *mut c_void,
}

unsafe impl Send for CallbackEntry {}
unsafe impl Sync for CallbackEntry {}

#[derive(Default)]
struct NativeHandler {
    callback: Mutex<Option<CallbackEntry>>,
}

unsafe impl Send for NativeHandler {}
unsafe impl Sync for NativeHandler {}

impl NativeHandler {
    fn new() -> Self {
        Self {
            callback: Mutex::new(None),
        }
    }

    fn configure(&self, func: HandlerCallback, user_data: *mut c_void) {
        let mut guard = lock_guard(&self.callback, "native_handler.callback");
        *guard = Some(CallbackEntry { func, user_data });
    }

    fn clear(&self) {
        let mut guard = lock_guard(&self.callback, "native_handler.callback");
        guard.take();
    }

    fn invoke(&self, request: &Request) -> Response {
        match self.invoke_inner(request) {
            Ok(response) => response,
            Err(err) => {
                let details = match err {
                    HandlerError::Serialization => "handshake_serialization".to_string(),
                    HandlerError::CString => "handshake_encoding".to_string(),
                    HandlerError::Callback(code) => format!("callback_error({})", code),
                    HandlerError::EmptyResponse => "empty_response".to_string(),
                };
                tracing::warn!(
                    target = "pqq_native::handler",
                    error = %details,
                    "handler failure; returning diagnostic frame"
                );
                Response::from_bytes(
                    json!({
                        "status": "handler_error",
                        "details": details,
                    })
                    .to_string(),
                )
            }
        }
    }

    fn invoke_inner(&self, request: &Request) -> Result<Response, HandlerError> {
        let callback = {
            let guard = lock_guard(&self.callback, "native_handler.callback");
            guard.as_ref().cloned()
        };

        if let Some(callback) = callback {
            let handshake_json = serde_json::to_string(request.handshake())
                .map_err(|_| HandlerError::Serialization)?;
            let handshake_c = CString::new(handshake_json).map_err(|_| HandlerError::CString)?;
            let mut out = PqqOwnedSlice::default();
            let status = unsafe {
                (callback.func)(
                    request.payload().as_ptr(),
                    request.payload().len(),
                    handshake_c.as_ptr(),
                    &mut out as *mut _,
                    callback.user_data,
                )
            };
            if status != 0 {
                return Err(HandlerError::Callback(status));
            }
            let bytes = unsafe { out.into_vec()? };
            Ok(Response::from_bytes(bytes))
        } else {
            Ok(Response::from_bytes(request.payload().to_vec()))
        }
    }
}

static INIT: Once = Once::new();
static STATE: OnceCell<GlobalState> = OnceCell::new();

const MAX_REQUEST_SIZE: usize = 64 * 1024;

struct GlobalState {
    runtime: Runtime,
    servers: Mutex<HashMap<u16, ServerEntry>>,
    easy_servers: Mutex<HashMap<u16, EasyServerEntry>>,
}

struct ServerEntry {
    addr: SocketAddr,
    kem_public: Vec<u8>,
    handler: Arc<NativeHandler>,
    shutdown: Mutex<Option<oneshot::Sender<()>>>,
    task: JoinHandle<()>,
}

struct EasyServerEntry {
    handle: EasyServerHandle,
}

#[derive(Deserialize, Debug)]
struct StartServerConfig {
    #[serde(default = "default_bind")]
    bind: String,
    #[serde(default = "default_alpns")]
    alpns: Vec<String>,
    #[serde(default)]
    fallback: Option<FallbackConfig>,
}

#[derive(Deserialize, Debug)]
struct FallbackConfig {
    alpn: String,
    host: String,
    port: u16,
}

fn default_profile_label() -> String {
    "balanced".to_string()
}

#[derive(Deserialize, Debug)]
#[serde(default)]
struct EasyServerStartConfig {
    bind: String,
    profile: String,
    alpns: Vec<String>,
    static_text: Option<String>,
    static_json: Option<Value>,
    cache_public_key: bool,
}

impl Default for EasyServerStartConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            profile: default_profile_label(),
            alpns: default_alpns(),
            static_text: None,
            static_json: None,
            cache_public_key: true,
        }
    }
}

#[derive(Default, Deserialize, Debug)]
#[serde(default)]
struct EasyClientFallbackConfig {
    enabled: Option<bool>,
    force_http1: Option<bool>,
    retries: Option<u32>,
    base_url: Option<String>,
    timeout_ms: Option<u64>,
    initial_backoff_ms: Option<u64>,
}

#[derive(Default, Deserialize, Debug)]
#[serde(default)]
struct EasyClientRequestConfig {
    server_addr: String,
    hostname: Option<String>,
    profile: Option<String>,
    server_key_base64: Option<String>,
    cached_key_host: Option<String>,
    cache_dir: Option<String>,
    cache_key: bool,
    path: Option<String>,
    method: Option<String>,
    fallback: EasyClientFallbackConfig,
}

/// Start a Velocity server using the easy API (static text or JSON handler).
///
/// # Safety
///
/// `config_json` must be a UTF-8 JSON document matching `EasyServerStartConfig`.
/// `out_response` must point to writable memory for a `PqqOwnedSlice` and will be
/// populated with an owned JSON payload to free via [`pqq_owned_slice_release`].
#[no_mangle]
pub unsafe extern "C" fn pqq_easy_start_server(
    config_json: *const c_char,
    out_response: *mut PqqOwnedSlice,
) -> i32 {
    guard_slice(out_response, || {
        pqq_init();
        if config_json.is_null() || out_response.is_null() {
            return respond_with_error(out_response, -1, "null pointer");
        }

        let cfg_str = match unsafe { CStr::from_ptr(config_json) }.to_str() {
            Ok(s) => s,
            Err(_) => return respond_with_error(out_response, -2, "invalid utf-8"),
        };

        let config: EasyServerStartConfig = match serde_json::from_str(cfg_str) {
            Ok(cfg) => cfg,
            Err(_) => return respond_with_error(out_response, -3, "invalid config json"),
        };

        let mut builder = match EasyServerBuilder::new().bind_addr(&config.bind) {
            Ok(b) => b,
            Err(err) => return respond_with_easy_error(out_response, err),
        };

        let profile_label = config.profile.clone();
        builder = match builder.security_profile_str(profile_label.as_str()) {
            Ok(b) => b,
            Err(err) => return respond_with_easy_error(out_response, err),
        };

        builder = builder.alpns(config.alpns.clone());
        builder = builder.cache_public_key(config.cache_public_key);

        if let Some(ref text) = config.static_text {
            builder = builder.static_text(text.clone());
        } else if let Some(ref json_val) = config.static_json {
            builder = builder.static_json(json_val.clone());
        }

        let handle = match builder.build() {
            Ok(handle) => handle,
            Err(err) => return respond_with_easy_error(out_response, err),
        };

        let addr = handle.address();
        let port = addr.port();
        let kem_public_base64 = handle.kem_public_key_base64();

        {
            let state = global_state();
            let mut easy = lock_guard(&state.easy_servers, "easy_servers");
            easy.insert(port, EasyServerEntry { handle });
        }

        let response = EasyServerStartResponse {
            status: "ok",
            port,
            addr: addr.to_string(),
            profile: profile_label,
            alpns: config.alpns,
            kem_public_base64,
        };

        match serde_json::to_vec(&response) {
            Ok(bytes) => {
                write_owned_slice(out_response, bytes);
                0
            }
            Err(_) => respond_with_error(out_response, -5, "serialization failure"),
        }
    })
}

/// Perform a Velocity request using the easy client wrapper with automatic
/// fallback handling.
///
/// # Safety
///
/// `config_json` must be UTF-8 JSON matching `EasyClientRequestConfig`. The
/// returned slice must be released via [`pqq_owned_slice_release`].
#[no_mangle]
pub unsafe extern "C" fn pqq_easy_request(
    config_json: *const c_char,
    out_response: *mut PqqOwnedSlice,
) -> i32 {
    guard_slice(out_response, || {
        pqq_init();
        if config_json.is_null() || out_response.is_null() {
            return respond_with_error(out_response, -1, "null pointer");
        }

        let cfg_str = match unsafe { CStr::from_ptr(config_json) }.to_str() {
            Ok(s) => s,
            Err(_) => return respond_with_error(out_response, -2, "invalid utf-8"),
        };

        let config: EasyClientRequestConfig = match serde_json::from_str(cfg_str) {
            Ok(cfg) => cfg,
            Err(_) => return respond_with_error(out_response, -3, "invalid config json"),
        };

        let mut builder = match EasyClientConfig::builder().server_addr(&config.server_addr) {
            Ok(b) => b,
            Err(err) => return respond_with_easy_error(out_response, err),
        };

        if let Some(ref hostname) = config.hostname {
            builder = builder.hostname(hostname.clone());
        }

        if let Some(ref profile) = config.profile {
            builder = match builder.security_profile_str(profile.as_str()) {
                Ok(b) => b,
                Err(err) => return respond_with_easy_error(out_response, err),
            };
        }

        if let Some(ref key_b64) = config.server_key_base64 {
            builder = match builder.server_key_base64(key_b64) {
                Ok(b) => b,
                Err(err) => return respond_with_easy_error(out_response, err),
            };
        } else if let Some(ref cached_host) = config.cached_key_host {
            builder = builder.server_key_cache(cached_host.clone());
        }

        if let Some(ref cache_dir) = config.cache_dir {
            builder = builder.cache_dir(PathBuf::from(cache_dir));
        }

        if config.cache_key {
            builder = builder.cache_key(true);
        }

        if let Some(enabled) = config.fallback.enabled {
            if !enabled {
                builder = builder.disable_fallback();
            }
        }

        if let Some(force_http1) = config.fallback.force_http1 {
            builder = builder.fallback_http1_only(force_http1);
        }

        if let Some(retries) = config.fallback.retries {
            builder = builder.fallback_retries(retries);
        }

        if let Some(timeout_ms) = config.fallback.timeout_ms {
            builder = builder.fallback_timeout(Duration::from_millis(timeout_ms));
        }

        if let Some(backoff_ms) = config.fallback.initial_backoff_ms {
            builder = builder.fallback_initial_backoff(Duration::from_millis(backoff_ms));
        }

        if let Some(ref base_url) = config.fallback.base_url {
            builder = builder.fallback_base_url(base_url.clone());
        }

        let client_config = match builder.build() {
            Ok(cfg) => cfg,
            Err(err) => return respond_with_easy_error(out_response, err),
        };

        let client = match EasyClient::connect(client_config) {
            Ok(client) => client,
            Err(err) => return respond_with_easy_error(out_response, err),
        };

        let path = config.path.unwrap_or_else(|| "/".to_string());
        let method = config.method.unwrap_or_else(|| "GET".to_string());
        let method_upper = method.trim().to_uppercase();

        let response = match method_upper.as_str() {
            "GET" => match client.fetch_text(&path) {
                Ok(body) => EasyClientResponse {
                    status: "ok",
                    body: Some(body),
                    handshake: None,
                },
                Err(err) => return respond_with_easy_error(out_response, err),
            },
            "JSON" => match client.fetch_json::<Value>(&path) {
                Ok(json_body) => match serde_json::to_string(&json_body) {
                    Ok(text) => EasyClientResponse {
                        status: "ok",
                        body: Some(text),
                        handshake: None,
                    },
                    Err(_) => return respond_with_error(out_response, -6, "serialization failure"),
                },
                Err(err) => return respond_with_easy_error(out_response, err),
            },
            "PROBE" => match client.probe() {
                Ok(handshake) => EasyClientResponse {
                    status: "ok",
                    body: None,
                    handshake: Some(handshake),
                },
                Err(err) => return respond_with_easy_error(out_response, err),
            },
            other => {
                return respond_with_error(out_response, -7, &format!("unsupported method {other}"))
            }
        };

        match serde_json::to_vec(&response) {
            Ok(bytes) => {
                write_owned_slice(out_response, bytes);
                0
            }
            Err(_) => respond_with_error(out_response, -5, "serialization failure"),
        }
    })
}

#[derive(Serialize)]
struct SuccessResponse {
    status: &'static str,
    handshake: HandshakeResponse,
    body: String,
}

#[derive(Serialize)]
struct HandshakeOnlyResponse {
    status: &'static str,
    handshake: HandshakeResponse,
}

#[derive(Serialize)]
struct ErrorResponse<'a> {
    status: &'static str,
    error: &'a str,
}

#[derive(Serialize)]
struct EasyServerStartResponse {
    status: &'static str,
    port: u16,
    addr: String,
    profile: String,
    alpns: Vec<String>,
    kem_public_base64: String,
}

#[derive(Serialize)]
struct EasyClientResponse {
    status: &'static str,
    body: Option<String>,
    handshake: Option<HandshakeResponse>,
}

fn default_bind() -> String {
    "127.0.0.1:0".to_string()
}

fn default_alpns() -> Vec<String> {
    vec!["pqq/1".to_string(), "h3".to_string()]
}

fn global_state() -> &'static GlobalState {
    STATE.get_or_init(|| GlobalState {
        runtime: Runtime::new().expect("tokio runtime"),
        servers: Mutex::new(HashMap::new()),
        easy_servers: Mutex::new(HashMap::new()),
    })
}

#[no_mangle]
pub extern "C" fn pqq_init() {
    INIT.call_once(|| {
        let _ = tracing_subscriber::fmt::try_init();
        let _ = global_state();
    });
}

/// # Safety
///
/// `config_json` must point to a valid, null-terminated UTF-8 string for the
/// duration of this call.
#[no_mangle]
pub unsafe extern "C" fn pqq_start_server(config_json: *const c_char) -> i32 {
    guard_i32(|| {
        pqq_init();
        if config_json.is_null() {
            return -1;
        }
        let cfg_str = match CStr::from_ptr(config_json).to_str() {
            Ok(s) => s,
            Err(_) => return -2,
        };
        let config: StartServerConfig = match serde_json::from_str(cfg_str) {
            Ok(cfg) => cfg,
            Err(_) => return -3,
        };

        let bind_addr: SocketAddr = match config.bind.parse() {
            Ok(addr) => addr,
            Err(_) => return -4,
        };

        let runtime = &global_state().runtime;
        let handler = Arc::new(NativeHandler::new());
        let mut handshake_cfg = HandshakeConfig::default().with_supported_alpns(config.alpns.clone());
        if let Some(fallback) = &config.fallback {
            handshake_cfg = handshake_cfg.with_fallback_endpoint(
                fallback.alpn.clone(),
                fallback.host.clone(),
                fallback.port,
            );
        }

        let handler_for_entry = Arc::clone(&handler);
        let result = runtime.block_on(async move {
            let server = Server::bind(bind_addr, ServerConfig::default().with_handshake(handshake_cfg))
                .await
                .map_err(|_| -5)?;
            let addr = server.local_addr().map_err(|_| -6)?;
            let kem_public = server.kem_public_key().to_vec();
            let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
            let handler_for_task = Arc::clone(&handler_for_entry);
            let task = tokio::spawn(async move {
                let serve_fut = server.serve(move |req: Request| {
                    let handler_inner = Arc::clone(&handler_for_task);
                    async move { handler_inner.invoke(&req) }
                });
                tokio::select! {
                    res = serve_fut => {
                        if let Err(err) = res {
                            tracing::error!(target: "pqq_native::server", error = ?err, "native server loop terminated");
                        } else {
                            tracing::info!(target: "pqq_native::server", "native server loop completed");
                        }
                    }
                    _ = &mut shutdown_rx => {
                        tracing::info!(target: "pqq_native::server", "shutdown signal received; terminating server loop");
                    }
                }
            });
            Ok::<ServerEntry, i32>(ServerEntry {
                addr,
                kem_public,
                handler: handler_for_entry,
                shutdown: Mutex::new(Some(shutdown_tx)),
                task,
            })
        });

        match result {
            Ok(entry) => {
                let port = entry.addr.port();
                {
                    let mut servers = lock_guard(&global_state().servers, "servers");
                    servers.insert(port, entry);
                }
                port as i32
            }
            Err(code) => code,
        }
    })
}

#[no_mangle]
pub extern "C" fn pqq_set_handler(
    port: u16,
    callback: HandlerCallback,
    user_data: *mut c_void,
) -> i32 {
    guard_i32(|| {
        pqq_init();
        let handler = {
            let servers = lock_guard(&global_state().servers, "servers");
            match servers.get(&port) {
                Some(entry) => Arc::clone(&entry.handler),
                None => return -1,
            }
        };
        handler.configure(callback, user_data);
        0
    })
}

#[no_mangle]
pub extern "C" fn pqq_clear_handler(port: u16) -> i32 {
    guard_i32(|| {
        pqq_init();
        let handler = {
            let servers = lock_guard(&global_state().servers, "servers");
            match servers.get(&port) {
                Some(entry) => Arc::clone(&entry.handler),
                None => return -1,
            }
        };
        handler.clear();
        0
    })
}

#[no_mangle]
pub extern "C" fn pqq_stop_server(port: u16) -> i32 {
    guard_i32(|| {
        pqq_init();
        let state = global_state();

        if let Some(entry) = {
            let mut easy = lock_guard(&state.easy_servers, "easy_servers");
            easy.remove(&port)
        } {
            let handle = entry.handle;
            handle.shutdown();
            return 0;
        }

        let entry = {
            let mut servers = lock_guard(&state.servers, "servers");
            match servers.remove(&port) {
                Some(entry) => entry,
                None => return -1,
            }
        };

        let ServerEntry {
            addr: _,
            kem_public: _,
            handler: _,
            shutdown,
            task,
        } = entry;

        {
            let mut guard = lock_guard(&shutdown, "shutdown");
            if let Some(tx) = guard.take() {
                let _ = tx.send(());
            }
        }

        task.abort();
        let runtime = &state.runtime;
        runtime.block_on(async move {
            let _ = task.await;
        });
        0
    })
}

/// # Safety
///
/// Callers must guarantee that any non-null pointers remain valid for the
/// duration of this call and that `_out_response` points to writable storage
/// for a `*const c_char`. The returned pointer must be freed via
/// [`pqq_string_free`].
#[no_mangle]
pub unsafe extern "C" fn pqq_request(
    method: *const c_char,
    url: *const c_char,
    body: *const c_char,
    out_response: *mut *const c_char,
) -> i32 {
    guard_i32(|| {
        if out_response.is_null() {
            return -1;
        }
        *out_response = ptr::null();
        if method.is_null() || url.is_null() {
            return -1;
        }

        let method = match CStr::from_ptr(method).to_str() {
            Ok(m) => m.to_uppercase(),
            Err(_) => return -2,
        };
        let url_str = match CStr::from_ptr(url).to_str() {
            Ok(u) => u,
            Err(_) => return -2,
        };
        let body_str = if body.is_null() {
            ""
        } else {
            match CStr::from_ptr(body).to_str() {
                Ok(b) => b,
                Err(_) => return -2,
            }
        };

        let url = match Url::parse(url_str) {
            Ok(u) => u,
            Err(_) => return -3,
        };
        let port = url.port().unwrap_or(0);
        let port = if port == 0 { return -4 } else { port };

        let entry = {
            let servers = lock_guard(&global_state().servers, "servers");
            match servers.get(&port) {
                Some(entry) => (entry.addr, entry.kem_public.clone()),
                None => return -5,
            }
        };

        let alpns_owned: Vec<String> = url
            .query_pairs()
            .find(|(key, _)| key == "alpns")
            .map(|(_, value)| value.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_else(default_alpns);

        let path = url.path().to_string();
        let body_owned = body_str.to_string();
        let method_owned = method.clone();
        let (server_addr, server_key) = entry;

        let runtime = &global_state().runtime;
        let result = runtime.block_on(async move {
            let mut client_config = ClientConfig::new(server_addr);
            client_config = client_config
                .with_alpns(alpns_owned.clone())
                .with_server_kem_public(server_key.clone());
            let client = Client::new(client_config);

            match client.connect_or_fallback().await.map_err(|_| -7)? {
                HandshakeOutcome::Established { session, .. } => {
                    let handshake = session.handshake_response().clone();
                    let request_payload = match method_owned.as_str() {
                        "GET" => json!({
                            "method": "GET",
                            "target": path,
                            "body": serde_json::Value::Null,
                        })
                        .to_string()
                        .into_bytes(),
                        "POST" => json!({
                            "method": "POST",
                            "target": path,
                            "body": body_owned,
                        })
                        .to_string()
                        .into_bytes(),
                        _ => return Err(-8),
                    };
                    if request_payload.len() > MAX_REQUEST_SIZE {
                        return Err(-10);
                    }
                    let response_bytes = session
                        .send_request(&request_payload)
                        .await
                        .map_err(|_| -8)?;
                    let response = String::from_utf8(response_bytes).map_err(|_| -8)?;
                    let json_payload = serde_json::to_string(&SuccessResponse {
                        status: "ok",
                        handshake,
                        body: response,
                    })
                    .map_err(|_| -9)?;
                    Ok(json_payload)
                }
                HandshakeOutcome::Fallback(handshake) => {
                    let payload = serde_json::to_string(&HandshakeOnlyResponse {
                        status: "fallback",
                        handshake,
                    })
                    .map_err(|_| -9)?;
                    Ok(payload)
                }
                HandshakeOutcome::Unsupported(handshake) => {
                    let payload = serde_json::to_string(&HandshakeOnlyResponse {
                        status: "unsupported",
                        handshake,
                    })
                    .map_err(|_| -9)?;
                    Ok(payload)
                }
            }
        });

        match result {
            Ok(json_payload) => {
                assign_response(out_response, &json_payload);
                0
            }
            Err(code) => {
                let error = match code {
                    -1 => "invalid pointers",
                    -2 => "invalid utf-8",
                    -3 => "invalid url",
                    -4 => "missing port",
                    -5 => "unknown server",
                    -6 => "invalid host",
                    -7 => "handshake failed",
                    -8 => "request failed",
                    -9 => "serialization failed",
                    -10 => "request too large",
                    _ => "unknown error",
                };
                let payload = serde_json::to_string(&ErrorResponse {
                    status: "error",
                    error,
                })
                .unwrap_or_else(|_| json!({"status":"error","error":"serialization"}).to_string());
                assign_response(out_response, &payload);
                code
            }
        }
    })
}

fn assign_response(out: *mut *const c_char, payload: &str) {
    unsafe {
        if out.is_null() {
            return;
        }
        let cstring = CString::new(payload).expect("response cstring");
        *out = cstring.into_raw();
    }
}

/// # Safety
///
/// `ptr` must be either null or a pointer returned by Velocity FFI functions
/// that allocate strings, and it must not be used again after this call.
#[no_mangle]
pub unsafe extern "C" fn pqq_string_free(ptr: *const c_char) {
    if ptr.is_null() {
        return;
    }
    let _ = CString::from_raw(ptr as *mut c_char);
}
