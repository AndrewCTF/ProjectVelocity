use std::ffi::CString;

use pqq_native::{
    pqq_easy_request, pqq_easy_start_server, pqq_init, pqq_owned_slice_release, pqq_stop_server,
    PqqOwnedSlice,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct ServerInfo {
    status: String,
    port: u16,
    kem_public_base64: String,
}

#[derive(Deserialize)]
struct ClientInfo {
    status: String,
    body: Option<String>,
}

fn slice_to_vec(slice: &PqqOwnedSlice) -> Vec<u8> {
    if slice.len == 0 || slice.data.is_null() {
        return Vec::new();
    }
    unsafe { std::slice::from_raw_parts(slice.data, slice.len).to_vec() }
}

#[test]
fn easy_start_and_request_roundtrip() {
    pqq_init();

    let server_cfg = CString::new(
        r#"{"bind":"127.0.0.1:0","profile":"balanced","static_text":"Hello Velocity!"}"#,
    )
    .unwrap();

    let mut server_slice = PqqOwnedSlice::default();
    let rc = unsafe { pqq_easy_start_server(server_cfg.as_ptr(), &mut server_slice) };
    assert_eq!(rc, 0, "pqq_easy_start_server returned {rc}");

    let server_bytes = slice_to_vec(&server_slice);
    unsafe { pqq_owned_slice_release(&mut server_slice) };

    let server_info: ServerInfo = serde_json::from_slice(&server_bytes).expect("server json");
    assert_eq!(server_info.status, "ok");
    assert!(server_info.port > 0);

    let client_cfg = CString::new(format!(
        "{{\"server_addr\":\"127.0.0.1:{}\",\"hostname\":\"localhost\",\"server_key_base64\":\"{}\",\"path\":\"/\"}}",
        server_info.port, server_info.kem_public_base64
    ))
    .unwrap();

    let mut client_slice = PqqOwnedSlice::default();
    let rc = unsafe { pqq_easy_request(client_cfg.as_ptr(), &mut client_slice) };

    let client_bytes = slice_to_vec(&client_slice);
    eprintln!(
        "client response json: {}",
        String::from_utf8_lossy(&client_bytes)
    );
    assert_eq!(rc, 0, "pqq_easy_request returned {rc}");
    unsafe { pqq_owned_slice_release(&mut client_slice) };

    let client_info: ClientInfo = serde_json::from_slice(&client_bytes).expect("client json");
    assert_eq!(client_info.status, "ok");
    let body = client_info.body.expect("body string");
    assert!(body.starts_with("HTTP/1.1 200 OK"));
    assert!(body.contains("Hello Velocity!"));

    let stop_rc = pqq_stop_server(server_info.port);
    assert_eq!(stop_rc, 0);
}
