#[path = "../src/proxy.rs"]
mod proxy;
#[path = "../src/runner.rs"]
mod runner;
#[path = "../src/store.rs"]
mod store;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use proxy::{handle_single_request, start_proxy_server};
use runner::run_redacted;
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use store::{validate_route_name, validate_secret_name, validate_upstream_url, SecretStore};
use tempfile::TempDir;
use tiny_http::{Response, Server};

#[derive(Clone, Default)]
struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn vault_encrypts_with_xchacha20_and_redacts_variants() {
    let dir = TempDir::new().unwrap();
    let store = SecretStore::new(Some(dir.path().to_path_buf()), Some("test-pass".into()));
    let secret = "ghp_SuperSecretToken_2026!";
    store.set_secret("GH_TOKEN", secret).unwrap();

    let listed = store.list_secrets().unwrap();
    assert_eq!(
        listed,
        vec![("GH_TOKEN".to_string(), "ghp_****".to_string())]
    );

    let raw_vault = fs::read_to_string(dir.path().join("vault.enc")).unwrap();
    assert!(!raw_vault.contains(secret));

    // Wrong passphrase must fail authentication
    let wrong_store = SecretStore::new(Some(dir.path().to_path_buf()), Some("wrong-pass".into()));
    assert!(wrong_store.get_secret("GH_TOKEN").is_err());

    // Redacts raw, base64, and url-encoded variants
    let b64 = B64.encode(secret.as_bytes());
    let sample = format!(
        "raw={} b64={} url=ghp_SuperSecretToken_2026%21",
        secret, b64
    );
    let redacted = store.redact_text(&sample).unwrap();
    assert_eq!(
        redacted,
        "raw=[REDACTED:GH_TOKEN] b64=[REDACTED:GH_TOKEN] url=[REDACTED:GH_TOKEN]"
    );

    assert!(store.delete_secret("GH_TOKEN").unwrap());
    assert!(!store.delete_secret("GH_TOKEN").unwrap());
    assert!(store.list_secrets().unwrap().is_empty());
}

#[test]
fn rejects_invalid_names_and_insecure_http() {
    assert!(validate_secret_name("VALID_KEY-1").is_ok());
    assert!(validate_secret_name("../evil").is_err());
    assert!(validate_route_name("github-api").is_ok());
    assert!(validate_route_name("bad/route").is_err());
    assert!(validate_upstream_url("https://api.github.com", false).is_ok());
    assert!(validate_upstream_url("http://127.0.0.1:8080", false).is_ok());
    assert!(validate_upstream_url("http://example.com", false).is_err());
    assert!(validate_upstream_url("http://example.com", true).is_ok());
}

#[test]
fn proxy_injects_auth_blocks_traversal_and_redacts_response() {
    let dir = TempDir::new().unwrap();
    let store = SecretStore::new(Some(dir.path().to_path_buf()), Some("px-pass".into()));
    store.set_secret("API_KEY", "sk_test_proxy_9999").unwrap();

    // Start mock upstream server
    let upstream = Server::http("127.0.0.1:0").unwrap();
    let up_port = upstream.server_addr().to_ip().unwrap().port();
    thread::spawn(move || {
        if let Ok(req) = upstream.recv() {
            let auth = req
                .headers()
                .iter()
                .find(|h| {
                    h.field
                        .as_str()
                        .as_str()
                        .eq_ignore_ascii_case("Authorization")
                })
                .map(|h| h.value.as_str().to_string())
                .unwrap_or_default();
            let body = format!("{{\"echo\":\"{}\"}}", auth);
            let _ = req.respond(Response::from_string(body));
        }
    });

    let mut headers = BTreeMap::new();
    headers.insert("Authorization".into(), "Bearer {{SECRET:API_KEY}}".into());
    store
        .save_route(
            "mock",
            &format!("http://127.0.0.1:{}", up_port),
            headers,
            false,
        )
        .unwrap();

    let proxy_srv = start_proxy_server(&store, "127.0.0.1", 0).unwrap();
    let px_port = proxy_srv.server_addr().to_ip().unwrap().port();
    let dir_clone = dir.path().to_path_buf();
    thread::spawn(move || {
        let local = SecretStore::new(Some(dir_clone), Some("px-pass".into()));
        for _ in 0..2 {
            if let Ok(req) = proxy_srv.recv() {
                handle_single_request(req, &local);
            }
        }
    });

    // 1. Path traversal must be rejected even when sent raw without client URL normalization
    {
        use std::net::TcpStream;
        let mut conn = TcpStream::connect(format!("127.0.0.1:{}", px_port)).unwrap();
        conn.write_all(
            b"GET /r/mock/../etc/passwd HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        )
        .unwrap();
        let mut raw_resp = String::new();
        conn.read_to_string(&mut raw_resp).unwrap();
        assert!(raw_resp.starts_with("HTTP/1.1 400"));
    }

    // 2. Normal request injects secret & redacts echoed secret
    let resp = ureq::get(&format!("http://127.0.0.1:{}/r/mock/v1/test", px_port))
        .set("Authorization", "Bearer attacker-spoof")
        .call()
        .unwrap();
    let mut text = String::new();
    resp.into_reader().read_to_string(&mut text).unwrap();
    assert_eq!(text, "{\"echo\":\"Bearer [REDACTED:API_KEY]\"}");
}

#[test]
fn runner_redacts_subprocess_stdout_and_stderr() {
    let dir = TempDir::new().unwrap();
    let store = SecretStore::new(Some(dir.path().to_path_buf()), None);
    store
        .set_secret("DEMO_TOK", "tok_runner_secret_777")
        .unwrap();

    let out_buf = SharedBuf::default();
    let err_buf = SharedBuf::default();

    #[cfg(unix)]
    let cmd = vec![
        "sh".to_string(),
        "-c".to_string(),
        "printf 'out=%s\\n' \"$DEMO_TOK\"; printf 'err=%s\\n' \"$DEMO_TOK\" >&2".to_string(),
    ];
    #[cfg(windows)]
    let cmd = vec![
        "cmd".to_string(),
        "/c".to_string(),
        "echo out=%DEMO_TOK% & echo err=%DEMO_TOK% 1>&2".to_string(),
    ];

    let rc = run_redacted(
        &cmd,
        &["DEMO_TOK=secret://DEMO_TOK".to_string()],
        &store,
        out_buf.clone(),
        err_buf.clone(),
    )
    .unwrap();

    assert_eq!(rc, 0);
    let out_s = String::from_utf8_lossy(&out_buf.0.lock().unwrap()).to_string();
    let err_s = String::from_utf8_lossy(&err_buf.0.lock().unwrap()).to_string();
    assert!(out_s.contains("out=[REDACTED:DEMO_TOK]"));
    assert!(err_s.contains("err=[REDACTED:DEMO_TOK]"));
    assert!(!out_s.contains("tok_runner_secret_777"));
    assert!(!err_s.contains("tok_runner_secret_777"));
}
