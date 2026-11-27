use crate::store::SecretStore;
use std::collections::BTreeMap;
use std::io::Read;
use tiny_http::{Header, Response, Server, StatusCode};

const MAX_HTTP_BODY: u64 = 10 * 1024 * 1024; // 10 MiB cap

pub fn resolve_headers(
    templates: &BTreeMap<String, String>,
    store: &SecretStore,
) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    for (hk, tpl) in templates {
        let mut rendered = tpl.clone();
        while let Some(start) = rendered.find("{{SECRET:") {
            let after = &rendered[start + 9..];
            let Some(end) = after.find("}}") else {
                break;
            };
            let sec_name = &after[..end];
            let secret = store
                .get_secret(sec_name)?
                .ok_or_else(|| format!("Secret '{}' not found in vault", sec_name))?;
            rendered = format!(
                "{}{}{}",
                &rendered[..start],
                secret.as_str(),
                &after[end + 2..]
            );
        }
        out.insert(hk.clone(), rendered);
    }
    Ok(out)
}

fn has_path_traversal(rest: &str) -> bool {
    let path_only = rest.split('?').next().unwrap_or(rest);
    path_only
        .split('/')
        .any(|seg| seg == ".." || seg.eq_ignore_ascii_case("%2e%2e"))
}

pub fn start_proxy_server(_store: &SecretStore, host: &str, port: u16) -> Result<Server, String> {
    let addr = format!("{}:{}", host, port);
    Server::http(&addr).map_err(|e| format!("Failed to bind {}: {}", addr, e))
}

pub fn handle_single_request(mut req: tiny_http::Request, store: &SecretStore) {
    let url_path = req.url().to_string();
    let trimmed = url_path.trim_start_matches('/');
    let mut parts = trimmed.splitn(3, '/');
    let prefix = parts.next().unwrap_or("");
    let route_name = parts.next().unwrap_or("");
    let rest = parts.next().unwrap_or("");

    if prefix != "r" || route_name.is_empty() {
        let _ = req.respond(
            Response::from_string("Use /r/<route_name>/<path>").with_status_code(StatusCode(400)),
        );
        return;
    }

    if has_path_traversal(rest) {
        let _ = req.respond(
            Response::from_string("Path traversal rejected").with_status_code(StatusCode(400)),
        );
        return;
    }

    let routes = match store.load_routes() {
        Ok(r) => r,
        Err(e) => {
            let _ = req.respond(Response::from_string(e).with_status_code(StatusCode(500)));
            return;
        }
    };
    let Some(route) = routes.get(route_name) else {
        let _ = req.respond(
            Response::from_string(format!("Unknown route: {}", route_name))
                .with_status_code(StatusCode(404)),
        );
        return;
    };

    let upstream_url = if rest.is_empty() {
        route.target.clone()
    } else {
        format!("{}/{}", route.target, rest)
    };

    let mut body = Vec::new();
    if let Err(e) = req
        .as_reader()
        .take(MAX_HTTP_BODY + 1)
        .read_to_end(&mut body)
    {
        let _ = req.respond(Response::from_string(e.to_string()).with_status_code(StatusCode(400)));
        return;
    }
    if body.len() as u64 > MAX_HTTP_BODY {
        let _ = req.respond(
            Response::from_string("Request body too large").with_status_code(StatusCode(413)),
        );
        return;
    }

    let method = req.method().as_str().to_string();
    let mut up_req = ureq::request(&method, &upstream_url);

    // Copy safe headers; strip auth, cookies, host, and hop-by-hop headers
    for h in req.headers() {
        let name_lower = h.field.as_str().as_str().to_ascii_lowercase();
        if matches!(
            name_lower.as_str(),
            "host"
                | "content-length"
                | "connection"
                | "authorization"
                | "proxy-authorization"
                | "cookie"
                | "transfer-encoding"
        ) {
            continue;
        }
        up_req = up_req.set(h.field.as_str().as_str(), h.value.as_str());
    }

    match resolve_headers(&route.headers, store) {
        Ok(injected) => {
            for (k, v) in injected {
                up_req = up_req.set(&k, &v);
            }
        }
        Err(e) => {
            let _ = req.respond(Response::from_string(e).with_status_code(StatusCode(500)));
            return;
        }
    }

    let up_res = if body.is_empty() {
        up_req.call()
    } else {
        up_req.send_bytes(&body)
    };

    let (status, resp_headers, raw_body) = match up_res {
        Ok(r) => extract_ureq_response(r),
        Err(ureq::Error::Status(_, r)) => extract_ureq_response(r),
        Err(e) => {
            let _ = req.respond(
                Response::from_string(format!("Upstream error: {}", e))
                    .with_status_code(StatusCode(502)),
            );
            return;
        }
    };

    let final_body = match String::from_utf8(raw_body) {
        Ok(txt) => store.redact_text(&txt).unwrap_or(txt).into_bytes(),
        Err(e) => e.into_bytes(),
    };

    let mut out_resp = Response::from_data(final_body).with_status_code(StatusCode(status));
    for (hk, hv) in resp_headers {
        let low = hk.to_ascii_lowercase();
        if matches!(
            low.as_str(),
            "transfer-encoding" | "content-length" | "connection"
        ) {
            continue;
        }
        let clean_v = store.redact_text(&hv).unwrap_or(hv);
        if let Ok(header) = Header::from_bytes(hk.as_bytes(), clean_v.as_bytes()) {
            out_resp.add_header(header);
        }
    }
    let _ = req.respond(out_resp);
}

fn extract_ureq_response(resp: ureq::Response) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let status = resp.status();
    let headers: Vec<(String, String)> = resp
        .headers_names()
        .into_iter()
        .filter_map(|name| resp.header(&name).map(|val| (name, val.to_string())))
        .collect();
    let mut buf = Vec::new();
    let _ = resp.into_reader().take(MAX_HTTP_BODY).read_to_end(&mut buf);
    (status, headers, buf)
}
