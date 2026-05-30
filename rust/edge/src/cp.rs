//! HTTPS client to the in-cluster control plane. Presents the edge's bearer
//! token; fetches the cert+key for an SNI with ETag revalidation. The token and
//! the returned private key only ever travel over this TLS connection.

use serde::Deserialize;

/// Outcome of a cert fetch.
pub enum CertFetch {
    /// `304` — the edge's cached copy is still current.
    Unchanged,
    /// `200` — new material (and its ETag, if the server sent one).
    Updated {
        chain_pem: Vec<u8>,
        key_pem: Vec<u8>,
        etag: Option<String>,
    },
}

#[derive(Deserialize)]
struct CertBody {
    chain_pem: String,
    key_pem: String,
}

/// Outcome of a WAF ruleset fetch.
pub enum WafFetch {
    /// `304` — the edge's cached ruleset is still current.
    Unchanged,
    /// `200` — new payload (generation, global YAML, zones, host→zone, + ETag).
    Updated {
        generation: u64,
        global_rules: String,
        zones: std::collections::HashMap<String, String>,
        host_zone_map: std::collections::HashMap<String, String>,
        etag: Option<String>,
    },
}

#[derive(Deserialize)]
struct WafBody {
    #[serde(default)]
    generation: u64,
    #[serde(default)]
    global_rules: String,
    #[serde(default)]
    zones: std::collections::HashMap<String, String>,
    #[serde(default)]
    host_zone_map: std::collections::HashMap<String, String>,
}

#[derive(Clone)]
pub struct CpClient {
    http: reqwest::Client,
    base: String,
    token: String,
}

impl CpClient {
    /// `base` is the control-plane URL (e.g. `https://controlplane:8443`).
    /// `ca_pem`, when present, is added as a trusted root (for a private CA).
    pub fn new(
        base: String,
        token: String,
        ca_pem: Option<Vec<u8>>,
    ) -> Result<Self, reqwest::Error> {
        let mut b = reqwest::Client::builder();
        if let Some(ca) = ca_pem {
            if let Ok(cert) = reqwest::Certificate::from_pem(&ca) {
                b = b.add_root_certificate(cert);
            }
        }
        Ok(Self {
            http: b.build()?,
            base: base.trim_end_matches('/').to_string(),
            token,
        })
    }

    pub async fn fetch_cert(
        &self,
        sni: &str,
        current_etag: Option<&str>,
    ) -> Result<CertFetch, String> {
        let url = format!("{}/v1/certs", self.base);
        // `sni` goes in the query string (?sni=…); .query() percent-encodes it,
        // so a wildcard SNI like `*.acme.com` is transmitted safely.
        let mut req = self
            .http
            .get(&url)
            .query(&[("sni", sni)])
            .bearer_auth(&self.token);
        if let Some(etag) = current_etag {
            req = req.header(reqwest::header::IF_NONE_MATCH, etag);
        }
        let resp = req.send().await.map_err(|e| format!("request: {e}"))?;

        match resp.status() {
            reqwest::StatusCode::NOT_MODIFIED => Ok(CertFetch::Unchanged),
            reqwest::StatusCode::OK => {
                let etag = resp
                    .headers()
                    .get(reqwest::header::ETAG)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                let body: CertBody = resp.json().await.map_err(|e| format!("decode: {e}"))?;
                Ok(CertFetch::Updated {
                    chain_pem: body.chain_pem.into_bytes(),
                    key_pem: body.key_pem.into_bytes(),
                    etag,
                })
            }
            s => Err(format!("control plane returned {s} for sni {sni:?}")),
        }
    }

    /// Fetch the global WAF ruleset (raw YAML + generation), with ETag
    /// revalidation. Mirrors `fetch_cert`.
    pub async fn fetch_waf(&self, current_etag: Option<&str>) -> Result<WafFetch, String> {
        let url = format!("{}/v1/waf", self.base);
        let mut req = self.http.get(&url).bearer_auth(&self.token);
        if let Some(etag) = current_etag {
            req = req.header(reqwest::header::IF_NONE_MATCH, etag);
        }
        let resp = req.send().await.map_err(|e| format!("request: {e}"))?;

        match resp.status() {
            reqwest::StatusCode::NOT_MODIFIED => Ok(WafFetch::Unchanged),
            reqwest::StatusCode::OK => {
                let etag = resp
                    .headers()
                    .get(reqwest::header::ETAG)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string);
                let body: WafBody = resp.json().await.map_err(|e| format!("decode: {e}"))?;
                Ok(WafFetch::Updated {
                    generation: body.generation,
                    global_rules: body.global_rules,
                    zones: body.zones,
                    host_zone_map: body.host_zone_map,
                    etag,
                })
            }
            s => Err(format!("control plane returned {s} for /v1/waf")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A one-shot HTTP/1.1 stub: serves a single request with `response`, and
    /// records the raw request head (request line + headers) for assertions.
    /// Returns the bound `http://127.0.0.1:port` base URL.
    async fn stub(response: &'static str, captured: Arc<Mutex<String>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap();
            *captured.lock().unwrap() = String::from_utf8_lossy(&buf[..n]).to_string();
            sock.write_all(response.as_bytes()).await.unwrap();
            sock.flush().await.unwrap();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn fetch_200_parses_body_and_etag_and_sends_bearer() {
        let body = r#"{"chain_pem":"CHAIN","key_pem":"KEY"}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nETag: \"abc\"\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        // leak to get 'static (test-only)
        let resp: &'static str = Box::leak(resp.into_boxed_str());
        let captured = Arc::new(Mutex::new(String::new()));
        let base = stub(resp, captured.clone()).await;

        let cp = CpClient::new(base, "tok-123".into(), None).unwrap();
        let got = cp.fetch_cert("acme.com", None).await.unwrap();
        match got {
            CertFetch::Updated {
                chain_pem,
                key_pem,
                etag,
            } => {
                assert_eq!(chain_pem, b"CHAIN");
                assert_eq!(key_pem, b"KEY");
                assert_eq!(etag.as_deref(), Some("\"abc\""));
            }
            _ => panic!("expected Updated"),
        }

        let req = captured.lock().unwrap().clone();
        assert!(req.starts_with("GET /v1/certs?sni=acme.com "), "path: {req}");
        assert!(
            req.contains("authorization: Bearer tok-123")
                || req.contains("Authorization: Bearer tok-123"),
            "missing bearer header: {req}"
        );
    }

    #[tokio::test]
    async fn fetch_304_is_unchanged_and_sends_if_none_match() {
        let resp = "HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n";
        let captured = Arc::new(Mutex::new(String::new()));
        let base = stub(resp, captured.clone()).await;

        let cp = CpClient::new(base, "tok".into(), None).unwrap();
        let got = cp.fetch_cert("acme.com", Some("\"v1\"")).await.unwrap();
        assert!(matches!(got, CertFetch::Unchanged));

        let req = captured.lock().unwrap().clone();
        assert!(
            req.to_lowercase().contains("if-none-match: \"v1\""),
            "missing INM: {req}"
        );
    }

    #[tokio::test]
    async fn fetch_403_is_error() {
        let resp = "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n";
        let captured = Arc::new(Mutex::new(String::new()));
        let base = stub(resp, captured).await;
        let cp = CpClient::new(base, "tok".into(), None).unwrap();
        assert!(cp.fetch_cert("evil.com", None).await.is_err());
    }
}
