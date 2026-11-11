//! Forwarding requests to the seller's API. Bodies stream in both directions; the gateway only
//! reads a response body when a paid request has to be settled (`x402`).

use std::net::SocketAddr;
use std::time::Duration;

use axum::body::Body;
use http::header::{
    CONNECTION, CONTENT_LENGTH, HOST, HeaderMap, HeaderName, HeaderValue, PROXY_AUTHENTICATE,
    PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
};
use http::uri::{PathAndQuery, Uri};
use http::{Request, Response};
use hyper::body::Incoming;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

use crate::x402::PAYMENT_SIGNATURE;

const KEEP_ALIVE: HeaderName = HeaderName::from_static("keep-alive");
const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");

/// Hop-by-hop headers (RFC 9110, section 7.6.1) that never travel through a proxy.
const HOP_BY_HOP: [HeaderName; 8] = [
    CONNECTION,
    KEEP_ALIVE,
    PROXY_AUTHENTICATE,
    PROXY_AUTHORIZATION,
    TE,
    TRAILER,
    TRANSFER_ENCODING,
    UPGRADE,
];

#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("the upstream didn't answer within {0:?}")]
    Timeout(Duration),
    #[error("connecting to the upstream failed: {0}")]
    Connect(hyper_util::client::legacy::Error),
    #[error("the upstream request failed: {0}")]
    Request(hyper_util::client::legacy::Error),
}

/// The seller's API.
#[derive(Clone)]
pub struct Upstream {
    base: Uri,
    client: Client<HttpsConnector<HttpConnector>, Body>,
    timeout: Duration,
}

impl Upstream {
    /// `base` has a scheme and an authority, and an optional path prefix.
    pub fn new(base: Uri, connect_timeout: Duration, timeout: Duration) -> Self {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_connect_timeout(Some(connect_timeout));
        http.set_nodelay(true);
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_provider_and_webpki_roots(rustls::crypto::aws_lc_rs::default_provider())
            .expect("the webpki roots load")
            .https_or_http()
            .enable_http1()
            .wrap_connector(http);
        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .build(https);
        Self {
            base,
            client,
            timeout,
        }
    }

    pub fn base(&self) -> &Uri {
        &self.base
    }

    /// How long a response's headers may take, and the buffered part of a paid body after them.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Forwards the request and returns the upstream's response with its body still streaming.
    /// The timeout covers the time to the response headers only.
    pub async fn forward(
        &self,
        mut request: Request<Body>,
        peer: SocketAddr,
    ) -> Result<Response<Incoming>, UpstreamError> {
        prepare(&mut request, &self.base, peer);
        let response = tokio::time::timeout(self.timeout, self.client.request(request))
            .await
            .map_err(|_| UpstreamError::Timeout(self.timeout))?
            .map_err(|error| {
                if error.is_connect() {
                    UpstreamError::Connect(error)
                } else {
                    UpstreamError::Request(error)
                }
            })?;
        let (mut parts, body) = response.into_parts();
        strip_hop_by_hop(&mut parts.headers);
        Ok(Response::from_parts(parts, body))
    }
}

/// Rewrites a client's request into the one sent upstream: the upstream's scheme, authority and
/// path prefix with the client's path and query; `Host` for the upstream; hop-by-hop headers and
/// the client's payment header removed; `X-Forwarded-For` extended with the peer, and
/// `X-Forwarded-Proto` and `X-Forwarded-Host` set when the proxy in front of us didn't.
pub fn prepare(request: &mut Request<Body>, base: &Uri, peer: SocketAddr) {
    let original_host = request.headers().get(HOST).cloned();

    let path_and_query = request
        .uri()
        .path_and_query()
        .map_or("/", PathAndQuery::as_str);
    let prefix = base.path().trim_end_matches('/');
    let joined = format!("{prefix}{path_and_query}");
    let mut parts = base.clone().into_parts();
    parts.path_and_query = Some(
        joined
            .parse()
            .unwrap_or_else(|_| PathAndQuery::from_static("/")),
    );
    *request.uri_mut() = Uri::from_parts(parts).expect("scheme, authority and path are set");

    let headers = request.headers_mut();
    strip_hop_by_hop(headers);
    headers.remove(PAYMENT_SIGNATURE);
    if let Some(authority) = base.authority()
        && let Ok(value) = HeaderValue::from_str(authority.as_str())
    {
        headers.insert(HOST, value);
    }

    let forwarded_for = match headers.get(X_FORWARDED_FOR).and_then(|v| v.to_str().ok()) {
        Some(existing) if !existing.trim().is_empty() => format!("{existing}, {}", peer.ip()),
        _ => peer.ip().to_string(),
    };
    if let Ok(value) = HeaderValue::from_str(&forwarded_for) {
        headers.insert(X_FORWARDED_FOR, value);
    }
    if !headers.contains_key(X_FORWARDED_PROTO) {
        headers.insert(X_FORWARDED_PROTO, HeaderValue::from_static("http"));
    }
    if !headers.contains_key(X_FORWARDED_HOST)
        && let Some(host) = original_host
    {
        headers.insert(X_FORWARDED_HOST, host);
    }
}

/// Removes the hop-by-hop headers, and every header the `Connection` header names.
pub fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
}

/// Drops the framing headers of a response whose body the gateway rewrote (buffered or
/// re-streamed), so hyper frames it again.
pub fn strip_framing(headers: &mut HeaderMap) {
    headers.remove(CONTENT_LENGTH);
    headers.remove(TRANSFER_ENCODING);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .header(HOST, "example.com")
            .header(CONNECTION, "close, x-hop")
            .header("x-hop", "1")
            .header(TRANSFER_ENCODING, "chunked")
            .header("payment-signature", "secret")
            .header("x-keep", "yes")
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn rewrites_the_uri_and_host() {
        let base: Uri = "http://127.0.0.1:3000".parse().unwrap();
        let mut req = request("/tx/0xabc?x=1");
        prepare(&mut req, &base, "203.0.113.5:4711".parse().unwrap());
        assert_eq!(req.uri().to_string(), "http://127.0.0.1:3000/tx/0xabc?x=1");
        assert_eq!(req.headers()[HOST], "127.0.0.1:3000");
        assert_eq!(req.headers()[X_FORWARDED_HOST], "example.com");
        assert_eq!(req.headers()[X_FORWARDED_PROTO], "http");
        assert_eq!(req.headers()[X_FORWARDED_FOR], "203.0.113.5");
    }

    #[test]
    fn keeps_the_upstream_prefix() {
        let base: Uri = "https://api.internal/v1/".parse().unwrap();
        let mut req = request("/tx");
        prepare(&mut req, &base, "203.0.113.5:4711".parse().unwrap());
        assert_eq!(req.uri().to_string(), "https://api.internal/v1/tx");
    }

    #[test]
    fn strips_hop_by_hop_and_payment_headers() {
        let base: Uri = "http://127.0.0.1:3000".parse().unwrap();
        let mut req = request("/");
        prepare(&mut req, &base, "203.0.113.5:4711".parse().unwrap());
        for name in [
            "connection",
            "x-hop",
            "transfer-encoding",
            "payment-signature",
        ] {
            assert!(!req.headers().contains_key(name), "{name} was forwarded");
        }
        assert_eq!(req.headers()["x-keep"], "yes");
    }

    #[test]
    fn appends_to_forwarded_for_and_keeps_forwarded_proto() {
        let base: Uri = "http://127.0.0.1:3000".parse().unwrap();
        let mut req = request("/");
        req.headers_mut()
            .insert(X_FORWARDED_FOR, HeaderValue::from_static("198.51.100.1"));
        req.headers_mut()
            .insert(X_FORWARDED_PROTO, HeaderValue::from_static("https"));
        prepare(&mut req, &base, "203.0.113.5:4711".parse().unwrap());
        assert_eq!(req.headers()[X_FORWARDED_FOR], "198.51.100.1, 203.0.113.5");
        assert_eq!(req.headers()[X_FORWARDED_PROTO], "https");
    }
}
