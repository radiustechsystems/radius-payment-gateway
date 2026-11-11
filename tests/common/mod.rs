//! Test fixtures: an upstream that echoes what it receives, and the gateway served in-process.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path, Request};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use clap::Parser;
use futures_util::{StreamExt, stream};
use radius_gateway::{App, Config};
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// What the echo upstream saw.
#[derive(Debug, Deserialize)]
pub struct Echo {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub headers: BTreeMap<String, String>,
    pub body: String,
}

async fn echo(request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let status = parts
        .headers
        .get("x-echo-status")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u16>().ok())
        .and_then(|code| StatusCode::from_u16(code).ok())
        .unwrap_or(StatusCode::OK);
    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    let headers: BTreeMap<String, String> = parts
        .headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                value.to_str().unwrap_or("<binary>").to_owned(),
            )
        })
        .collect();
    let json = serde_json::json!({
        "method": parts.method.as_str(),
        "path": parts.uri.path(),
        "query": parts.uri.query(),
        "headers": headers,
        "body": String::from_utf8_lossy(&bytes),
    });
    let mut response = (status, axum::Json(json)).into_response();
    response
        .headers_mut()
        .insert("x-echo-method", parts.method.as_str().parse().unwrap());
    if let Some(value) = parts.headers.get("x-echo-cache-control") {
        response
            .headers_mut()
            .insert("cache-control", value.clone());
    }
    response
}

async fn status(Path(code): Path<u16>) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert("x-upstream", "yes".parse().unwrap());
    (
        StatusCode::from_u16(code).unwrap(),
        headers,
        format!("status {code}"),
    )
        .into_response()
}

/// Three chunks, half a second apart, so a test can tell streaming from buffering.
async fn slow_stream() -> Response {
    let body = stream::unfold(0u8, |i| async move {
        if i >= 3 {
            return None;
        }
        if i > 0 {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Some((
            Ok::<_, Infallible>(Bytes::from(format!("chunk{i}\n"))),
            i + 1,
        ))
    });
    Response::new(Body::from_stream(body))
}

/// A body of `n` bytes, for tests of the paid-body limit.
async fn big(Path(n): Path<usize>) -> Response {
    Response::new(Body::from(vec![b'x'; n]))
}

/// Response headers and one chunk, then a body that never ends.
async fn stall() -> Response {
    let first = stream::iter([Ok::<_, Infallible>(Bytes::from_static(b"chunk0\n"))]);
    Response::new(Body::from_stream(first.chain(stream::pending())))
}

/// Response headers and one chunk, then, a moment later, a body that fails.
async fn broken() -> Response {
    let first = stream::iter([Ok(Bytes::from_static(b"chunk0\n"))]);
    let failure = stream::once(async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        Err(std::io::Error::other("the upstream failed mid-body"))
    });
    Response::new(Body::from_stream(first.chain(failure)))
}

/// Starts the echo upstream on a free port.
pub async fn spawn_upstream() -> SocketAddr {
    let (addr, stop) = spawn_upstream_stoppable().await;
    // Dropping the handle would stop the server; it lives for the rest of the test process.
    std::mem::forget(stop);
    addr
}

/// Starts the echo upstream on a free port, with a handle that shuts it down.
pub async fn spawn_upstream_stoppable() -> (SocketAddr, oneshot::Sender<()>) {
    let (stop, stopped) = oneshot::channel::<()>();
    let router = Router::new()
        .route("/stream", get(slow_stream))
        .route("/status/{code}", any(status))
        .route("/big/{n}", get(big))
        .route("/paid/big/{n}", get(big))
        .route("/paid/stall", get(stall))
        .route("/paid/broken", get(broken))
        .fallback(echo);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap()
    });
    (addr, stop)
}

/// The gateway, serving in this process.
pub struct Gateway {
    pub addr: SocketAddr,
    pub admin_addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
}

impl Gateway {
    /// Starts the gateway with the given upstream and extra flags. The platform API is pointed at
    /// `platform_url` (a mock in tests) with a throwaway key.
    pub async fn spawn(upstream: &str, platform_url: &str, extra: &[&str]) -> Self {
        let mut args = vec![
            "radius-gateway".to_owned(),
            "--listen".to_owned(),
            "127.0.0.1:0".to_owned(),
            "--admin-listen".to_owned(),
            "127.0.0.1:0".to_owned(),
            "--upstream".to_owned(),
            upstream.to_owned(),
            "--platform-api-url".to_owned(),
            platform_url.to_owned(),
            "--platform-api-key".to_owned(),
            "sk_test_key".to_owned(),
            "--organization-id".to_owned(),
            "org_test".to_owned(),
            "--project-id".to_owned(),
            PROJECT_ID.to_owned(),
            "--startup-policy-wait".to_owned(),
            "5s".to_owned(),
            "--poll-interval".to_owned(),
            "1h".to_owned(),
        ];
        args.extend(extra.iter().map(|s| (*s).to_owned()));
        let config = Config::try_parse_from(args).unwrap();
        let app = App::bind(&config).await.unwrap();
        let addr = app.addr();
        let admin_addr = app.admin_addr();
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            app.serve(async {
                let _ = rx.await;
            })
            .await
            .unwrap();
        });
        Self {
            addr,
            admin_addr,
            shutdown: Some(tx),
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    pub fn admin_url(&self, path: &str) -> String {
        format!("http://{}{path}", self.admin_addr)
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

pub const PROJECT_ID: &str = "01a1c14b-cc9f-7033-92d3-bd51d003d97e";

pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}
