//! The pass-through proxy: requests the policy allows reach the upstream unchanged, and its
//! responses come back streaming.

mod common;

use std::time::{Duration, Instant};

use common::{Echo, Gateway, client, spawn_upstream};
use futures_util::StreamExt;

/// No platform answers here, so no policy loads; these tests pass every request through.
const PASS_THROUGH: &[&str] = &["--no-policy", "allow"];

#[tokio::test]
async fn forwards_the_request_and_rewrites_proxy_headers() {
    let upstream = spawn_upstream().await;
    let gateway = Gateway::spawn(
        &format!("http://{upstream}"),
        "http://127.0.0.1:9",
        PASS_THROUGH,
    )
    .await;

    let response = client()
        .post(gateway.url("/a/b?x=1&y=2"))
        .header("x-test", "1")
        .header("connection", "close, x-hop")
        .header("x-hop", "dropped")
        .header("payment-signature", "never-forwarded")
        .body("hello")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(response.headers().contains_key("x-request-id"));
    let echo: Echo = response.json().await.unwrap();

    assert_eq!(echo.method, "POST");
    assert_eq!(echo.path, "/a/b");
    assert_eq!(echo.query.as_deref(), Some("x=1&y=2"));
    assert_eq!(echo.body, "hello");
    assert_eq!(echo.headers["x-test"], "1");
    assert_eq!(echo.headers["host"], upstream.to_string());
    assert_eq!(echo.headers["x-forwarded-for"], "127.0.0.1");
    assert_eq!(echo.headers["x-forwarded-proto"], "http");
    assert_eq!(echo.headers["x-forwarded-host"], gateway.addr.to_string());
    for name in ["connection", "x-hop", "payment-signature"] {
        assert!(!echo.headers.contains_key(name), "{name} was forwarded");
    }
}

#[tokio::test]
async fn keeps_an_upstream_path_prefix() {
    let upstream = spawn_upstream().await;
    let gateway = Gateway::spawn(
        &format!("http://{upstream}/v1"),
        "http://127.0.0.1:9",
        PASS_THROUGH,
    )
    .await;
    let echo: Echo = client()
        .get(gateway.url("/tx?x=1"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(echo.path, "/v1/tx");
    assert_eq!(echo.query.as_deref(), Some("x=1"));
}

#[tokio::test]
async fn streams_the_upstream_response() {
    let upstream = spawn_upstream().await;
    let gateway = Gateway::spawn(
        &format!("http://{upstream}"),
        "http://127.0.0.1:9",
        PASS_THROUGH,
    )
    .await;

    let started = Instant::now();
    let response = client().get(gateway.url("/stream")).send().await.unwrap();
    let mut body = response.bytes_stream();
    let first = body.next().await.unwrap().unwrap();
    assert_eq!(first, "chunk0\n");
    assert!(
        started.elapsed() < Duration::from_millis(400),
        "first chunk took {:?}: the response was buffered",
        started.elapsed()
    );
    let mut rest = Vec::new();
    while let Some(chunk) = body.next().await {
        rest.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(rest, b"chunk1\nchunk2\n");
}

#[tokio::test]
async fn forwards_head_as_head() {
    let upstream = spawn_upstream().await;
    let gateway = Gateway::spawn(
        &format!("http://{upstream}"),
        "http://127.0.0.1:9",
        PASS_THROUGH,
    )
    .await;
    let response = client().head(gateway.url("/x")).send().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["x-echo-method"], "HEAD");
    assert_eq!(response.bytes().await.unwrap().len(), 0);
}

#[tokio::test]
async fn passes_upstream_statuses_through() {
    let upstream = spawn_upstream().await;
    let gateway = Gateway::spawn(
        &format!("http://{upstream}"),
        "http://127.0.0.1:9",
        PASS_THROUGH,
    )
    .await;
    let response = client()
        .get(gateway.url("/status/418"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 418);
    assert_eq!(response.headers()["x-upstream"], "yes");
    assert_eq!(response.text().await.unwrap(), "status 418");
}

#[tokio::test]
async fn answers_502_when_the_upstream_is_down() {
    // A listener that's dropped at once: the port is free, so connecting is refused.
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = closed.local_addr().unwrap();
    drop(closed);
    let gateway = Gateway::spawn(
        &format!("http://{addr}"),
        "http://127.0.0.1:9",
        PASS_THROUGH,
    )
    .await;
    let response = client().get(gateway.url("/x")).send().await.unwrap();
    assert_eq!(response.status(), 502);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["code"], "upstream_unavailable");
}

#[tokio::test]
async fn admin_listener_answers_health() {
    let upstream = spawn_upstream().await;
    let gateway = Gateway::spawn(
        &format!("http://{upstream}"),
        "http://127.0.0.1:9",
        PASS_THROUGH,
    )
    .await;
    let response = client()
        .get(gateway.admin_url("/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "ok");
}
