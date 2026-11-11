//! Tickets: a browser that paid from the payment page gets the purchase on the reload that
//! follows, once, without paying again.

mod common;

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::{Echo, Gateway, PROJECT_ID, client, spawn_upstream_stoppable};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SBC: &str = "0x33ad9e4BD16B69B5BFdED37D8B5D9fF9aba014Fb";
const PAY_TO: &str = "0x4373dD700774F8C3f649AC58B7EDCC112785Fe6e";
const PAYER: &str = "0x857b06519E91e3A54538791bDbb0E22373e36b66";

fn policy(facilitator: &str) -> Value {
    json!({
        "schema": "radius.policy/0.1",
        "version": 1,
        "project_id": PROJECT_ID,
        "generated_at": "2026-11-10T14:16:13Z",
        "mode": "test",
        "defaults": {
            "unmatched": "allow",
            "failure": { "counter_error": "within", "no_policy": "allow" },
            "client_ip": "remote_addr",
            "headers": { "ratelimit": true, "retry_after": true }
        },
        "rules": [{
            "uid": uuid::Uuid::new_v4(),
            "id": "paid/charge",
            "match": { "endpoint": { "slug": "paid", "methods": [], "path": "/paid/*" } },
            "action": {
                "type": "charge",
                "price": "0.01",
                "description": "Paid endpoints, per call",
                "accepts": [{
                    "scheme": "exact", "network": "eip155:72344", "asset": SBC, "decimals": 6,
                    "amount": "10000", "pay_to": PAY_TO, "facilitator": facilitator
                }]
            }
        }]
    })
}

struct World {
    upstream: std::net::SocketAddr,
    stop_upstream: Option<tokio::sync::oneshot::Sender<()>>,
    platform: MockServer,
    facilitator: MockServer,
}

impl World {
    async fn start() -> Self {
        let (upstream, stop_upstream) = spawn_upstream_stoppable().await;
        let platform = MockServer::start().await;
        let facilitator = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/supported"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&facilitator)
            .await;
        Mock::given(method("POST"))
            .and(path("/verify"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "isValid": true })))
            .mount(&facilitator)
            .await;
        Mock::given(method("POST"))
            .and(path("/settle"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true, "transaction": "0xtx", "network": "eip155:72344", "payer": PAYER
            })))
            .mount(&facilitator)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/organizations/org_test/projects/{PROJECT_ID}/policy/compiled"
            )))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"1\"")
                    .set_body_json(policy(&facilitator.uri())),
            )
            .mount(&platform)
            .await;
        Self {
            upstream,
            stop_upstream: Some(stop_upstream),
            platform,
            facilitator,
        }
    }

    async fn gateway(&self, extra: &[&str]) -> Gateway {
        Gateway::spawn(
            &format!("http://{}", self.upstream),
            &self.platform.uri(),
            extra,
        )
        .await
    }

    async fn calls(&self, endpoint: &str) -> usize {
        self.facilitator
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path() == endpoint)
            .count()
    }
}

fn signature(nonce: &str) -> String {
    let payload = json!({
        "x402Version": 2,
        "accepted": {
            "scheme": "exact", "network": "eip155:72344", "amount": "10000", "asset": SBC,
            "payTo": PAY_TO, "maxTimeoutSeconds": 60,
            "extra": { "assetTransferMethod": "eip3009", "name": "Stable Coin", "version": "1" }
        },
        "payload": {
            "signature": "0xsig",
            "authorization": {
                "from": PAYER, "to": PAY_TO, "value": "10000",
                "validAfter": "1760000000", "validBefore": "1760000600", "nonce": nonce
            }
        }
    });
    STANDARD.encode(serde_json::to_vec(&payload).unwrap())
}

/// Pays `url` the way the page does, and returns the response.
async fn pay_from_page(gateway: &Gateway, url: &str, nonce: &str) -> reqwest::Response {
    client()
        .get(gateway.url(url))
        .header("payment-signature", signature(nonce))
        .header("accept", "application/json")
        .header("radius-page", "1")
        .send()
        .await
        .unwrap()
}

/// The `radius_ticket` cookie's value and attributes from a paid response.
fn ticket_cookie(response: &reqwest::Response) -> Option<String> {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with("radius_ticket="))
        .map(str::to_owned)
}

fn ticket_id(cookie: &str) -> String {
    cookie
        .trim_start_matches("radius_ticket=")
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

async fn reload(gateway: &Gateway, url: &str, cookie: &str) -> reqwest::Response {
    client()
        .get(gateway.url(url))
        .header("cookie", cookie)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn a_page_payment_gets_a_ticket_and_the_reload_is_delivered_once() {
    let world = World::start().await;
    let gateway = world
        .gateway(&["--public-url", "https://api.example.com"])
        .await;

    let paid = pay_from_page(&gateway, "/paid/report?day=1", "0x01").await;
    assert_eq!(paid.status(), 200);
    assert!(paid.headers().contains_key("payment-response"));
    let cookie = ticket_cookie(&paid).expect("a ticket cookie");
    for attribute in [
        "; Path=/paid/report;",
        "; Max-Age=60;",
        "; HttpOnly;",
        "; SameSite=Strict",
        "; Secure",
    ] {
        assert!(cookie.contains(attribute), "{cookie} lacks {attribute}");
    }
    let id = ticket_id(&cookie);
    assert_eq!(id.len(), 32);

    // The reload: delivered, nothing verified or settled, the cookie stripped and cleared.
    let delivered = reload(
        &gateway,
        "/paid/report?day=1",
        &format!("session=abc; radius_ticket={id}"),
    )
    .await;
    assert_eq!(delivered.status(), 200);
    assert!(!delivered.headers().contains_key("payment-response"));
    let cleared = ticket_cookie(&delivered).expect("the cookie is cleared");
    assert!(
        cleared.starts_with("radius_ticket=;") && cleared.contains("Max-Age=0"),
        "{cleared}"
    );
    let echo: Echo = delivered.json().await.unwrap();
    assert_eq!(
        echo.headers.get("cookie").map(String::as_str),
        Some("session=abc")
    );
    assert_eq!(echo.path, "/paid/report");
    assert_eq!(world.calls("/verify").await, 1);
    assert_eq!(world.calls("/settle").await, 1);

    // A second reload with the same ticket pays again.
    let again = reload(
        &gateway,
        "/paid/report?day=1",
        &format!("radius_ticket={id}"),
    )
    .await;
    assert_eq!(again.status(), 402);
}

#[tokio::test]
async fn tickets_are_bound_to_the_method_and_url() {
    let world = World::start().await;
    let gateway = world.gateway(&[]).await;
    let paid = pay_from_page(&gateway, "/paid/x?a=1", "0x02").await;
    assert_eq!(paid.status(), 200);
    let cookie = ticket_cookie(&paid).unwrap();
    assert!(
        !cookie.contains("Secure"),
        "no Secure flag over plain http: {cookie}"
    );
    let id = ticket_id(&cookie);

    // Another query string, another path, another method: not this ticket, and it survives.
    for url in ["/paid/x?a=2", "/paid/x", "/paid/y?a=1"] {
        let response = reload(&gateway, url, &format!("radius_ticket={id}")).await;
        assert_eq!(response.status(), 402, "{url}");
    }
    let posted = client()
        .post(gateway.url("/paid/x?a=1"))
        .header("cookie", format!("radius_ticket={id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(posted.status(), 402);

    let delivered = reload(&gateway, "/paid/x?a=1", &format!("radius_ticket={id}")).await;
    assert_eq!(delivered.status(), 200, "the mismatches didn't consume it");
    // HEAD is delivered as GET.
    let paid = pay_from_page(&gateway, "/paid/h", "0x03").await;
    let id = ticket_id(&ticket_cookie(&paid).unwrap());
    let head = client()
        .head(gateway.url("/paid/h"))
        .header("cookie", format!("radius_ticket={id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(head.status(), 200);
    assert_eq!(world.calls("/settle").await, 2);
}

#[tokio::test]
async fn only_page_payments_get_tickets() {
    let world = World::start().await;
    let gateway = world.gateway(&[]).await;

    let plain = client()
        .get(gateway.url("/paid/x"))
        .header("payment-signature", signature("0x04"))
        .send()
        .await
        .unwrap();
    assert_eq!(plain.status(), 200);
    assert!(ticket_cookie(&plain).is_none(), "no marker, no ticket");

    let posted = client()
        .post(gateway.url("/paid/x"))
        .header("payment-signature", signature("0x05"))
        .header("radius-page", "1")
        .send()
        .await
        .unwrap();
    assert_eq!(posted.status(), 200);
    assert!(ticket_cookie(&posted).is_none(), "a POST can't be reloaded");
}

#[tokio::test]
async fn tickets_expire() {
    let world = World::start().await;
    let gateway = world.gateway(&["--ticket-ttl", "1s"]).await;
    let paid = pay_from_page(&gateway, "/paid/x", "0x06").await;
    let cookie = ticket_cookie(&paid).unwrap();
    assert!(cookie.contains("Max-Age=1;"), "{cookie}");
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let late = reload(
        &gateway,
        "/paid/x",
        &format!("radius_ticket={}", ticket_id(&cookie)),
    )
    .await;
    assert_eq!(late.status(), 402);
}

#[tokio::test]
async fn an_upstream_failure_on_the_reload_keeps_the_ticket() {
    let mut world = World::start().await;
    let gateway = world.gateway(&[]).await;
    let paid = pay_from_page(&gateway, "/paid/x", "0x07").await;
    assert_eq!(paid.status(), 200);
    let id = ticket_id(&ticket_cookie(&paid).unwrap());

    world.stop_upstream.take().unwrap().send(()).unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    for attempt in 0..2 {
        let response = reload(&gateway, "/paid/x", &format!("radius_ticket={id}")).await;
        assert_eq!(
            response.status(),
            502,
            "attempt {attempt}: nothing delivered"
        );
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["code"], "upstream_unavailable", "attempt {attempt}");
    }
    assert_eq!(
        world.calls("/verify").await,
        1,
        "the ticket, not a payment, was tried"
    );
}
