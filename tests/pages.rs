//! The payment page a browser gets on a 402, its assets, and the pages directory that
//! customizes them.

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::{Gateway, PROJECT_ID, client, spawn_upstream};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SBC: &str = "0x33ad9e4BD16B69B5BFdED37D8B5D9fF9aba014Fb";
const PAY_TO: &str = "0x4373dD700774F8C3f649AC58B7EDCC112785Fe6e";
const BROWSER: &str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

/// A policy that charges 0.01 SBC for everything (a catch-all rule), with `description`.
fn policy(facilitator: &str, description: &str) -> Value {
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
            "id": "charge",
            "match": {},
            "action": {
                "type": "charge",
                "price": "0.01",
                "description": description,
                "accepts": [{
                    "scheme": "exact",
                    "network": "eip155:72344",
                    "asset": SBC,
                    "decimals": 6,
                    "amount": "10000",
                    "pay_to": PAY_TO,
                    "facilitator": facilitator
                }]
            }
        }]
    })
}

struct World {
    upstream: std::net::SocketAddr,
    platform: MockServer,
    facilitator: MockServer,
}

impl World {
    async fn start(description: &str) -> Self {
        let upstream = spawn_upstream().await;
        let platform = MockServer::start().await;
        let facilitator = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/supported"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "kinds": [{
                    "x402Version": 2, "scheme": "exact", "network": "eip155:72344", "asset": SBC,
                    "extra": { "assetTransferMethod": "eip3009", "name": "Stable Coin", "version": "1" }
                }],
                "extensions": [],
                "signers": {}
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
                    .set_body_json(policy(&facilitator.uri(), description)),
            )
            .mount(&platform)
            .await;
        Self {
            upstream,
            platform,
            facilitator,
        }
    }

    async fn gateway(&self, extra: &[&str]) -> Gateway {
        let mut args = vec!["--public-url", "https://api.example.com"];
        args.extend_from_slice(extra);
        Gateway::spawn(
            &format!("http://{}", self.upstream),
            &self.platform.uri(),
            &args,
        )
        .await
    }

    async fn verify_calls(&self) -> usize {
        self.facilitator
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path() == "/verify")
            .count()
    }
}

fn decode(header: &str) -> Value {
    serde_json::from_slice(&STANDARD.decode(header).unwrap()).unwrap()
}

/// The challenge embedded in the page, as JSON.
fn embedded_challenge(html: &str) -> Value {
    let start = html
        .find(r#"<script type="application/json" id="x402-challenge">"#)
        .expect("the challenge block");
    let rest = &html[start..];
    let open = rest.find('>').unwrap() + 1;
    let close = rest.find("</script>").unwrap();
    let json = rest[open..close]
        .replace("<\\/", "</")
        .replace("<\\!--", "<!--");
    serde_json::from_str(&json).expect("valid JSON in the block")
}

#[tokio::test]
async fn browsers_get_the_page_and_agents_the_json() {
    let world = World::start("Reports, per call").await;
    let gateway = world.gateway(&[]).await;

    let response = client()
        .get(gateway.url("/reports/today?format=csv"))
        .header("accept", BROWSER)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 402);
    let headers = response.headers().clone();
    assert_eq!(headers["content-type"], "text/html; charset=utf-8");
    assert_eq!(headers["vary"], "Accept");
    assert_eq!(headers["cache-control"], "no-store");
    assert!(
        headers["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("script-src 'self'")
    );
    let challenge = decode(headers["payment-required"].to_str().unwrap());
    let html = response.text().await.unwrap();
    assert_eq!(
        embedded_challenge(&html),
        challenge,
        "the page embeds the header's challenge"
    );
    let network_label = domain::pricing::catalog::network("eip155:72344")
        .expect("the catalog knows Radius testnet")
        .label;
    for expected in [
        "<h1>Payment required</h1>",
        "Reports, per call",
        "0.01 SBC",
        network_label,
        PAY_TO,
        "https://api.example.com/reports/today?format=csv",
        "radius-cli wallet pay get &#39;https://api.example.com/reports/today?format=csv&#39; --threshold 0.01 -y",
        "https://api.example.com/_radius/assets/style.css",
        "https://api.example.com/_radius/assets/pay.js",
    ] {
        assert!(html.contains(expected), "missing {expected:?} in:\n{html}");
    }
    assert!(
        !html.contains("class=\"brand\""),
        "no brand unless configured"
    );
    assert!(!html.contains("{{"), "every placeholder is filled");

    for (accept, html) in [
        (None, false),
        (Some("*/*"), false),
        (Some("application/json"), false),
        (Some("text/html;q=0.5, application/json"), false),
        (Some("text/*"), true),
    ] {
        let mut request = client().get(gateway.url("/x"));
        if let Some(accept) = accept {
            request = request.header("accept", accept);
        }
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), 402, "{accept:?}");
        let content_type = response.headers()["content-type"]
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(content_type.starts_with("text/html"), html, "{accept:?}");
        assert_eq!(response.headers()["vary"], "Accept", "{accept:?}");
        if !html {
            let body: Value = response.json().await.unwrap();
            assert_eq!(body["x402Version"], 2, "{accept:?}");
        }
    }
    assert_eq!(world.verify_calls().await, 0);
}

#[tokio::test]
async fn the_page_escapes_what_the_policy_and_request_say() {
    let world = World::start("Reports <b>per call</b></script><!--").await;
    let gateway = world
        .gateway(&[
            "--brand",
            "Acme <Data>",
            "--brand-url",
            "https://acme.example/?a=1&b=2",
        ])
        .await;

    let response = client()
        .get(gateway.url("/x?q=%22a%22&b=<c>"))
        .header("accept", BROWSER)
        .send()
        .await
        .unwrap();
    let html = response.text().await.unwrap();
    assert!(html.contains("Reports &lt;b&gt;per call&lt;/b&gt;&lt;/script&gt;&lt;!--"));
    assert!(!html.contains("<b>per call</b>"));
    assert!(html.contains(
        r#"<a href="https://acme.example/?a=1&amp;b=2" rel="noopener">Acme &lt;Data&gt;</a>"#
    ));
    assert!(
        html.contains("?q=%22a%22&amp;b=%3Cc%3E") || html.contains("?q=%22a%22&amp;b=&lt;c&gt;"),
        "{html}"
    );
    let challenge = embedded_challenge(&html);
    assert_eq!(
        challenge["resource"]["description"],
        "Reports <b>per call</b></script><!--"
    );
    assert!(
        html.contains("<\\/b><\\/script><\\!--"),
        "the JSON block can't close the script"
    );
}

#[tokio::test]
async fn assets_are_served_before_the_policy_and_cached() {
    let world = World::start("d").await;
    let gateway = world.gateway(&[]).await;

    let css = client()
        .get(gateway.url("/_radius/assets/style.css"))
        .send()
        .await
        .unwrap();
    assert_eq!(css.status(), 200);
    assert_eq!(css.headers()["content-type"], "text/css; charset=utf-8");
    assert_eq!(css.headers()["cache-control"], "public, max-age=300");
    assert_eq!(css.headers()["x-content-type-options"], "nosniff");
    let etag = css.headers()["etag"].to_str().unwrap().to_owned();
    assert!(css.text().await.unwrap().contains(".card"));

    let unchanged = client()
        .get(gateway.url("/_radius/assets/style.css"))
        .header("if-none-match", &etag)
        .send()
        .await
        .unwrap();
    assert_eq!(unchanged.status(), 304);

    let js = client()
        .get(gateway.url("/_radius/assets/pay.js"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        js.headers()["content-type"],
        "text/javascript; charset=utf-8"
    );

    let missing = client()
        .get(gateway.url("/_radius/assets/nope.css"))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);
    let posted = client()
        .post(gateway.url("/_radius/assets/style.css"))
        .send()
        .await
        .unwrap();
    assert_eq!(posted.status(), 405);
    // The catch-all charge rule never saw any of it.
    assert_eq!(world.verify_calls().await, 0);
}

#[tokio::test]
async fn a_pages_dir_overrides_files_one_by_one() {
    let dir = std::env::temp_dir().join(format!("radius-gateway-pages-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(dir.join("assets")).unwrap();
    std::fs::write(
        dir.join("402.html"),
        "<p>custom {{price}} {{ description }} {{assets_base}} {{nothing_known}}</p>",
    )
    .unwrap();
    std::fs::write(dir.join("assets/extra.css"), "body{}").unwrap();
    std::fs::write(dir.join("stray.txt"), "ignored").unwrap();

    let world = World::start("Thing").await;
    let gateway = world.gateway(&["--pages-dir", dir.to_str().unwrap()]).await;

    let page = client()
        .get(gateway.url("/x"))
        .header("accept", BROWSER)
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), 402);
    assert!(page.headers().contains_key("payment-required"));
    assert_eq!(
        page.text().await.unwrap(),
        "<p>custom 0.01 SBC Thing https://api.example.com/_radius/assets </p>"
    );
    let extra = client()
        .get(gateway.url("/_radius/assets/extra.css"))
        .send()
        .await
        .unwrap();
    assert_eq!(extra.status(), 200);
    assert_eq!(extra.text().await.unwrap(), "body{}");
    let default = client()
        .get(gateway.url("/_radius/assets/style.css"))
        .send()
        .await
        .unwrap();
    assert_eq!(default.status(), 200, "files not overridden stay built in");
    let stray = client()
        .get(gateway.url("/_radius/assets/../stray.txt"))
        .send()
        .await
        .unwrap();
    assert_ne!(stray.status(), 200);
    std::fs::remove_dir_all(&dir).unwrap();
}
