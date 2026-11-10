//! Fetching the policy from a mock platform and enforcing its allow, deny and limit rules.

mod common;

use common::{Echo, Gateway, PROJECT_ID, client, spawn_upstream};
use serde_json::{Value, json};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn policy_path() -> String {
    format!("/organizations/org_test/projects/{PROJECT_ID}/policy/compiled")
}

/// A compiled policy document with the given defaults overrides and rules.
fn document(version: u64, unmatched: &str, rules: Value) -> Value {
    json!({
        "schema": "radius.policy/0.1",
        "version": version,
        "project_id": PROJECT_ID,
        "generated_at": "2026-11-10T14:16:13Z",
        "mode": "test",
        "defaults": {
            "unmatched": unmatched,
            "failure": { "counter_error": "within", "no_policy": "allow" },
            "client_ip": "remote_addr",
            "headers": { "ratelimit": true, "retry_after": true }
        },
        "rules": rules
    })
}

fn rule(id: &str, matcher: Value, action: Value) -> Value {
    json!({
        "uid": uuid::Uuid::new_v4(),
        "id": id,
        "match": matcher,
        "action": action
    })
}

fn endpoint(methods: &[&str], path: &str) -> Value {
    json!({ "endpoint": { "slug": "ep", "methods": methods, "path": path } })
}

fn deny(status: u16, code: &str) -> Value {
    json!({ "type": "deny", "status": status, "code": code })
}

fn serve(version: u64, document: &Value) -> Mock {
    Mock::given(method("GET"))
        .and(path(policy_path()))
        .and(header("authorization", "Bearer sk_test_key"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", format!("\"{version}\"").as_str())
                .set_body_json(document),
        )
}

async fn refresh(gateway: &Gateway) -> Value {
    client()
        .post(gateway.admin_url("/policy/refresh"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn loads_the_policy_and_asks_conditionally_afterwards() {
    let upstream = spawn_upstream().await;
    let platform = MockServer::start().await;
    serve(1, &document(1, "allow", json!([])))
        .mount(&platform)
        .await;
    Mock::given(method("GET"))
        .and(path(policy_path()))
        .and(header("if-none-match", "\"1\""))
        .respond_with(ResponseTemplate::new(304))
        .with_priority(1)
        .mount(&platform)
        .await;

    let gateway = Gateway::spawn(&format!("http://{upstream}"), &platform.uri(), &[]).await;
    let status: Value = client()
        .get(gateway.admin_url("/policy"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["loaded"], true);
    assert_eq!(status["version"], 1);
    assert_eq!(status["fetch"]["attempts"], 1);

    let refreshed = refresh(&gateway).await;
    assert_eq!(refreshed["refresh"], "NotModified");
    assert_eq!(refreshed["version"], 1);
    let requests = platform.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].headers.get("if-none-match").is_none());
    assert_eq!(requests[1].headers["if-none-match"], "\"1\"");

    let ready = client()
        .get(gateway.admin_url("/readyz"))
        .send()
        .await
        .unwrap();
    assert_eq!(ready.status(), 200);
}

#[tokio::test]
async fn replaces_the_policy_only_with_a_newer_version() {
    let upstream = spawn_upstream().await;
    let platform = MockServer::start().await;
    let v2 = serve(2, &document(2, "allow", json!([])))
        .mount_as_scoped(&platform)
        .await;
    let gateway = Gateway::spawn(&format!("http://{upstream}"), &platform.uri(), &[]).await;
    drop(v2);

    serve(1, &document(1, "deny", json!([])))
        .mount(&platform)
        .await;
    let refreshed = refresh(&gateway).await;
    assert_eq!(refreshed["version"], 2);
    assert!(
        refreshed["refresh"]
            .as_str()
            .unwrap()
            .starts_with("Ignored")
    );
    // Still version 2: unmatched requests pass.
    let response = client().get(gateway.url("/x")).send().await.unwrap();
    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn keeps_the_policy_when_the_next_document_is_bad() {
    let upstream = spawn_upstream().await;
    let platform = MockServer::start().await;
    let good = serve(1, &document(1, "deny", json!([])))
        .mount_as_scoped(&platform)
        .await;
    let gateway = Gateway::spawn(&format!("http://{upstream}"), &platform.uri(), &[]).await;
    drop(good);

    let mut unknown = document(5, "allow", json!([]));
    unknown["schema"] = "radius.policy/9.9".into();
    let bad = serve(5, &unknown).mount_as_scoped(&platform).await;
    let refreshed = refresh(&gateway).await;
    assert_eq!(refreshed["version"], 1);
    assert!(
        refreshed["fetch"]["last_error"]
            .as_str()
            .unwrap()
            .contains("radius.policy/9.9"),
        "{refreshed}"
    );
    drop(bad);

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&platform)
        .await;
    let refreshed = refresh(&gateway).await;
    assert_eq!(refreshed["version"], 1);
    assert!(
        refreshed["fetch"]["last_error"]
            .as_str()
            .unwrap()
            .contains("500")
    );

    // Version 1 denies unmatched requests, and still does.
    let response = client().get(gateway.url("/x")).send().await.unwrap();
    assert_eq!(response.status(), 403);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["code"], "no_matching_rule");
}

#[tokio::test]
async fn enforces_allow_and_deny_rules_in_order() {
    let upstream = spawn_upstream().await;
    let platform = MockServer::start().await;
    let rules = json!([
        rule(
            "open",
            endpoint(&["GET"], "/public/*"),
            json!({ "type": "allow" })
        ),
        rule(
            "blocked",
            endpoint(&[], "/admin/:anything"),
            deny(451, "blocked")
        ),
    ]);
    serve(1, &document(1, "deny", rules)).mount(&platform).await;
    let gateway = Gateway::spawn(&format!("http://{upstream}"), &platform.uri(), &[]).await;

    let open = client()
        .get(gateway.url("/public/a/b?q=1"))
        .send()
        .await
        .unwrap();
    assert_eq!(open.status(), 200);
    let echo: Echo = open.json().await.unwrap();
    assert_eq!(echo.path, "/public/a/b");

    let posted = client()
        .post(gateway.url("/public/a"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        posted.status(),
        403,
        "POST isn't in the allow rule's methods"
    );

    let blocked = client()
        .get(gateway.url("/admin/users"))
        .send()
        .await
        .unwrap();
    assert_eq!(blocked.status(), 451);
    let body: Value = blocked.json().await.unwrap();
    assert_eq!(body["code"], "blocked");
    assert_eq!(body["message"], "denied by policy rule \"blocked\"");

    // HEAD is evaluated as GET, so it passes where GET passes.
    let head = client()
        .head(gateway.url("/public/a"))
        .send()
        .await
        .unwrap();
    assert_eq!(head.status(), 200);
    assert_eq!(head.headers()["x-echo-method"], "HEAD");
}

#[tokio::test]
async fn counts_free_quotas_and_rate_limits() {
    let upstream = spawn_upstream().await;
    let platform = MockServer::start().await;
    let mut freemium = rule("freemium", endpoint(&[], "/tx/:id"), deny(402, "paid_only"));
    freemium["free_quota"] = json!({ "key": "ip", "quota": 2, "window_s": 3600 });
    let mut limited = rule(
        "limited",
        endpoint(&[], "/search"),
        json!({ "type": "allow" }),
    );
    limited["rate_limit"] = json!({ "key": "global", "quota": 1, "window_s": 3600 });
    serve(1, &document(1, "allow", json!([freemium, limited])))
        .mount(&platform)
        .await;
    let gateway = Gateway::spawn(&format!("http://{upstream}"), &platform.uri(), &[]).await;

    let first = client().get(gateway.url("/tx/1")).send().await.unwrap();
    assert_eq!(first.status(), 200);
    assert_eq!(first.headers()["ratelimit-limit"], "2");
    assert_eq!(first.headers()["ratelimit-remaining"], "1");
    assert!(first.headers().contains_key("ratelimit-reset"));
    let second = client().get(gateway.url("/tx/2")).send().await.unwrap();
    assert_eq!(second.status(), 200);
    assert_eq!(second.headers()["ratelimit-remaining"], "0");
    let third = client().get(gateway.url("/tx/3")).send().await.unwrap();
    assert_eq!(third.status(), 402);
    assert_eq!(third.headers()["ratelimit-remaining"], "0");
    assert!(third.headers().contains_key("retry-after"));
    let body: Value = third.json().await.unwrap();
    assert_eq!(body["code"], "paid_only");

    let ok = client().get(gateway.url("/search")).send().await.unwrap();
    assert_eq!(ok.status(), 200);
    let over = client().get(gateway.url("/search")).send().await.unwrap();
    assert_eq!(over.status(), 429);
    assert_eq!(over.headers()["ratelimit-limit"], "1");
    assert!(over.headers().contains_key("retry-after"));
    let body: Value = over.json().await.unwrap();
    assert_eq!(body["code"], "rate_limited");
}

#[tokio::test]
async fn no_policy_is_the_gateways_own_setting() {
    let upstream = spawn_upstream().await;
    let platform = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&platform)
        .await;

    let denying = Gateway::spawn(
        &format!("http://{upstream}"),
        &platform.uri(),
        &["--no-policy", "deny"],
    )
    .await;
    let response = client().get(denying.url("/x")).send().await.unwrap();
    assert_eq!(response.status(), 503);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["code"], "policy_unavailable");
    let ready = client()
        .get(denying.admin_url("/readyz"))
        .send()
        .await
        .unwrap();
    assert_eq!(ready.status(), 503);

    let allowing = Gateway::spawn(&format!("http://{upstream}"), &platform.uri(), &[]).await;
    let response = client().get(allowing.url("/x")).send().await.unwrap();
    assert_eq!(response.status(), 200);
    let ready = client()
        .get(allowing.admin_url("/readyz"))
        .send()
        .await
        .unwrap();
    assert_eq!(ready.status(), 200);
}

#[tokio::test]
async fn refuses_paths_whose_encoding_changes_the_rule() {
    let upstream = spawn_upstream().await;
    let platform = MockServer::start().await;
    let rules = json!([
        rule("hello", endpoint(&[], "/hello"), deny(403, "no_hello")),
        rule(
            "files",
            endpoint(&[], "/files/:name"),
            json!({ "type": "allow" })
        ),
    ]);
    serve(1, &document(1, "allow", rules))
        .mount(&platform)
        .await;
    let gateway = Gateway::spawn(&format!("http://{upstream}"), &platform.uri(), &[]).await;

    let ambiguous = client().get(gateway.url("/hell%6F")).send().await.unwrap();
    assert_eq!(ambiguous.status(), 400);
    let body: Value = ambiguous.json().await.unwrap();
    assert_eq!(body["code"], "ambiguous_path");

    let fine = client()
        .get(gateway.url("/files/caf%C3%A9"))
        .send()
        .await
        .unwrap();
    assert_eq!(fine.status(), 200);
    let echo: Echo = fine.json().await.unwrap();
    assert_eq!(
        echo.path, "/files/caf%C3%A9",
        "the path is forwarded as sent"
    );
}

#[tokio::test]
#[ignore = "forwards every request, paid routes included, until the first policy loads"]
async fn refuses_everything_before_the_first_policy_by_default() {
    let upstream = spawn_upstream().await;
    let platform = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&platform)
        .await;

    let gateway = Gateway::spawn(&format!("http://{upstream}"), &platform.uri(), &[]).await;
    for route in ["/x", "/paid/report"] {
        let response = client().get(gateway.url(route)).send().await.unwrap();
        assert_eq!(response.status(), 503, "{route}");
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["code"], "policy_unavailable", "{route}");
    }
}

#[tokio::test]
#[ignore = "after a failed first fetch, waits a whole POLL_INTERVAL before fetching again"]
async fn retries_a_failed_first_fetch_soon() {
    let upstream = spawn_upstream().await;
    let platform = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&platform)
        .await;
    serve(3, &document(3, "deny", json!([])))
        .mount(&platform)
        .await;

    let gateway = Gateway::spawn(
        &format!("http://{upstream}"),
        &platform.uri(),
        &["--no-policy", "deny"],
    )
    .await;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let ready = client()
            .get(gateway.admin_url("/readyz"))
            .send()
            .await
            .unwrap();
        if ready.status() == 200 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no policy 5s after a failed first fetch, under a 1h poll interval"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let response = client().get(gateway.url("/x")).send().await.unwrap();
    assert_eq!(response.status(), 403);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["code"], "no_matching_rule");
    // Once a policy is in force, the next fetch waits for the interval again.
    tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
    assert_eq!(platform.received_requests().await.unwrap().len(), 2);
}
