//! The x402 handshake for `charge` rules: the challenge, then verify, forward and settle.

mod common;

use std::str::FromStr;
use std::time::Duration;

use alloy_primitives::U256;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use common::{Echo, Gateway, PROJECT_ID, client, spawn_upstream};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SBC: &str = "0x33ad9e4BD16B69B5BFdED37D8B5D9fF9aba014Fb";
const PAY_TO: &str = "0x4373dD700774F8C3f649AC58B7EDCC112785Fe6e";
const PAYER: &str = "0x857b06519E91e3A54538791bDbb0E22373e36b66";

fn policy_path() -> String {
    format!("/organizations/org_test/projects/{PROJECT_ID}/policy/compiled")
}

/// A policy that charges 0.01 SBC for everything under `/paid/` and lets the rest through.
fn charging_policy(facilitator: &str) -> Value {
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

/// What the Radius testnet facilitator's `/supported` says today.
fn radius_supported() -> Value {
    let kind = |transfer_method: &str| {
        json!({
            "x402Version": 2, "scheme": "exact", "network": "eip155:72344", "asset": SBC,
            "extra": { "assetTransferMethod": transfer_method, "name": "Stable Coin", "version": "1" }
        })
    };
    json!({
        "kinds": [kind("eip3009"), kind("permit2")],
        "extensions": ["eip2612GasSponsoring"],
        "signers": {}
    })
}

impl World {
    async fn start() -> Self {
        Self::start_with(Some(radius_supported())).await
    }

    /// `supported` is what the facilitator's `/supported` answers; none answers 404.
    async fn start_with(supported: Option<Value>) -> Self {
        let upstream = spawn_upstream().await;
        let platform = MockServer::start().await;
        let facilitator = MockServer::start().await;
        if let Some(supported) = supported {
            Mock::given(method("GET"))
                .and(path("/supported"))
                .respond_with(ResponseTemplate::new(200).set_body_json(supported))
                .mount(&facilitator)
                .await;
        }
        Mock::given(method("GET"))
            .and(path(policy_path()))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("etag", "\"1\"")
                    .set_body_json(charging_policy(&facilitator.uri())),
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

    async fn verify_answers(&self, status: u16, body: Value) {
        Mock::given(method("POST"))
            .and(path("/verify"))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .mount(&self.facilitator)
            .await;
    }

    async fn settle_answers(&self, status: u16, body: Value) {
        Mock::given(method("POST"))
            .and(path("/settle"))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .mount(&self.facilitator)
            .await;
    }

    async fn calls(&self, endpoint: &str) -> usize {
        self.facilitator
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.url.path() == endpoint)
            .count()
    }
}

fn decode(header: &str) -> Value {
    serde_json::from_slice(&STANDARD.decode(header).unwrap()).unwrap()
}

/// The `accepts[0]` the challenge offers, as a buyer would echo it back.
fn accepted() -> Value {
    json!({
        "scheme": "exact",
        "network": "eip155:72344",
        "amount": "10000",
        "asset": SBC,
        "payTo": PAY_TO,
        "maxTimeoutSeconds": 60,
        "extra": { "assetTransferMethod": "permit2", "name": "Stable Coin", "version": "1" }
    })
}

fn payload(accepted: Value, nonce: &str, signature: &str) -> Value {
    json!({
        "x402Version": 2,
        "accepted": accepted,
        "payload": {
            "signature": signature,
            "authorization": {
                "from": PAYER,
                "to": PAY_TO,
                "value": "10000",
                "validAfter": "1760000000",
                "validBefore": "1760000600",
                "nonce": nonce
            }
        }
    })
}

fn encode(value: &Value) -> String {
    STANDARD.encode(serde_json::to_vec(value).unwrap())
}

fn settled() -> Value {
    json!({ "success": true, "transaction": "0xtx", "network": "eip155:72344", "payer": PAYER })
}

/// The Permit2 contract, the spender of the EIP-2612 permit the gas-sponsoring extension carries.
const PERMIT2: &str = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
/// x402's Permit2 proxy, the spender the buyer's Permit2 signature names.
const PERMIT2_PROXY: &str = "0x402085c248EeA27D92E8b30b2C58ed07f9E20001";
const SIGNATURE: &str = "0x2d6a7588d6acca505cbf0d9a4a227e0c52c6c34008c8e8986a1283259764173608a2ce6496642e377d6da8dbbf5836e9bd15092f9ecab05ded3d6293af148b571c";

/// A Permit2 payment for `accepted()`, shaped as the x402 spec's `exact` on EVM gives it, with
/// the EIP-2612 permit for Permit2 that `eip2612GasSponsoring` adds. `nonce` is decimal.
fn permit2_payload(nonce: &str) -> Value {
    json!({
        "x402Version": 2,
        "accepted": accepted(),
        "payload": {
            "signature": SIGNATURE,
            "permit2Authorization": {
                "permitted": { "token": SBC, "amount": "10000" },
                "from": PAYER,
                "spender": PERMIT2_PROXY,
                "nonce": nonce,
                "deadline": "1760000600",
                "witness": { "to": PAY_TO, "validAfter": "1760000000" }
            }
        },
        "extensions": {
            "eip2612GasSponsoring": {
                "info": {
                    "from": PAYER,
                    "asset": SBC,
                    "spender": PERMIT2,
                    "amount": U256::MAX.to_string(),
                    "nonce": "0",
                    "deadline": "1760000600",
                    "signature": SIGNATURE,
                    "version": "1"
                }
            }
        }
    })
}

/// `0x` followed by the hex digits in upper case.
fn upper_hex(text: &str) -> String {
    format!("0x{}", text[2..].to_uppercase())
}

/// Sends `signature` to a paid route and returns the response.
async fn pay(gateway: &Gateway, signature: &str) -> reqwest::Response {
    client()
        .get(gateway.url("/paid/x"))
        .header("payment-signature", signature)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn challenges_without_a_payment() {
    let world = World::start().await;
    let gateway = world.gateway(&[]).await;

    let response = client()
        .get(gateway.url("/paid/report?day=1"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 402);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let header = decode(response.headers()["payment-required"].to_str().unwrap());
    let body: Value = response.json().await.unwrap();
    assert_eq!(
        header, body,
        "the header and the body carry the same challenge"
    );
    assert_eq!(body["x402Version"], 2);
    assert_eq!(body["error"], "PAYMENT-SIGNATURE header is required");
    assert_eq!(
        body["resource"]["url"],
        "https://api.example.com/paid/report?day=1"
    );
    assert_eq!(body["resource"]["description"], "Paid endpoints, per call");
    assert_eq!(body["accepts"], json!([accepted()]));
    assert!(
        body["extensions"]["eip2612GasSponsoring"]["info"].is_object(),
        "the facilitator sponsors the Permit2 approval, so the challenge says so: {body}"
    );
    // The facilitator was asked once, when the policy loaded, not per request.
    assert_eq!(world.calls("/supported").await, 1);

    // Everything else passes through.
    let free = client().get(gateway.url("/free")).send().await.unwrap();
    assert_eq!(free.status(), 200);
    assert_eq!(world.calls("/verify").await, 0);
}

#[tokio::test]
async fn falls_back_to_known_tokens_when_supported_is_unavailable() {
    let world = World::start_with(None).await;
    let gateway = world.gateway(&[]).await;

    let response = client().get(gateway.url("/paid/x")).send().await.unwrap();
    assert_eq!(response.status(), 402);
    let body: Value = response.json().await.unwrap();
    assert_eq!(
        body["accepts"][0]["extra"],
        json!({ "assetTransferMethod": "permit2", "name": "Stable Coin", "version": "1" }),
        "SBC on Radius is paid through Permit2 even without the facilitator's word"
    );
    assert!(
        body.get("extensions").is_none(),
        "no sponsoring is promised without the facilitator's word"
    );
}

#[tokio::test]
async fn offers_eip3009_where_the_facilitator_prefers_it() {
    let supported = json!({
        "kinds": [{
            "x402Version": 2, "scheme": "exact", "network": "eip155:72344", "asset": SBC,
            "extra": { "assetTransferMethod": "eip3009", "name": "Stable Coin", "version": "1" }
        }],
        "extensions": [],
        "signers": {}
    });
    let world = World::start_with(Some(supported)).await;
    let gateway = world.gateway(&[]).await;
    let response = client().get(gateway.url("/paid/x")).send().await.unwrap();
    let body: Value = response.json().await.unwrap();
    assert_eq!(
        body["accepts"][0]["extra"]["assetTransferMethod"],
        "eip3009"
    );
    assert!(body.get("extensions").is_none());
}

#[tokio::test]
async fn verifies_forwards_and_settles() {
    let world = World::start().await;
    world
        .verify_answers(200, json!({ "isValid": true, "payer": PAYER }))
        .await;
    world.settle_answers(200, settled()).await;
    let gateway = world.gateway(&[]).await;

    let signature = encode(&payload(accepted(), "0x01", "0xsig"));
    let response = client()
        .post(gateway.url("/paid/report"))
        .header("payment-signature", &signature)
        .body("hello")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let settlement = decode(response.headers()["payment-response"].to_str().unwrap());
    assert_eq!(settlement["success"], true);
    assert_eq!(settlement["transaction"], "0xtx");
    assert_eq!(settlement["payer"], PAYER);
    let echo: Echo = response.json().await.unwrap();
    assert_eq!(echo.method, "POST");
    assert_eq!(echo.body, "hello");
    assert!(
        !echo.headers.contains_key("payment-signature"),
        "the payment header reached the upstream"
    );

    let requests: Vec<_> = world
        .facilitator
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|request| request.method == "POST")
        .collect();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].url.path(), "/verify");
    assert_eq!(requests[1].url.path(), "/settle");
    for request in &requests {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["x402Version"], 2);
        assert_eq!(body["paymentPayload"]["payload"]["signature"], "0xsig");
        assert_eq!(body["paymentRequirements"]["payTo"], PAY_TO);
        assert_eq!(body["paymentRequirements"]["extra"]["name"], "Stable Coin");
    }

    // The same payment can't pay twice, even re-encoded with another signature string.
    let replay = encode(&payload(accepted(), "0x01", "0xother"));
    let response = client()
        .get(gateway.url("/paid/report"))
        .header("payment-signature", &replay)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 402);
    let body: Value = response.json().await.unwrap();
    assert_eq!(
        body["error"],
        "this payment has already been used; sign a new one"
    );
    assert_eq!(world.calls("/verify").await, 1);
}

#[tokio::test]
async fn refuses_payments_that_dont_verify() {
    let world = World::start().await;
    world
        .verify_answers(
            400,
            json!({ "isValid": false, "invalidReason": "insufficient_funds", "payer": PAYER }),
        )
        .await;
    let gateway = world.gateway(&[]).await;

    let signature = encode(&payload(accepted(), "0x02", "0xsig"));
    let response = client()
        .get(gateway.url("/paid/x"))
        .header("payment-signature", &signature)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 402);
    assert!(response.headers().contains_key("payment-required"));
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"], "insufficient_funds");
    assert_eq!(world.calls("/settle").await, 0);

    // The claim was released: the same payment is verified again when retried.
    let response = client()
        .get(gateway.url("/paid/x"))
        .header("payment-signature", &signature)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 402);
    assert_eq!(world.calls("/verify").await, 2);
}

#[tokio::test]
async fn answers_502_when_the_facilitator_is_unusable() {
    let world = World::start().await;
    Mock::given(method("POST"))
        .and(path("/verify"))
        .respond_with(ResponseTemplate::new(504).set_body_string("gateway timeout"))
        .mount(&world.facilitator)
        .await;
    let gateway = world.gateway(&[]).await;

    let signature = encode(&payload(accepted(), "0x03", "0xsig"));
    let response = client()
        .get(gateway.url("/paid/x"))
        .header("payment-signature", &signature)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 502);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["code"], "facilitator_unavailable");
}

#[tokio::test]
async fn never_charges_for_an_upstream_error() {
    let world = World::start().await;
    world.verify_answers(200, json!({ "isValid": true })).await;
    world.settle_answers(200, settled()).await;
    let gateway = world.gateway(&[]).await;

    let signature = encode(&payload(accepted(), "0x04", "0xsig"));
    let response = client()
        .get(gateway.url("/paid/anything"))
        .header("payment-signature", &signature)
        .header("x-echo-status", "500")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 500);
    assert!(!response.headers().contains_key("payment-response"));
    assert_eq!(world.calls("/settle").await, 0);

    // The payment wasn't used: a retry verifies again.
    let response = client()
        .get(gateway.url("/paid/anything"))
        .header("payment-signature", &signature)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(response.headers().contains_key("payment-response"));
    assert_eq!(world.calls("/verify").await, 2);
    assert_eq!(world.calls("/settle").await, 1);
}

#[tokio::test]
async fn reports_a_failed_settlement_and_keeps_the_claim() {
    let world = World::start().await;
    world.verify_answers(200, json!({ "isValid": true })).await;
    world
        .settle_answers(
            200,
            json!({ "success": false, "errorReason": "invalid_transaction_state", "transaction": "", "network": "eip155:72344" }),
        )
        .await;
    let gateway = world.gateway(&[]).await;

    let signature = encode(&payload(accepted(), "0x05", "0xsig"));
    let response = client()
        .get(gateway.url("/paid/x"))
        .header("payment-signature", &signature)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 402);
    let settlement = decode(response.headers()["payment-response"].to_str().unwrap());
    assert_eq!(settlement["success"], false);
    let body: Value = response.json().await.unwrap();
    assert_eq!(
        body["error"],
        "settlement failed: invalid_transaction_state"
    );

    // Settlement was attempted, so the payment stays claimed: no second verify.
    let response = client()
        .get(gateway.url("/paid/x"))
        .header("payment-signature", &signature)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 402);
    let body: Value = response.json().await.unwrap();
    assert_eq!(
        body["error"],
        "this payment has already been used; sign a new one"
    );
    assert_eq!(world.calls("/verify").await, 1);
}

#[tokio::test]
async fn rejects_malformed_and_mismatched_payments() {
    let world = World::start().await;
    let gateway = world.gateway(&[]).await;
    let get = |signature: String| {
        client()
            .get(gateway.url("/paid/x"))
            .header("payment-signature", signature)
            .send()
    };

    let response = get("not base64!".to_owned()).await.unwrap();
    assert_eq!(response.status(), 400);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["code"], "invalid_payment");

    let response = get(STANDARD.encode(r#"{"x402Version":2}"#)).await.unwrap();
    assert_eq!(
        response.status(),
        400,
        "a payload without `accepted` is malformed"
    );

    let mut v1 = payload(accepted(), "0x06", "0xsig");
    v1["x402Version"] = 1.into();
    let response = get(encode(&v1)).await.unwrap();
    assert_eq!(response.status(), 402);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"], "x402 version 2 is required");

    let mut cheaper = accepted();
    cheaper["amount"] = "1".into();
    let response = get(encode(&payload(cheaper, "0x07", "0xsig")))
        .await
        .unwrap();
    assert_eq!(response.status(), 402);
    let body: Value = response.json().await.unwrap();
    assert_eq!(
        body["error"],
        "the payment doesn't match an accepted requirement"
    );
    assert_eq!(world.calls("/verify").await, 0);
}

#[tokio::test]
async fn settles_large_responses_on_their_status_and_streams_them() {
    let world = World::start().await;
    world.verify_answers(200, json!({ "isValid": true })).await;
    world.settle_answers(200, settled()).await;
    let gateway = world.gateway(&["--paid-body-limit", "1000"]).await;

    let signature = encode(&payload(accepted(), "0x08", "0xsig"));
    let response = client()
        .get(gateway.url("/paid/big/5000"))
        .header("payment-signature", &signature)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(response.headers().contains_key("payment-response"));
    let body = response.bytes().await.unwrap();
    assert_eq!(body.len(), 5000);
    assert!(body.iter().all(|b| *b == b'x'));
    assert_eq!(world.calls("/settle").await, 1);
}

#[tokio::test]
async fn serves_a_permit2_payment_once_however_it_is_encoded() {
    let world = World::start().await;
    world
        .verify_answers(200, json!({ "isValid": true, "payer": PAYER }))
        .await;
    world.settle_answers(200, settled()).await;
    let gateway = world.gateway(&[]).await;

    let nonce = "33247007178036348590600198031289925668252061821958005840077069883511451257277";
    let original = permit2_payload(nonce);
    let response = pay(&gateway, &encode(&original)).await;
    assert_eq!(response.status(), 200);
    assert_eq!(world.calls("/settle").await, 1);

    let mut cased = original.clone();
    cased["payload"]["permit2Authorization"]["from"] = upper_hex(PAYER).into();
    cased["payload"]["signature"] = upper_hex(SIGNATURE).into();
    let mut hex_nonce = original.clone();
    hex_nonce["payload"]["permit2Authorization"]["nonce"] =
        format!("{:#x}", U256::from_str(nonce).unwrap()).into();
    for (what, copy) in [
        ("addresses and hex in upper case", cased),
        ("the nonce in hex", hex_nonce),
    ] {
        let response = pay(&gateway, &encode(&copy)).await;
        assert_eq!(response.status(), 402, "{what}");
        let body: Value = response.json().await.unwrap();
        assert_eq!(
            body["error"], "this payment has already been used; sign a new one",
            "{what}"
        );
    }
    assert_eq!(world.calls("/verify").await, 1);
    assert_eq!(world.calls("/settle").await, 1);
}

/// Asserts that `response` tells the buyer its payment's settlement outcome is unknown: the
/// content is withheld, no fresh terms are offered, and the transaction the facilitator named, if
/// any, is in `PAYMENT-RESPONSE`.
async fn assert_settlement_unknown(
    response: reqwest::Response,
    transaction: Option<&str>,
    what: &str,
) {
    assert_eq!(response.status(), 503, "{what}");
    assert!(
        !response.headers().contains_key("payment-required"),
        "{what} was offered fresh terms"
    );
    assert_eq!(response.headers()["cache-control"], "no-store", "{what}");
    match transaction {
        Some(hash) => {
            let settlement = decode(response.headers()["payment-response"].to_str().unwrap());
            assert_eq!(settlement["success"], false, "{what}");
            assert_eq!(settlement["transaction"], hash, "{what}");
        }
        None => assert!(
            !response.headers().contains_key("payment-response"),
            "{what}"
        ),
    }
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["code"], "settlement_unknown", "{what}: {body}");
    let message = body["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("outcome is unknown") && message.contains("don't repeat this payment"),
        "{what}: {message}"
    );
}

/// A `/settle` answer reporting a failure for `reason`, naming `transaction` (none if empty).
fn failed_settlement(reason: &str, transaction: &str) -> Value {
    json!({
        "success": false,
        "errorReason": reason,
        "transaction": transaction,
        "network": "eip155:72344",
        "payer": PAYER
    })
}

#[tokio::test]
async fn a_settlement_whose_outcome_is_unknown_keeps_the_payment() {
    let hash = "0x5c1e0f3a9b7d2c4e6f8a0b1c3d5e7f9a2b4c6d8e0f1a3b5c7d9e2f4a6b8c0d1e";
    for (case, status, answer, transaction, nonce) in [
        (
            "settlement_pending, naming no transaction yet",
            200,
            failed_settlement("settlement_pending", ""),
            None,
            "1001",
        ),
        (
            "a failure that names a transaction",
            200,
            failed_settlement("unexpected_settle_error", hash),
            Some(hash),
            "1002",
        ),
        (
            "a 503, whatever its body says",
            503,
            failed_settlement("unexpected_settle_error", ""),
            None,
            "1003",
        ),
    ] {
        let world = World::start().await;
        world
            .verify_answers(200, json!({ "isValid": true, "payer": PAYER }))
            .await;
        world.settle_answers(status, answer).await;
        let gateway = world.gateway(&[]).await;

        let signature = encode(&permit2_payload(nonce));
        for attempt in ["the paid request", "a retry of the same payment"] {
            let response = pay(&gateway, &signature).await;
            assert_settlement_unknown(response, transaction, &format!("{case}: {attempt}")).await;
        }
        assert_eq!(world.calls("/verify").await, 1, "{case}");
        assert_eq!(world.calls("/settle").await, 1, "{case}");
    }
}

#[tokio::test]
async fn a_definite_settlement_refusal_offers_fresh_terms() {
    let hash = "0x7e2d4c6b8a0f1e3d5c7b9a2f4e6d8c0b1a3f5e7d9c2b4a6f8e0d1c3b5a7f9e2d";
    for (case, reason, transaction, nonce) in [
        (
            "a reason and no transaction",
            "insufficient_funds",
            "",
            "1008",
        ),
        (
            "a transaction that failed on chain",
            "invalid_transaction_state",
            hash,
            "1009",
        ),
    ] {
        let world = World::start().await;
        world.verify_answers(200, json!({ "isValid": true })).await;
        world
            .settle_answers(400, failed_settlement(reason, transaction))
            .await;
        let gateway = world.gateway(&[]).await;

        let response = pay(&gateway, &encode(&permit2_payload(nonce))).await;
        assert_eq!(response.status(), 402, "{case}");
        assert!(
            response.headers().contains_key("payment-required"),
            "{case}"
        );
        let body: Value = response.json().await.unwrap();
        assert_eq!(
            body["error"],
            format!("settlement failed: {reason}"),
            "{case}"
        );
    }
}

/// `payload(accepted(), nonce, SIGNATURE)` naming `url` as its resource.
fn payload_for(url: &str, nonce: &str) -> Value {
    let mut payment = payload(accepted(), nonce, SIGNATURE);
    payment["resource"] = json!({ "url": url, "description": "Paid endpoints, per call" });
    payment
}

#[tokio::test]
async fn refuses_a_payment_made_out_for_another_resource() {
    let world = World::start().await;
    world
        .verify_answers(200, json!({ "isValid": true, "payer": PAYER }))
        .await;
    world.settle_answers(200, settled()).await;
    let gateway = world.gateway(&[]).await;

    let other = encode(&payload_for("https://api.example.com/paid/other", "0x2101"));
    let response = pay(&gateway, &other).await;
    assert_eq!(response.status(), 402);
    assert!(response.headers().contains_key("payment-required"));
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["resource"]["url"], "https://api.example.com/paid/x");
    assert_eq!(
        body["error"],
        "the payment is for https://api.example.com/paid/other, not this resource"
    );
    assert_eq!(world.calls("/verify").await, 0);

    // The same URL spelled another way, and a payment that names no resource, are accepted.
    for (what, signature) in [
        (
            "the URL in another spelling",
            encode(&payload_for(
                "HTTPS://API.Example.com:443/paid/./x#top",
                "0x2102",
            )),
        ),
        (
            "no resource",
            encode(&payload(accepted(), "0x2103", SIGNATURE)),
        ),
    ] {
        let response = pay(&gateway, &signature).await;
        assert_eq!(response.status(), 200, "{what}");
    }
    assert_eq!(world.calls("/settle").await, 2);
}

/// A client that gives up after `timeout`.
fn impatient(timeout: Duration) -> reqwest::Client {
    reqwest::Client::builder().timeout(timeout).build().unwrap()
}

#[tokio::test]
async fn a_stalled_paid_body_times_out_and_releases_the_payment() {
    let world = World::start().await;
    world.verify_answers(200, json!({ "isValid": true })).await;
    world.settle_answers(200, settled()).await;
    let gateway = world.gateway(&["--upstream-timeout", "300ms"]).await;

    let signature = encode(&payload(accepted(), "0x2201", SIGNATURE));
    for attempt in ["the paid request", "a retry of the same payment"] {
        let response = impatient(Duration::from_secs(3))
            .get(gateway.url("/paid/stall"))
            .header("payment-signature", &signature)
            .send()
            .await
            .expect("the gateway answers within 3s");
        assert_eq!(response.status(), 504, "{attempt}");
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["code"], "upstream_timeout", "{attempt}");
    }
    assert_eq!(world.calls("/verify").await, 2, "the payment was released");
    assert_eq!(world.calls("/settle").await, 0);
}

#[tokio::test]
async fn a_failed_paid_body_releases_the_payment() {
    let world = World::start().await;
    world.verify_answers(200, json!({ "isValid": true })).await;
    world.settle_answers(200, settled()).await;
    let gateway = world.gateway(&[]).await;

    let signature = encode(&payload(accepted(), "0x2202", SIGNATURE));
    for attempt in ["the paid request", "a retry of the same payment"] {
        let response = client()
            .get(gateway.url("/paid/broken"))
            .header("payment-signature", &signature)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 502, "{attempt}");
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["code"], "upstream_unavailable", "{attempt}");
    }
    assert_eq!(world.calls("/verify").await, 2, "the payment was released");
    assert_eq!(world.calls("/settle").await, 0);
}

#[tokio::test]
async fn a_disconnect_before_settlement_releases_the_payment() {
    let world = World::start().await;
    Mock::given(method("POST"))
        .and(path("/verify"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({ "isValid": true }))
                .set_delay(Duration::from_millis(800)),
        )
        .mount(&world.facilitator)
        .await;
    world.settle_answers(200, settled()).await;
    let gateway = world.gateway(&[]).await;

    let signature = encode(&payload(accepted(), "0x2301", SIGNATURE));
    let gave_up = impatient(Duration::from_millis(200))
        .get(gateway.url("/paid/x"))
        .header("payment-signature", &signature)
        .send()
        .await;
    assert!(gave_up.is_err(), "the buyer gave up during /verify");
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(
        world.calls("/settle").await,
        0,
        "the request went on after the buyer left"
    );

    let response = pay(&gateway, &signature).await;
    assert_eq!(response.status(), 200);
    assert_eq!(world.calls("/verify").await, 2);
    assert_eq!(world.calls("/settle").await, 1);
}

#[tokio::test]
async fn a_disconnect_during_settlement_keeps_the_payment() {
    let world = World::start().await;
    world.verify_answers(200, json!({ "isValid": true })).await;
    Mock::given(method("POST"))
        .and(path("/settle"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(settled())
                .set_delay(Duration::from_millis(800)),
        )
        .mount(&world.facilitator)
        .await;
    let gateway = world.gateway(&[]).await;

    let signature = encode(&payload(accepted(), "0x2302", SIGNATURE));
    let gave_up = impatient(Duration::from_millis(400))
        .get(gateway.url("/paid/x"))
        .header("payment-signature", &signature)
        .send()
        .await;
    assert!(gave_up.is_err(), "the buyer gave up during /settle");
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(world.calls("/settle").await, 1);

    let response = pay(&gateway, &signature).await;
    assert_settlement_unknown(response, None, "a retry of the same payment").await;
    assert_eq!(world.calls("/verify").await, 1);
    assert_eq!(world.calls("/settle").await, 1);
}

#[tokio::test]
#[ignore = "passes the upstream's Cache-Control through on a paid response, or sets none"]
async fn shared_caches_dont_store_paid_responses() {
    let world = World::start().await;
    world.verify_answers(200, json!({ "isValid": true })).await;
    world.settle_answers(200, settled()).await;
    let gateway = world.gateway(&[]).await;

    for (nonce, upstream, released) in [
        ("0x2401", None, "private"),
        ("0x2402", Some("public, max-age=60"), "private, max-age=60"),
        ("0x2403", Some("no-store"), "no-store"),
        ("0x2404", Some("max-age=30, PRIVATE"), "max-age=30, PRIVATE"),
    ] {
        let mut request = client().get(gateway.url("/paid/x")).header(
            "payment-signature",
            encode(&payload(accepted(), nonce, SIGNATURE)),
        );
        if let Some(value) = upstream {
            request = request.header("x-echo-cache-control", value);
        }
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), 200, "{upstream:?}");
        assert!(response.headers().contains_key("payment-response"));
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some(released),
            "{upstream:?}"
        );
    }
}

#[tokio::test]
#[ignore = "follows a /verify redirect, sending the signed payment to another host"]
async fn doesnt_follow_a_facilitator_redirect() {
    let world = World::start().await;
    let elsewhere = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/verify"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "isValid": true })))
        .mount(&elsewhere)
        .await;
    Mock::given(method("POST"))
        .and(path("/verify"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("location", format!("{}/verify", elsewhere.uri())),
        )
        .mount(&world.facilitator)
        .await;
    world.settle_answers(200, settled()).await;
    let gateway = world.gateway(&[]).await;

    let response = pay(&gateway, &encode(&payload(accepted(), "0x2501", SIGNATURE))).await;
    assert_eq!(response.status(), 502);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["code"], "facilitator_unavailable");
    assert_eq!(elsewhere.received_requests().await.unwrap().len(), 0);
    assert_eq!(world.calls("/settle").await, 0);
}

#[tokio::test]
#[ignore = "answers 200 to a payment signed to another recipient, for another amount or for another token: only `accepted` is compared with the offer"]
async fn refuses_a_payment_signed_for_other_terms() {
    let world = World::start().await;
    world
        .verify_answers(200, json!({ "isValid": true, "payer": PAYER }))
        .await;
    world.settle_answers(200, settled()).await;
    let gateway = world.gateway(&[]).await;
    let other = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
    let usdc = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";

    let eip3009 = |nonce: &str, field: &str, value: &str| {
        let mut payment = payload(accepted(), nonce, SIGNATURE);
        payment["payload"]["authorization"][field] = value.into();
        payment
    };
    let permit2 = |nonce: &str, pointer: &str, value: &str| {
        let mut payment = permit2_payload(nonce);
        *payment.pointer_mut(pointer).unwrap() = value.into();
        payment
    };
    let witness_to = "/payload/permit2Authorization/witness/to";
    let permitted_amount = "/payload/permit2Authorization/permitted/amount";
    let permitted_token = "/payload/permit2Authorization/permitted/token";
    for (field, payment) in [
        ("payload.authorization.to", eip3009("0x2601", "to", other)),
        (
            "payload.authorization.value",
            eip3009("0x2603", "value", "20000"),
        ),
        (
            "payload.permit2Authorization.witness.to",
            permit2("2604", witness_to, other),
        ),
        (
            "payload.permit2Authorization.permitted.amount",
            permit2("2605", permitted_amount, "9999"),
        ),
        (
            "payload.permit2Authorization.permitted.token",
            permit2("2606", permitted_token, usdc),
        ),
    ] {
        let response = pay(&gateway, &encode(&payment)).await;
        assert_eq!(response.status(), 402, "{field}");
        assert!(
            response.headers().contains_key("payment-required"),
            "{field}"
        );
        let body: Value = response.json().await.unwrap();
        let error = body["error"].as_str().unwrap_or_default();
        assert!(error.contains(field), "{field}: {error}");
        assert_eq!(world.calls("/verify").await, 0, "{field}");
    }

    // Addresses in another case and amounts in hex are the offered terms.
    for (what, payment) in [
        ("EIP-3009", eip3009("0x2607", "to", &upper_hex(PAY_TO))),
        ("Permit2", permit2("2608", permitted_amount, "0x2710")),
    ] {
        let response = pay(&gateway, &encode(&payment)).await;
        assert_eq!(response.status(), 200, "{what}");
    }
    assert_eq!(world.calls("/settle").await, 2);
}
