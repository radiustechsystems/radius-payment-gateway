//! x402 version 2 over HTTP: the payment challenge and the verify, forward and settle flow for a
//! `charge` rule (gate standard, section 6). A port of the platform SDK's `x402.ts`.

pub mod claim;
pub mod domains;
pub mod facilitator;
pub mod supported;
pub mod types;

use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use http::header::{CACHE_CONTROL, HOST};
use http::{HeaderName, HeaderValue, Request, StatusCode};
use http_body_util::BodyExt;
use policy::compiled::PaymentRequirement;
use serde_json::Value;

use crate::counters::{ClaimGuard, UnknownSettlement};
use crate::error::{error_response, uncacheable_error};
use crate::proxy::strip_framing;
pub use facilitator::FacilitatorClient;
pub use types::{PaymentRequired, PaymentRequirements, ResourceInfo, SettleResponse};

/// The challenge: base64 of a `PaymentRequired` object, on a 402 response.
pub const PAYMENT_REQUIRED: HeaderName = HeaderName::from_static("payment-required");
/// The client's payment: base64 of a `PaymentPayload`.
pub const PAYMENT_SIGNATURE: HeaderName = HeaderName::from_static("payment-signature");
/// The settlement: base64 of a `SettlementResponse`, on the paid response.
pub const PAYMENT_RESPONSE: HeaderName = HeaderName::from_static("payment-response");

pub const X402_VERSION: u8 = 2;

/// A `charge` decision: what the policy wants paid.
pub struct Charge<'a> {
    pub description: &'a str,
    pub accepts: &'a [PaymentRequirement],
}

/// What the gate gives the charge flow.
pub struct ChargeContext<'a> {
    pub facilitator: &'a FacilitatorClient,
    pub claims: &'a dyn ClaimGuard,
    pub claim_ttl: Duration,
    pub paid_body_limit: usize,
    pub max_timeout_seconds: u32,
    pub public_url: Option<&'a str>,
}

/// How a charge ended, for telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChargeOutcome {
    /// A 402 was answered: no payment, or one that wasn't accepted.
    Challenged,
    /// The payment header couldn't be read (400).
    Invalid,
    /// The payment was verified and settled; the upstream's response is returned.
    Paid,
    /// The payment was verified but the upstream failed, so nothing was charged.
    UpstreamFailed,
    /// The facilitator or the claim store couldn't be used.
    Unavailable,
    /// Settlement was attempted and its outcome is unknown; the payment stays claimed.
    Unknown,
}

impl ChargeOutcome {
    pub fn label(self) -> &'static str {
        match self {
            Self::Challenged => "payment_required",
            Self::Invalid => "deny:invalid_payment",
            Self::Paid => "paid",
            Self::UpstreamFailed => "upstream_failed",
            Self::Unavailable => "payment_unavailable",
            Self::Unknown => "settlement_unknown",
        }
    }
}

/// The URL buyers called, for `resource.url`: the request's path and query under `public_url`,
/// or rebuilt from what the proxy in front of us forwarded.
pub fn resource_url(request: &Request<Body>, public_url: Option<&str>) -> String {
    let path_and_query = request.uri().path_and_query().map_or("/", |pq| pq.as_str());
    if let Some(base) = public_url {
        return format!("{}{path_and_query}", base.trim_end_matches('/'));
    }
    let header = |name: &str| {
        request
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.split(',').next().unwrap_or_default().trim())
            .filter(|value| !value.is_empty())
    };
    let scheme = header("x-forwarded-proto").unwrap_or("http");
    let host = header("x-forwarded-host")
        .or_else(|| request.headers().get(HOST).and_then(|v| v.to_str().ok()))
        .unwrap_or("localhost");
    format!("{scheme}://{host}{path_and_query}")
}

/// The payment requirements of a charge, for the request's resource: one entry per compiled
/// option, in order (gate standard, 6.1). Each option's `extra` (the transfer method and the
/// token's EIP-712 domain) comes from what its facilitator says it supports, else from the
/// gateway's own table of tokens; the gas-sponsoring extension is declared when a facilitator
/// offers it.
pub async fn challenge(
    facilitators: &FacilitatorClient,
    charge: &Charge<'_>,
    resource_url: String,
    max_timeout_seconds: u32,
) -> PaymentRequired {
    let mut accepts = Vec::with_capacity(charge.accepts.len());
    let mut sponsored = false;
    for accept in charge.accepts {
        let supported = match &accept.facilitator {
            Some(url) => facilitators.supported_or_fetch(url).await,
            None => None,
        };
        let asset = accept.asset.to_string();
        let extra = supported
            .as_ref()
            .and_then(|supported| supported.exact_extra(&accept.network, &asset))
            .or_else(|| domains::exact_extra(&accept.network, accept.asset))
            .unwrap_or_else(|| Value::Object(Default::default()));
        if supported.is_some_and(|s| s.declares(supported::EIP2612_GAS_SPONSORING)) {
            sponsored = true;
        }
        accepts.push(PaymentRequirements {
            scheme: accept.scheme.as_str().to_owned(),
            network: accept.network.clone(),
            amount: accept.amount.to_string(),
            asset,
            pay_to: accept.pay_to.to_string(),
            max_timeout_seconds,
            extra,
        });
    }
    PaymentRequired {
        x402_version: X402_VERSION,
        error: None,
        resource: ResourceInfo {
            url: resource_url,
            description: charge.description.to_owned(),
        },
        accepts,
        extensions: sponsored.then(|| {
            serde_json::json!({
                supported::EIP2612_GAS_SPONSORING: supported::gas_sponsoring_declaration()
            })
        }),
    }
}

/// A 402 with the requirements in the `PAYMENT-REQUIRED` header and as the body. A challenge is
/// for this request only, so caches must not answer another with it.
pub fn payment_required_response(mut requirements: PaymentRequired, error: &str) -> Response {
    requirements.error = Some(error.to_owned());
    let encoded = encode(&requirements);
    let mut response = (StatusCode::PAYMENT_REQUIRED, axum::Json(requirements)).into_response();
    let headers = response.headers_mut();
    headers.insert(PAYMENT_REQUIRED, encoded);
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn encode<T: serde::Serialize>(value: &T) -> HeaderValue {
    HeaderValue::from_str(&types::encode_header(value)).expect("base64 is a valid header value")
}

/// Turns a `payment_required` decision into the x402 handshake. Without `PAYMENT-SIGNATURE`,
/// answers 402 with the requirements. With it: checks the payment is for one of the offered
/// options, claims it so it can't pay for another request, verifies it with the option's
/// facilitator, forwards the request, settles after a 2xx and adds `PAYMENT-RESPONSE`. An
/// upstream response that isn't 2xx is returned as is and never charged, and its payment can be
/// tried again.
///
/// `forward` must not see the client's payment header; `proxy::prepare` strips it.
pub async fn charge<F, Fut>(
    ctx: &ChargeContext<'_>,
    charge: &Charge<'_>,
    request: Request<Body>,
    forward: F,
) -> (Response, ChargeOutcome)
where
    F: FnOnce(Request<Body>) -> Fut,
    Fut: Future<Output = Response>,
{
    let requirements = challenge(
        ctx.facilitator,
        charge,
        resource_url(&request, ctx.public_url),
        ctx.max_timeout_seconds,
    )
    .await;
    let Some(signature) = request
        .headers()
        .get(PAYMENT_SIGNATURE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
    else {
        return (
            payment_required_response(requirements, "PAYMENT-SIGNATURE header is required"),
            ChargeOutcome::Challenged,
        );
    };

    let payload = match types::decode_header(&signature) {
        Some(payload)
            if payload.is_object() && payload.get("accepted").is_some_and(Value::is_object) =>
        {
            payload
        }
        _ => {
            return (
                error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_payment",
                    "PAYMENT-SIGNATURE isn't a base64 JSON payment payload",
                ),
                ChargeOutcome::Invalid,
            );
        }
    };
    if payload.get("x402Version").and_then(Value::as_u64) != Some(u64::from(X402_VERSION)) {
        return (
            payment_required_response(
                requirements,
                &format!("x402 version {X402_VERSION} is required"),
            ),
            ChargeOutcome::Challenged,
        );
    }
    let accepted = payload["accepted"].as_object().expect("checked above");
    let Some(index) = requirements
        .accepts
        .iter()
        .position(|offered| offered.matches(accepted))
    else {
        return (
            payment_required_response(
                requirements,
                "the payment doesn't match an accepted requirement",
            ),
            ChargeOutcome::Challenged,
        );
    };
    // Validation refuses a policy with an option that names no facilitator, so this holds.
    let facilitator = charge.accepts[index]
        .facilitator
        .clone()
        .unwrap_or_default();
    let offered = requirements.accepts[index].clone();

    let id = claim::payment_id(&payload, &signature);
    match ctx.claims.claim(&id, ctx.claim_ttl).await {
        Ok(true) => {}
        Ok(false) => {
            // A payment whose settlement didn't conclude may still be charged, so its repeat is
            // told that again, never to sign a new payment.
            return match ctx.claims.unknown(&id).await {
                Ok(Some(unknown)) => (
                    settlement_unknown(unknown.payment_response.as_deref()),
                    ChargeOutcome::Unknown,
                ),
                Ok(None) => (
                    payment_required_response(
                        requirements,
                        "this payment has already been used; sign a new one",
                    ),
                    ChargeOutcome::Challenged,
                ),
                Err(error) => claim_failed(error),
            };
        }
        Err(error) => return claim_failed(error),
    }

    let (response, outcome, keep_claim) = claimed(
        ctx,
        requirements,
        &facilitator,
        &payload,
        &offered,
        request,
        forward,
    )
    .await;
    if !keep_claim && let Err(error) = ctx.claims.release(&id).await {
        tracing::error!(error = %error, "payment release failed");
    }
    if outcome == ChargeOutcome::Unknown {
        let payment_response = response
            .headers()
            .get(PAYMENT_RESPONSE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let unknown = UnknownSettlement { payment_response };
        if let Err(error) = ctx.claims.mark_unknown(&id, unknown).await {
            tracing::error!(error = %error, "payment mark failed");
        }
    }
    (response, outcome)
}

/// The flow once the payment is claimed. Returns whether the claim stays: it does once `/settle`
/// has been called, whatever the facilitator answered, since the transfer may have been broadcast.
async fn claimed<F, Fut>(
    ctx: &ChargeContext<'_>,
    requirements: PaymentRequired,
    facilitator: &str,
    payload: &Value,
    offered: &PaymentRequirements,
    request: Request<Body>,
    forward: F,
) -> (Response, ChargeOutcome, bool)
where
    F: FnOnce(Request<Body>) -> Fut,
    Fut: Future<Output = Response>,
{
    let verification = match ctx.facilitator.verify(facilitator, payload, offered).await {
        Ok(verification) => verification,
        Err(error) => return (facilitator_failed(error), ChargeOutcome::Unavailable, false),
    };
    if !verification.is_valid {
        let reason = verification
            .invalid_reason
            .as_deref()
            .unwrap_or("the payment is invalid");
        tracing::debug!(reason, "payment didn't verify");
        return (
            payment_required_response(requirements, reason),
            ChargeOutcome::Challenged,
            false,
        );
    }

    let response = forward(request).await;
    if !response.status().is_success() {
        return (response, ChargeOutcome::UpstreamFailed, false);
    }

    // From here the payment stays claimed, whatever the facilitator answers: it may have
    // broadcast the transfer before something failed (a timeout, a lost connection, a failed
    // receipt wait it reports as `settlement_pending`), and the transfer can still land. Only a
    // refusal asks the buyer for a new payment; any other failure is answered as unknown.
    let (parts, body) = response.into_parts();
    let body = match buffer(body, ctx.paid_body_limit).await {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(error = %error, "upstream body failed before settlement");
            return (
                error_response(
                    StatusCode::BAD_GATEWAY,
                    "upstream_unavailable",
                    "the upstream's response failed",
                ),
                ChargeOutcome::UpstreamFailed,
                true,
            );
        }
    };
    let settlement = match ctx.facilitator.settle(facilitator, payload, offered).await {
        Ok(settlement) => settlement,
        Err(error) => {
            tracing::error!(error = %error, network = offered.network, "settlement outcome unknown");
            return (settlement_unknown(None), ChargeOutcome::Unknown, true);
        }
    };
    if !settlement.success {
        let reason = settlement
            .error_reason
            .as_deref()
            .unwrap_or("unknown reason");
        // Hashes, networks and payers are fine to log; the payment itself is not.
        if !refused(&settlement) {
            tracing::error!(
                reason,
                transaction = settlement.transaction,
                network = settlement.network,
                "settlement outcome unknown"
            );
            let header =
                (!settlement.transaction.is_empty()).then(|| types::encode_header(&settlement));
            return (
                settlement_unknown(header.as_deref()),
                ChargeOutcome::Unknown,
                true,
            );
        }
        if settlement.transaction.is_empty() {
            tracing::warn!(reason, "settlement failed");
        } else {
            // The transaction failed on chain: logged for the seller to reconcile.
            tracing::error!(
                reason,
                transaction = settlement.transaction,
                network = settlement.network,
                "settlement failed after a transaction"
            );
        }
        let mut failed =
            payment_required_response(requirements, &format!("settlement failed: {reason}"));
        failed
            .headers_mut()
            .insert(PAYMENT_RESPONSE, encode(&settlement));
        return (failed, ChargeOutcome::Challenged, true);
    }
    tracing::info!(
        transaction = settlement.transaction,
        network = settlement.network,
        payer = settlement.payer.as_deref().unwrap_or(""),
        amount = offered.amount,
        "payment settled"
    );
    let mut paid = Response::from_parts(parts, body);
    paid.headers_mut()
        .insert(PAYMENT_RESPONSE, encode(&settlement));
    strip_framing(paid.headers_mut());
    (paid, ChargeOutcome::Paid, true)
}

/// Reads the body up to `limit` bytes. A body that fits is returned whole, so it's known to be
/// complete before settlement; a larger one is returned as the read prefix followed by the rest
/// of the stream, since the standard only asks for the status before settling.
async fn buffer(mut body: Body, limit: usize) -> Result<Body, axum::Error> {
    let mut prefix = Vec::new();
    while prefix.len() < limit {
        match body.frame().await {
            None => return Ok(Body::from(prefix)),
            Some(Err(error)) => return Err(error),
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    prefix.extend_from_slice(&data);
                }
            }
        }
    }
    tracing::debug!(
        limit,
        "paid response exceeds the buffer limit; streaming the rest"
    );
    let head = futures_util::stream::iter([Ok::<_, axum::Error>(Bytes::from(prefix))]);
    Ok(Body::from_stream(head.chain(body.into_data_stream())))
}

/// Whether a failed settlement is a refusal, so the transfer can't land and the buyer may pay
/// again: the facilitator gave a reason and broadcast nothing, or the transaction it names failed
/// on chain (`invalid_transaction_state`). `settlement_pending`, and any other failure that names
/// a transaction, may still land.
fn refused(settlement: &SettleResponse) -> bool {
    match settlement.error_reason.as_deref() {
        Some("settlement_pending") => false,
        Some("invalid_transaction_state") => true,
        _ => settlement.transaction.is_empty(),
    }
}

/// A 503 without payment terms for a payment whose settlement didn't conclude, with the
/// facilitator's `PAYMENT-RESPONSE` when it named a transaction, so the buyer can look it up.
fn settlement_unknown(payment_response: Option<&str>) -> Response {
    let mut response = uncacheable_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "settlement_unknown",
        "the payment's settlement outcome is unknown and it may still be charged: don't repeat \
         this payment or sign a new one for this request",
    );
    if let Some(value) = payment_response.and_then(|value| HeaderValue::from_str(value).ok()) {
        response.headers_mut().insert(PAYMENT_RESPONSE, value);
    }
    response
}

fn claim_failed(error: crate::counters::ClaimError) -> (Response, ChargeOutcome) {
    tracing::error!(error = %error, "payment claim failed");
    (
        uncacheable_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "payment_unavailable",
            "payments can't be taken right now",
        ),
        ChargeOutcome::Unavailable,
    )
}

fn facilitator_failed(error: facilitator::FacilitatorError) -> Response {
    tracing::error!(error = %error, "facilitator call failed");
    error_response(
        StatusCode::BAD_GATEWAY,
        "facilitator_unavailable",
        "the payment facilitator couldn't be reached",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(uri: &str, headers: &[(&str, &str)]) -> Request<Body> {
        let mut builder = Request::builder().uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        builder.body(Body::empty()).unwrap()
    }

    #[test]
    fn resource_url_prefers_the_public_url() {
        let req = request("/tx/1?x=1", &[("host", "gw.internal:8080")]);
        assert_eq!(
            resource_url(&req, Some("https://api.example.com/")),
            "https://api.example.com/tx/1?x=1"
        );
        assert_eq!(
            resource_url(&req, Some("https://example.com/api")),
            "https://example.com/api/tx/1?x=1"
        );
        assert_eq!(resource_url(&req, None), "http://gw.internal:8080/tx/1?x=1");
    }

    #[test]
    fn resource_url_uses_forwarded_headers() {
        let req = request(
            "/tx/1",
            &[
                ("host", "gw.internal:8080"),
                ("x-forwarded-proto", "https"),
                ("x-forwarded-host", "api.example.com, gw.internal"),
            ],
        );
        assert_eq!(resource_url(&req, None), "https://api.example.com/tx/1");
    }
}
