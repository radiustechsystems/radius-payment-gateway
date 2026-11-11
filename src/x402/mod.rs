//! x402 version 2 over HTTP: the payment challenge and the verify, forward and settle flow for a
//! `charge` rule (gate standard, section 6). A port of the platform SDK's `x402.ts`.

pub mod claim;
pub mod domains;
pub mod facilitator;
pub mod supported;
pub mod types;

use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::U256;
use axum::body::{Body, Bytes};
use axum::response::{IntoResponse, Response};
use domain::pricing::catalog;
use futures_util::StreamExt;
use http::header::{ACCEPT, CACHE_CONTROL, CONTENT_TYPE, HOST, VARY};
use http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode};
use http_body_util::BodyExt;
use policy::compiled::PaymentRequirement;
use serde_json::Value;

use crate::counters::{ClaimGuard, Ticket, TicketStore, UnknownSettlement};
use crate::error::{error_response, uncacheable_error};
use crate::gate::upstream_failed;
use crate::pages::{PageVars, Pages, negotiate};
use crate::proxy::{UpstreamError, strip_framing};
use crate::ticket;
pub use facilitator::FacilitatorClient;
pub use types::{PaymentRequired, PaymentRequirements, ResourceInfo, SettleResponse};

/// The challenge: base64 of a `PaymentRequired` object, on a 402 response.
pub const PAYMENT_REQUIRED: HeaderName = HeaderName::from_static("payment-required");
/// The client's payment: base64 of a `PaymentPayload`.
pub const PAYMENT_SIGNATURE: HeaderName = HeaderName::from_static("payment-signature");
/// The settlement: base64 of a `SettlementResponse`, on the paid response.
pub const PAYMENT_RESPONSE: HeaderName = HeaderName::from_static("payment-response");

pub const X402_VERSION: u8 = 2;

/// The challenge's `error` when no payment was presented: the page shows nothing for it.
pub const NO_PAYMENT: &str = "PAYMENT-SIGNATURE header is required";

/// What a browser's page may load, so a custom template can't be turned into a script injection
/// by what the request controls: scripts and styles only from the gateway's own assets.
const PAGE_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'";

/// A `charge` decision: what the policy wants paid.
pub struct Charge<'a> {
    pub rule: Option<&'a str>,
    pub description: &'a str,
    pub accepts: &'a [PaymentRequirement],
}

/// The page marks the paid request it sends, so a settled payment gets a ticket for the reload.
pub const PAGE_MARKER: HeaderName = HeaderName::from_static("radius-page");

/// What the gate gives the charge flow.
pub struct ChargeContext<'a> {
    pub facilitator: &'a FacilitatorClient,
    pub claims: &'a Arc<dyn ClaimGuard>,
    pub claim_ttl: Duration,
    pub paid_body_limit: usize,
    /// The upstream's timeout, which also bounds the read of a paid body before settlement.
    pub upstream_timeout: Duration,
    pub max_timeout_seconds: u32,
    pub public_url: Option<&'a str>,
    pub pages: &'a Pages,
    pub brand: Option<&'a str>,
    pub brand_url: Option<&'a str>,
    pub tickets: &'a Arc<dyn TicketStore>,
    pub ticket_ttl: Duration,
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

/// Whether buyers reach the gateway over https: by `public_url`, else by what the proxy in
/// front of us forwarded. Decides the `Secure` flag of the page's cookies.
pub fn public_https(request: &Request<Body>, public_url: Option<&str>) -> bool {
    if let Some(base) = public_url {
        return base.starts_with("https://");
    }
    request
        .headers()
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("https"))
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
/// gateway's own table of tokens; the gas-sponsoring extension is declared when an option is
/// paid through Permit2 and its facilitator sponsors the approval.
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
        let permit2 = extra.get("assetTransferMethod") == Some(&Value::from("permit2"));
        if permit2 && supported.is_some_and(|s| s.declares(supported::EIP2612_GAS_SPONSORING)) {
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

/// A 402 with the requirements in the `PAYMENT-REQUIRED` header and as the JSON body. A
/// challenge is for this request only, so caches must not answer another with it.
pub fn payment_required_response(mut requirements: PaymentRequired, error: &str) -> Response {
    requirements.error = Some(error.to_owned());
    let encoded = encode(&requirements);
    let mut response = (StatusCode::PAYMENT_REQUIRED, axum::Json(requirements)).into_response();
    let headers = response.headers_mut();
    headers.insert(PAYMENT_REQUIRED, encoded);
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(VARY, HeaderValue::from_static("Accept"));
    response
}

/// Answers a 402 the way the client asked for it: the page for a browser, JSON for everyone
/// else. Built while the request is still at hand, since the challenge may be answered after the
/// request has gone upstream.
pub struct Challenger<'a> {
    pages: &'a Pages,
    html: bool,
    vars: PageVars,
    /// The ticket to issue if this request settles: only a GET from the page.
    ticket: Option<TicketRequest>,
}

struct TicketRequest {
    ticket: Ticket,
    cookie_path: String,
    secure: bool,
}

impl<'a> Challenger<'a> {
    fn new(
        ctx: &ChargeContext<'a>,
        charge: &Charge<'_>,
        requirements: &PaymentRequired,
        request: &Request<Body>,
    ) -> Self {
        let html = negotiate::prefers_html(
            request
                .headers()
                .get(ACCEPT)
                .and_then(|value| value.to_str().ok()),
        );
        let from_page = request
            .headers()
            .get(PAGE_MARKER)
            .is_some_and(|value| value == "1");
        let method = ticket::normalized_method(request.method());
        let ticket = (from_page && method == "GET").then(|| TicketRequest {
            ticket: Ticket {
                method: method.to_owned(),
                path_and_query: request
                    .uri()
                    .path_and_query()
                    .map_or("/", |pq| pq.as_str())
                    .to_owned(),
                rule: charge.rule.map(str::to_owned),
            },
            cookie_path: ticket::cookie_path(request.uri().path()).to_owned(),
            secure: requirements.resource.url.starts_with("https://"),
        });
        Self {
            pages: ctx.pages,
            html,
            vars: page_vars(ctx, charge, requirements),
            ticket,
        }
    }

    /// Gives the paid response a ticket for the reload that delivers the purchase, when the
    /// request came from the page.
    async fn issue_ticket(&self, ctx: &ChargeContext<'_>, response: &mut Response) {
        let Some(wanted) = &self.ticket else { return };
        let id = ticket::new_id();
        match ctx
            .tickets
            .issue(&id, wanted.ticket.clone(), ctx.ticket_ttl)
            .await
        {
            Ok(()) => {
                response.headers_mut().append(
                    http::header::SET_COOKIE,
                    ticket::set_cookie(&id, &wanted.cookie_path, ctx.ticket_ttl, wanted.secure),
                );
                tracing::debug!("ticket issued for the page's reload");
            }
            Err(error) => tracing::error!(error = %error, "ticket couldn't be issued"),
        }
    }

    pub fn respond(&self, requirements: PaymentRequired, error: &str) -> Response {
        if !self.html {
            return payment_required_response(requirements, error);
        }
        let mut requirements = requirements;
        requirements.error = Some(error.to_owned());
        let encoded = encode(&requirements);
        let vars = PageVars {
            error: if error == NO_PAYMENT {
                String::new()
            } else {
                error.to_owned()
            },
            challenge_json: serde_json::to_string(&requirements).expect("the challenge serializes"),
            ..self.vars.clone()
        };
        let html = self.pages.render_402(&vars);
        let mut response = (StatusCode::PAYMENT_REQUIRED, html).into_response();
        let headers = response.headers_mut();
        headers.insert(PAYMENT_REQUIRED, encoded);
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        headers.insert(VARY, HeaderValue::from_static("Accept"));
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
        headers.insert(
            "content-security-policy",
            HeaderValue::from_static(PAGE_CSP),
        );
        headers.insert(
            "x-content-type-options",
            HeaderValue::from_static("nosniff"),
        );
        response
    }
}

/// What the page says about the charge, from the option a browser can pay (the first EIP-3009
/// `exact` option on an EVM network, else the first) and the gateway's branding.
fn page_vars(
    ctx: &ChargeContext<'_>,
    charge: &Charge<'_>,
    requirements: &PaymentRequired,
) -> PageVars {
    let index = payable_index(&requirements.accepts).unwrap_or(0);
    let compiled = charge.accepts.get(index);
    let offered = requirements.accepts.get(index);
    let network = compiled.map(|c| c.network.as_str()).unwrap_or_default();
    let known = catalog::network(network);
    let amount = compiled
        .map(|c| format_units(c.amount, c.decimals))
        .unwrap_or_default();
    let asset_symbol = compiled
        .and_then(|c| known.and_then(|net| catalog::asset(net, c.asset)))
        .map(|asset| asset.symbol.to_owned())
        .or_else(|| {
            offered
                .and_then(|o| o.extra.get("name"))
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .or_else(|| compiled.map(|c| shorten(&c.asset.to_string())))
        .unwrap_or_default();
    PageVars {
        brand: ctx.brand.map(str::to_owned),
        brand_url: ctx.brand_url.map(str::to_owned),
        price: format!("{amount} {asset_symbol}").trim().to_owned(),
        cli_command: cli_command(&requirements.resource.url, &amount),
        amount,
        asset_symbol,
        description: charge.description.to_owned(),
        resource_url: requirements.resource.url.clone(),
        network_name: known
            .map(|net| net.label.to_owned())
            .unwrap_or_else(|| network.to_owned()),
        pay_to: compiled.map(|c| c.pay_to.to_string()).unwrap_or_default(),
        error: String::new(),
        challenge_json: String::new(),
    }
}

/// The first option the page can pay: `exact` on an EVM network through EIP-3009, the transfer
/// method a wallet signs in one step. (Permit2 needs an allowance and a second signature, which
/// the page doesn't do yet.)
pub fn payable_index(accepts: &[PaymentRequirements]) -> Option<usize> {
    accepts.iter().position(|offer| {
        let method = offer
            .extra
            .get("assetTransferMethod")
            .and_then(Value::as_str)
            .unwrap_or("eip3009");
        offer.scheme == "exact" && offer.network.starts_with("eip155:") && method == "eip3009"
    })
}

/// `amount` in the token's units with `decimals` places, trailing zeros dropped: 10000 with 6
/// decimals is `0.01`.
pub fn format_units(amount: U256, decimals: u8) -> String {
    let digits = amount.to_string();
    let decimals = usize::from(decimals);
    if decimals == 0 {
        return digits;
    }
    let padded = format!("{digits:0>width$}", width = decimals + 1);
    let (whole, fraction) = padded.split_at(padded.len() - decimals);
    let fraction = fraction.trim_end_matches('0');
    if fraction.is_empty() {
        whole.to_owned()
    } else {
        format!("{whole}.{fraction}")
    }
}

/// The radius-cli command that pays for `url`, with the URL single-quoted for a POSIX shell.
pub fn cli_command(url: &str, amount: &str) -> String {
    let quoted = url.replace('\'', "'\\''");
    format!("radius-cli wallet pay get '{quoted}' --threshold {amount} -y")
}

/// `0x4373…Fe6e` for an address.
fn shorten(address: &str) -> String {
    if address.len() > 12 {
        format!("{}…{}", &address[..6], &address[address.len() - 4..])
    } else {
        address.to_owned()
    }
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
    let challenger = Challenger::new(ctx, charge, &requirements, &request);
    let Some(signature) = request
        .headers()
        .get(PAYMENT_SIGNATURE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
    else {
        return (
            challenger.respond(requirements, NO_PAYMENT),
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
            challenger.respond(
                requirements,
                &format!("x402 version {X402_VERSION} is required"),
            ),
            ChargeOutcome::Challenged,
        );
    }
    if let Some(other) = other_resource(&payload, &requirements.resource.url) {
        let error = format!("the payment is for {other}, not this resource");
        return (
            challenger.respond(requirements, &error),
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
            challenger.respond(
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
    // Checked here so that a facilitator that doesn't check the signed terms can't settle them.
    if let Some((field, offered_field)) = offered.signed_mismatch(&payload) {
        let error = format!("the signed {field} doesn't match the offered {offered_field}");
        return (
            challenger.respond(requirements, &error),
            ChargeOutcome::Challenged,
        );
    }

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
                    challenger.respond(
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

    let mut held = Held {
        claims: ctx.claims.clone(),
        id,
        stage: Stage::Unused,
    };
    let (response, outcome) = claimed(
        ctx,
        &challenger,
        requirements,
        &facilitator,
        &payload,
        &offered,
        &mut held,
        request,
        forward,
    )
    .await;
    let unknown = (outcome == ChargeOutcome::Unknown).then(|| UnknownSettlement {
        payment_response: response
            .headers()
            .get(PAYMENT_RESPONSE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
    });
    held.end(unknown).await;
    (response, outcome)
}

/// A claimed payment while its request is handled. Until `/settle` is called the payment is
/// unused, so the claim is released when the request ends, also when it ends because the buyer
/// disconnected and the server dropped the request's future. Once `/settle` is called the claim
/// stays whatever the facilitator answers, since the transfer may have been broadcast, and an
/// outcome that is unknown, including one never read because the request was dropped, is
/// recorded.
struct Held {
    claims: Arc<dyn ClaimGuard>,
    id: String,
    stage: Stage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Unused,
    Settling,
    Ended,
}

impl Held {
    /// Called before `/settle`: from here the claim stays.
    fn settling(&mut self) {
        self.stage = Stage::Settling;
    }

    /// Ends the hold for a request that was answered, with its settlement when that is unknown.
    async fn end(mut self, unknown: Option<UnknownSettlement>) {
        if self.stage == Stage::Unused {
            if let Err(error) = self.claims.release(&self.id).await {
                tracing::error!(error = %error, "payment release failed");
            }
        } else if let Some(unknown) = unknown
            && let Err(error) = self.claims.mark_unknown(&self.id, unknown).await
        {
            tracing::error!(error = %error, "payment mark failed");
        }
        self.stage = Stage::Ended;
    }
}

impl Drop for Held {
    /// A request dropped before it ended: releases an unused payment, or records a settlement
    /// whose answer was never read as unknown. Neither can be awaited here, so it's spawned.
    fn drop(&mut self) {
        let stage = self.stage;
        if stage == Stage::Ended {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let claims = self.claims.clone();
        let id = std::mem::take(&mut self.id);
        tracing::debug!(
            ?stage,
            "the request was dropped while its payment was claimed"
        );
        runtime.spawn(async move {
            let result = if stage == Stage::Unused {
                claims.release(&id).await
            } else {
                let unknown = UnknownSettlement {
                    payment_response: None,
                };
                claims.mark_unknown(&id, unknown).await
            };
            if let Err(error) = result {
                tracing::error!(error = %error, "payment release or mark failed");
            }
        });
    }
}

/// The flow once the payment is claimed. Calls `held.settling()` before `/settle`.
#[allow(clippy::too_many_arguments)]
async fn claimed<F, Fut>(
    ctx: &ChargeContext<'_>,
    challenger: &Challenger<'_>,
    requirements: PaymentRequired,
    facilitator: &str,
    payload: &Value,
    offered: &PaymentRequirements,
    held: &mut Held,
    request: Request<Body>,
    forward: F,
) -> (Response, ChargeOutcome)
where
    F: FnOnce(Request<Body>) -> Fut,
    Fut: Future<Output = Response>,
{
    let verification = match ctx.facilitator.verify(facilitator, payload, offered).await {
        Ok(verification) => verification,
        Err(error) => return (facilitator_failed(error), ChargeOutcome::Unavailable),
    };
    if !verification.is_valid {
        let reason = verification
            .invalid_reason
            .as_deref()
            .unwrap_or("the payment is invalid");
        tracing::debug!(reason, "payment didn't verify");
        return (
            challenger.respond(requirements, reason),
            ChargeOutcome::Challenged,
        );
    }

    let response = forward(request).await;
    if !response.status().is_success() {
        return (response, ChargeOutcome::UpstreamFailed);
    }

    // A body that fails or doesn't arrive in time is an upstream failure like any other:
    // nothing was settled, so the payment can be tried again.
    let (parts, body) = response.into_parts();
    let buffered = tokio::time::timeout(ctx.upstream_timeout, buffer(body, ctx.paid_body_limit));
    let body = match buffered.await {
        Ok(Ok(body)) => body,
        Ok(Err(error)) => {
            tracing::warn!(error = %error, "upstream body failed before settlement");
            return (
                error_response(
                    StatusCode::BAD_GATEWAY,
                    "upstream_unavailable",
                    "the upstream's response failed",
                ),
                ChargeOutcome::UpstreamFailed,
            );
        }
        Err(_) => {
            let error = UpstreamError::Timeout(ctx.upstream_timeout);
            return (upstream_failed(error), ChargeOutcome::UpstreamFailed);
        }
    };

    // From here the payment stays claimed, whatever the facilitator answers: it may have
    // broadcast the transfer before something failed (a timeout, a lost connection, a failed
    // receipt wait it reports as `settlement_pending`), and the transfer can still land. Only a
    // refusal asks the buyer for a new payment; any other failure is answered as unknown.
    held.settling();
    let settlement = match ctx.facilitator.settle(facilitator, payload, offered).await {
        Ok(settlement) => settlement,
        Err(error) => {
            tracing::error!(error = %error, network = offered.network, "settlement outcome unknown");
            return (settlement_unknown(None), ChargeOutcome::Unknown);
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
        let mut failed = challenger.respond(requirements, &format!("settlement failed: {reason}"));
        failed
            .headers_mut()
            .insert(PAYMENT_RESPONSE, encode(&settlement));
        return (failed, ChargeOutcome::Challenged);
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
    keep_from_shared_caches(paid.headers_mut());
    challenger.issue_ticket(ctx, &mut paid).await;
    (paid, ChargeOutcome::Paid)
}

/// Keeps shared caches from storing a paid response, which they could otherwise give another
/// buyer without payment: `Cache-Control` gets `private`, and loses `public`, unless it already
/// has `private` or `no-store`.
fn keep_from_shared_caches(headers: &mut HeaderMap) {
    let directives: Vec<String> = headers
        .get_all(CACHE_CONTROL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(|directive| directive.trim().to_owned())
        .filter(|directive| !directive.is_empty())
        .collect();
    let is = |directive: &str, name: &str| directive.eq_ignore_ascii_case(name);
    if directives
        .iter()
        .any(|directive| is(directive, "private") || is(directive, "no-store"))
    {
        return;
    }
    let kept = directives
        .iter()
        .map(String::as_str)
        .filter(|directive| !is(directive, "public"));
    let value = std::iter::once("private").chain(kept).collect::<Vec<_>>();
    if let Ok(value) = HeaderValue::from_str(&value.join(", ")) {
        headers.insert(CACHE_CONTROL, value);
    }
}

/// The resource a payment names when it isn't `resource_url`, the one this request's challenge
/// names; none when they're the same or the payment names none (no `resource.url` string). Both
/// are compared as the WHATWG URL Standard serializes them (scheme and host in lower case, a
/// default port dropped, dot segments resolved), without a fragment. The buyer's signature
/// doesn't cover `resource`, so this catches a payment presented at the wrong route and binds
/// nothing.
fn other_resource(payload: &Value, resource_url: &str) -> Option<String> {
    let named = payload.pointer("/resource/url")?.as_str()?;
    let canonical = |text: &str| {
        reqwest::Url::parse(text).ok().map(|mut url| {
            url.set_fragment(None);
            url
        })
    };
    let same = canonical(named).is_some_and(|url| Some(url) == canonical(resource_url));
    (!same).then(|| named.to_owned())
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
    fn formats_units_and_the_cli_command() {
        assert_eq!(format_units(U256::from(10000u64), 6), "0.01");
        assert_eq!(format_units(U256::from(1_000_000u64), 6), "1");
        assert_eq!(format_units(U256::from(1_234_567u64), 6), "1.234567");
        assert_eq!(format_units(U256::from(5u64), 0), "5");
        assert_eq!(format_units(U256::ZERO, 6), "0");
        assert_eq!(
            cli_command("https://a.example/x?it's", "0.01"),
            "radius-cli wallet pay get 'https://a.example/x?it'\\''s' --threshold 0.01 -y"
        );
    }

    #[test]
    fn picks_the_option_a_wallet_can_sign() {
        let option = |method: Option<&str>, network: &str| PaymentRequirements {
            scheme: "exact".into(),
            network: network.into(),
            amount: "1".into(),
            asset: "0x33ad9e4BD16B69B5BFdED37D8B5D9fF9aba014Fb".into(),
            pay_to: "0x4373dD700774F8C3f649AC58B7EDCC112785Fe6e".into(),
            max_timeout_seconds: 60,
            extra: match method {
                Some(m) => serde_json::json!({ "assetTransferMethod": m }),
                None => serde_json::json!({}),
            },
        };
        let accepts = [
            option(Some("permit2"), "eip155:72344"),
            option(None, "solana:x"),
            option(None, "eip155:72344"),
        ];
        assert_eq!(payable_index(&accepts), Some(2));
        assert_eq!(payable_index(&accepts[..2]), None);
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
