//! One project's gate: its policy, the upstream it protects, and the decision for each request
//! (gate standard, section 2).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::response::{IntoResponse, Response};
use http::header::{HeaderName, HeaderValue};
use http::{Request, StatusCode};
use policy::eval::{Decision, Outcome};
use tracing::Instrument;

use crate::config::NoPolicy;
use crate::counters::{ClaimGuard, CounterStore};
use crate::error::error_response;
use crate::eval;
use crate::policy::PolicyHandle;
use crate::proxy::{Upstream, UpstreamError};
use crate::x402::{self, Charge, ChargeContext, FacilitatorClient};

pub struct Gate {
    pub policy: Arc<PolicyHandle>,
    pub upstream: Upstream,
    pub counters: Arc<dyn CounterStore>,
    pub claims: Arc<dyn ClaimGuard>,
    pub no_policy: NoPolicy,
    pub facilitator: Arc<FacilitatorClient>,
    pub payments: PaymentSettings,
}

/// The gate's side of a payment (gate standard, section 6).
#[derive(Debug, Clone)]
pub struct PaymentSettings {
    pub public_url: Option<String>,
    pub max_timeout_seconds: u32,
    pub paid_body_limit: usize,
    pub claim_ttl: std::time::Duration,
}

impl Gate {
    /// Decides and answers one request.
    pub async fn handle(&self, request: Request<Body>, peer: SocketAddr) -> Response {
        let span = tracing::info_span!(
            "request",
            method = %request.method(),
            policy.version = tracing::field::Empty,
            rule = tracing::field::Empty,
            decision = tracing::field::Empty,
            limited = tracing::field::Empty,
            status = tracing::field::Empty,
        );
        async {
            let response = self.decide_and_respond(request, peer).await;
            tracing::Span::current().record("status", response.status().as_u16());
            tracing::info!("handled");
            response
        }
        .instrument(span)
        .await
    }

    async fn decide_and_respond(&self, request: Request<Body>, peer: SocketAddr) -> Response {
        let span = tracing::Span::current();
        let Some(loaded) = self.policy.load() else {
            // No policy was ever loaded: `failure.no_policy`, from our configuration.
            span.record("rule", "none");
            return match self.no_policy {
                NoPolicy::Allow => {
                    span.record("decision", "allow");
                    self.forward(request, peer).await
                }
                NoPolicy::Deny => {
                    span.record("decision", "deny:policy_unavailable");
                    error_response(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "policy_unavailable",
                        "the policy isn't available yet",
                    )
                }
            };
        };
        let compiled = &loaded.compiled;
        span.record("policy.version", compiled.version);

        let described = eval::describe(&request, compiled, peer);
        if eval::ambiguous_path(compiled, &described) {
            span.record("decision", "deny:ambiguous_path");
            return error_response(
                StatusCode::BAD_REQUEST,
                "ambiguous_path",
                "the path's percent-encoding changes which rule applies; send it decoded",
            );
        }
        let decision = eval::evaluate(compiled, &described, self.counters.as_ref()).await;
        span.record("rule", decision.rule.as_deref().unwrap_or("none"));
        span.record(
            "limited",
            matches!(&decision.outcome, Outcome::Deny { code, .. } if code == "rate_limited"),
        );

        match &decision.outcome {
            Outcome::Allow => {
                span.record("decision", "allow");
                with_headers(self.forward(request, peer).await, &decision)
            }
            Outcome::Deny { status, code } => {
                span.record("decision", format!("deny:{code}").as_str());
                denied(*status, code, &decision)
            }
            Outcome::PaymentRequired {
                description,
                accepts,
                ..
            } => {
                let charge = Charge {
                    description,
                    accepts,
                };
                let context = ChargeContext {
                    facilitator: &self.facilitator,
                    claims: self.claims.as_ref(),
                    claim_ttl: self.payments.claim_ttl,
                    paid_body_limit: self.payments.paid_body_limit,
                    upstream_timeout: self.upstream.timeout(),
                    max_timeout_seconds: self.payments.max_timeout_seconds,
                    public_url: self.payments.public_url.as_deref(),
                };
                let (response, outcome) = x402::charge(&context, &charge, request, |request| {
                    self.forward(request, peer)
                })
                .await;
                span.record("decision", outcome.label());
                with_headers(response, &decision)
            }
        }
    }

    /// Forwards a request as the policy allowed it, streaming the upstream's response.
    pub async fn forward(&self, request: Request<Body>, peer: SocketAddr) -> Response {
        match self.upstream.forward(request, peer).await {
            Ok(response) => response.map(Body::new).into_response(),
            Err(error) => upstream_failed(error),
        }
    }
}

/// Adds the decision's headers (`RateLimit-*`, `Retry-After`) to a response.
pub fn with_headers(mut response: Response, decision: &Decision) -> Response {
    for (name, value) in &decision.headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            response.headers_mut().insert(name, value);
        }
    }
    response
}

fn denied(status: u16, code: &str, decision: &Decision) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN);
    let message = match code {
        "rate_limited" => "rate limit exceeded".to_owned(),
        "no_matching_rule" => "no policy rule matches this request".to_owned(),
        _ => match &decision.rule {
            Some(rule) => format!("denied by policy rule {rule:?}"),
            None => "denied by policy".to_owned(),
        },
    };
    with_headers(error_response(status, code, &message), decision)
}

pub fn upstream_failed(error: UpstreamError) -> Response {
    tracing::warn!(error = %error, "upstream request failed");
    match error {
        UpstreamError::Timeout(_) => error_response(
            StatusCode::GATEWAY_TIMEOUT,
            "upstream_timeout",
            "the upstream didn't answer in time",
        ),
        UpstreamError::Connect(_) | UpstreamError::Request(_) => error_response(
            StatusCode::BAD_GATEWAY,
            "upstream_unavailable",
            "the upstream couldn't be reached",
        ),
    }
}
