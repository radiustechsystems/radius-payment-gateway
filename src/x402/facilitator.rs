//! The facilitator's `/supported`, `/verify` and `/settle`, as x402 version 2 defines them. A
//! verdict comes back however the facilitator sends it: some answer a refusal with an error
//! status and the verdict as the body. Anything that isn't a verdict, or no answer in time, is an
//! error.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use http::StatusCode;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::X402_VERSION;
use super::supported::Supported;
use super::types::{PaymentRequirements, SettleResponse, VerifyResponse};

#[derive(Debug, thiserror::Error)]
pub enum FacilitatorError {
    #[error("POST {url} failed: {source}")]
    Transport { url: String, source: reqwest::Error },
    #[error("POST {url} answered {status} without a verdict")]
    NoVerdict { url: String, status: StatusCode },
}

/// How long a facilitator's `/supported` answer is used before it's asked again.
const SUPPORTED_MAX_AGE: Duration = Duration::from_secs(60 * 60);

struct Cached {
    supported: Arc<Supported>,
    fetched_at: Instant,
}

pub struct FacilitatorClient {
    http: reqwest::Client,
    supported: DashMap<String, Cached>,
}

impl FacilitatorClient {
    pub fn new(timeout: Duration) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(concat!("radius-gateway/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            http,
            supported: DashMap::new(),
        })
    }

    /// What the facilitator supports, as last fetched; none before the first successful fetch.
    pub fn supported(&self, facilitator: &str) -> Option<Arc<Supported>> {
        self.supported
            .get(facilitator)
            .map(|cached| cached.supported.clone())
    }

    /// What the facilitator supports, fetching it when it isn't cached yet. For the request path:
    /// the poller keeps the cache warm, so this normally doesn't fetch.
    pub async fn supported_or_fetch(&self, facilitator: &str) -> Option<Arc<Supported>> {
        if let Some(supported) = self.supported(facilitator) {
            return Some(supported);
        }
        match self.refresh_supported(facilitator).await {
            Ok(supported) => Some(supported),
            Err(error) => {
                tracing::warn!(facilitator, error = %error, "couldn't read what the facilitator supports");
                None
            }
        }
    }

    /// Refreshes `/supported` for every facilitator named, when the cached answer is older than
    /// an hour or missing. Failures keep the cached answer and are logged.
    pub async fn refresh_stale(&self, facilitators: impl IntoIterator<Item = String>) {
        for facilitator in facilitators {
            let fresh = self
                .supported
                .get(&facilitator)
                .is_some_and(|cached| cached.fetched_at.elapsed() < SUPPORTED_MAX_AGE);
            if fresh {
                continue;
            }
            if let Err(error) = self.refresh_supported(&facilitator).await {
                tracing::warn!(facilitator, error = %error, "couldn't read what the facilitator supports");
            }
        }
    }

    async fn refresh_supported(&self, facilitator: &str) -> Result<Arc<Supported>, String> {
        let url = format!("{}/supported", facilitator.trim_end_matches('/'));
        let response = self
            .http
            .get(&url)
            .header(http::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|error| format!("GET {url} failed: {error}"))?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!("GET {url} answered {status}"));
        }
        let supported: Supported = response
            .json()
            .await
            .map_err(|error| format!("GET {url} answered something else: {error}"))?;
        tracing::info!(
            facilitator,
            kinds = supported.kinds.len(),
            extensions = supported.extensions.join(","),
            "facilitator capabilities loaded"
        );
        let supported = Arc::new(supported);
        self.supported.insert(
            facilitator.to_owned(),
            Cached {
                supported: supported.clone(),
                fetched_at: Instant::now(),
            },
        );
        Ok(supported)
    }

    pub async fn verify(
        &self,
        facilitator: &str,
        payload: &Value,
        requirements: &PaymentRequirements,
    ) -> Result<VerifyResponse, FacilitatorError> {
        self.post(facilitator, "verify", payload, requirements, "isValid")
            .await
    }

    pub async fn settle(
        &self,
        facilitator: &str,
        payload: &Value,
        requirements: &PaymentRequirements,
    ) -> Result<SettleResponse, FacilitatorError> {
        let mut settlement: SettleResponse = self
            .post(facilitator, "settle", payload, requirements, "success")
            .await?;
        if settlement.network.is_empty() {
            settlement.network = requirements.network.clone();
        }
        Ok(settlement)
    }

    async fn post<T: DeserializeOwned>(
        &self,
        facilitator: &str,
        endpoint: &str,
        payload: &Value,
        requirements: &PaymentRequirements,
        verdict_field: &str,
    ) -> Result<T, FacilitatorError> {
        let url = format!("{}/{endpoint}", facilitator.trim_end_matches('/'));
        let body = json!({
            "x402Version": X402_VERSION,
            "paymentPayload": payload,
            "paymentRequirements": requirements,
        });
        let response = self
            .http
            .post(&url)
            .header(http::header::ACCEPT, "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|source| FacilitatorError::Transport {
                url: url.clone(),
                source,
            })?;
        let status = response.status();
        let verdict: Value = response.json().await.unwrap_or(Value::Null);
        if !verdict.get(verdict_field).is_some_and(Value::is_boolean) {
            return Err(FacilitatorError::NoVerdict { url, status });
        }
        serde_json::from_value(verdict).map_err(|_| FacilitatorError::NoVerdict { url, status })
    }
}
