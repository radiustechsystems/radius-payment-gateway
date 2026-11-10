//! Fetches the policy in the background, on an interval, and never on the request path.

use std::sync::Arc;
use std::time::{Duration, Instant};

use uuid::Uuid;

use policy::compiled::CompiledAction;

use super::fetch::{Fetched, PlatformClient};
use super::store::{Loaded, Offer, PolicyHandle};
use super::validate::validate;
use crate::x402::FacilitatorClient;

pub struct Poller {
    client: PlatformClient,
    handle: Arc<PolicyHandle>,
    facilitators: Arc<FacilitatorClient>,
    interval: Duration,
    project_id: Uuid,
}

/// What one poll did.
#[derive(Debug, PartialEq, Eq)]
pub enum Polled {
    NotModified,
    Installed { version: u64 },
    Ignored { current: u64, offered: u64 },
}

impl Poller {
    pub fn new(
        client: PlatformClient,
        handle: Arc<PolicyHandle>,
        facilitators: Arc<FacilitatorClient>,
        interval: Duration,
        project_id: Uuid,
    ) -> Self {
        Self {
            client,
            handle,
            facilitators,
            interval,
            project_id,
        }
    }

    pub fn handle(&self) -> &Arc<PolicyHandle> {
        &self.handle
    }

    /// Fetches once, validates, and offers the document to the store; then makes sure what each
    /// facilitator the policy names supports is known. Failures are recorded and returned; the
    /// policy in force is untouched by them.
    pub async fn poll_once(&self) -> Result<Polled, String> {
        self.handle.record_attempt();
        let result = self.fetch_and_offer().await;
        if let Some(loaded) = self.handle.load() {
            let mut facilitators: Vec<String> = loaded
                .compiled
                .rules
                .iter()
                .filter_map(|rule| match &rule.action {
                    CompiledAction::Charge { accepts, .. } => Some(accepts),
                    _ => None,
                })
                .flatten()
                .filter_map(|accept| accept.facilitator.clone())
                .collect();
            facilitators.sort();
            facilitators.dedup();
            self.facilitators.refresh_stale(facilitators).await;
        }
        match &result {
            Ok(polled) => {
                self.handle.record_success();
                match polled {
                    Polled::NotModified => tracing::debug!("policy unchanged"),
                    Polled::Installed { version } => {
                        tracing::info!(version, "policy installed");
                    }
                    Polled::Ignored { current, offered } => {
                        tracing::warn!(
                            current,
                            offered,
                            "policy ignored: not newer than the one in force"
                        );
                    }
                }
            }
            Err(error) => {
                self.handle.record_error(error.clone());
                tracing::error!(
                    error = %error,
                    url = self.client.url(),
                    "policy fetch failed; keeping the policy in force"
                );
            }
        }
        result
    }

    async fn fetch_and_offer(&self) -> Result<Polled, String> {
        let etag = self.handle.etag();
        let fetched = self
            .client
            .compiled(etag.as_deref())
            .await
            .map_err(|error| error.to_string())?;
        let Fetched::Document { body, etag } = fetched else {
            return Ok(Polled::NotModified);
        };
        let validated = validate(&body, self.project_id).map_err(|error| error.to_string())?;
        for warning in &validated.warnings {
            tracing::warn!(warning, "policy loaded with a warning");
        }
        let loaded = Loaded {
            compiled: validated.compiled,
            etag,
            loaded_at: Instant::now(),
        };
        Ok(match self.handle.offer(loaded) {
            Offer::Installed { version } => Polled::Installed { version },
            Offer::Ignored { current, offered } => Polled::Ignored { current, offered },
        })
    }

    /// Polls forever, `interval` apart (give or take 10%, so replicas don't poll in step). With
    /// `first_now`, the first poll happens at once; otherwise after one interval.
    pub async fn run(self: Arc<Self>, first_now: bool) {
        if !first_now {
            tokio::time::sleep(self.jittered()).await;
        }
        loop {
            let _ = self.poll_once().await;
            tokio::time::sleep(self.jittered()).await;
        }
    }

    fn jittered(&self) -> Duration {
        let factor: f64 = rand::random_range(0.9..1.1);
        self.interval.mul_f64(factor).max(Duration::from_secs(1))
    }
}
