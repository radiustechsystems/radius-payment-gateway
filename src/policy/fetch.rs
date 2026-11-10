//! `GET /organizations/{org}/projects/{project}/policy/compiled`, with `If-None-Match`.

use std::time::Duration;

use bytes::Bytes;
use http::StatusCode;
use http::header::{ACCEPT, AUTHORIZATION, ETAG, IF_NONE_MATCH};
use uuid::Uuid;

use crate::config::Secret;

#[derive(Debug)]
pub enum Fetched {
    /// The policy hasn't changed since the ETag we sent.
    NotModified,
    Document {
        body: Bytes,
        /// The `ETag` header as the platform sent it, echoed back verbatim next time.
        etag: Option<String>,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("request failed: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("the platform answered {0}")]
    Status(StatusCode),
}

/// The platform API, for one project.
pub struct PlatformClient {
    http: reqwest::Client,
    url: String,
    key: Secret,
}

impl PlatformClient {
    pub fn new(
        base: &str,
        key: Secret,
        organization_id: &str,
        project_id: Uuid,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(concat!("radius-gateway/", env!("CARGO_PKG_VERSION")))
            .build()?;
        let url = format!(
            "{}/organizations/{organization_id}/projects/{project_id}/policy/compiled",
            base.trim_end_matches('/')
        );
        Ok(Self { http, url, key })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub async fn compiled(&self, if_none_match: Option<&str>) -> Result<Fetched, FetchError> {
        let mut request = self
            .http
            .get(&self.url)
            .header(ACCEPT, "application/json")
            .header(AUTHORIZATION, format!("Bearer {}", self.key.expose()));
        if let Some(etag) = if_none_match {
            request = request.header(IF_NONE_MATCH, etag);
        }
        let response = request.send().await?;
        let status = response.status();
        if status == StatusCode::NOT_MODIFIED {
            return Ok(Fetched::NotModified);
        }
        if !status.is_success() {
            return Err(FetchError::Status(status));
        }
        let etag = response
            .headers()
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = response.bytes().await?;
        Ok(Fetched::Document { body, etag })
    }
}
