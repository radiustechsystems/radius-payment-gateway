//! Logging. One line per request is written by the gate (`gate.rs`) with the fields the gate
//! standard asks for (section 7): the policy version, the deciding rule, the decision and whether
//! a limit was reached. Nothing here, or anywhere, logs `PAYMENT-SIGNATURE`, `Authorization` or a
//! payment payload.

use anyhow::Context;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

use crate::config::{Config, LogFormat};

pub fn init(config: &Config) -> anyhow::Result<()> {
    let filter = EnvFilter::try_new(&config.log_filter).context("invalid log filter")?;
    let registry = tracing_subscriber::registry().with(filter);
    match config.log_format {
        LogFormat::Json => registry
            .with(fmt::layer().json().flatten_event(true))
            .try_init(),
        LogFormat::Text => registry.with(fmt::layer()).try_init(),
    }
    .context("logging is already initialized")
}
