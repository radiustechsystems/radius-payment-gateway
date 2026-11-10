//! The policy in force, read lock-free on every request and replaced by the poller.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwapOption;
use policy::Compiled;
use serde::Serialize;

pub struct Loaded {
    pub compiled: Compiled,
    /// The `ETag` the document came with, for the next conditional request.
    pub etag: Option<String>,
    pub loaded_at: Instant,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Offer {
    Installed {
        version: u64,
    },
    /// The document isn't newer than the one in force.
    Ignored {
        current: u64,
        offered: u64,
    },
}

/// What the admin endpoint reports about fetching.
#[derive(Debug, Default, Clone, Serialize)]
pub struct Status {
    pub attempts: u64,
    pub last_attempt_unix: Option<u64>,
    pub last_success_unix: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Default)]
pub struct PolicyHandle {
    current: ArcSwapOption<Loaded>,
    status: Mutex<Status>,
    /// Serializes offers, so two concurrent polls can't install an older document over a newer.
    offers: Mutex<()>,
}

impl PolicyHandle {
    /// The policy in force, if one was ever loaded.
    pub fn load(&self) -> Option<Arc<Loaded>> {
        self.current.load_full()
    }

    /// The ETag to send with the next fetch.
    pub fn etag(&self) -> Option<String> {
        self.load().and_then(|loaded| loaded.etag.clone())
    }

    /// Installs the document unless the one in force is as new or newer.
    pub fn offer(&self, loaded: Loaded) -> Offer {
        let _serialized = self.offers.lock().unwrap_or_else(|e| e.into_inner());
        let offered = loaded.compiled.version;
        if let Some(current) = self.load()
            && current.compiled.version >= offered
        {
            return Offer::Ignored {
                current: current.compiled.version,
                offered,
            };
        }
        self.current.store(Some(Arc::new(loaded)));
        Offer::Installed { version: offered }
    }

    pub fn record_attempt(&self) {
        let mut status = self.status.lock().unwrap_or_else(|e| e.into_inner());
        status.attempts += 1;
        status.last_attempt_unix = Some(now_unix());
    }

    pub fn record_success(&self) {
        let mut status = self.status.lock().unwrap_or_else(|e| e.into_inner());
        status.last_success_unix = Some(now_unix());
        status.last_error = None;
    }

    pub fn record_error(&self, error: String) {
        let mut status = self.status.lock().unwrap_or_else(|e| e.into_inner());
        status.last_error = Some(error);
    }

    pub fn status(&self) -> Status {
        self.status
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// What the admin endpoint shows: the policy's version and age, and how fetching is going.
    pub fn snapshot(&self) -> serde_json::Value {
        let status = self.status();
        match self.load() {
            Some(loaded) => serde_json::json!({
                "loaded": true,
                "schema": serde_json::to_value(loaded.compiled.schema).unwrap_or_default(),
                "version": loaded.compiled.version,
                "project_id": loaded.compiled.project_id,
                "mode": loaded.compiled.mode.as_str(),
                "generated_at": loaded.compiled.generated_at,
                "rules": loaded.compiled.rules.len(),
                "age_s": loaded.loaded_at.elapsed().as_secs(),
                "fetch": status,
            }),
            None => serde_json::json!({ "loaded": false, "fetch": status }),
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}
