//! Where rate-limit and free-quota counts live, and where used payments are claimed. The gate
//! standard needs an atomic increment with an expiry; any store with one will do behind these
//! traits. Only an in-process store exists today (`memory`), so limits and claims are per
//! instance.

pub mod memory;

use std::time::Duration;

use async_trait::async_trait;
pub use policy::eval::CounterUnavailable;

pub use memory::MemoryStore;

#[async_trait]
pub trait CounterStore: Send + Sync {
    /// Adds one to the counter and returns its new value. The counter expires `ttl` after this
    /// call unless the store already has a shorter expiry for it.
    async fn increment(&self, key: &str, ttl: Duration) -> Result<u64, CounterUnavailable>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the claim store is unavailable")]
pub struct ClaimError;

/// A claimed payment whose settlement was attempted without a verdict, so the transfer may still
/// land. A repeat of the payment is told so, with the `PAYMENT-RESPONSE` value the facilitator's
/// answer gave when it named a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownSettlement {
    pub payment_response: Option<String>,
}

#[async_trait]
pub trait ClaimGuard: Send + Sync {
    /// Claims `id` for `ttl`. False when it's already claimed.
    async fn claim(&self, id: &str, ttl: Duration) -> Result<bool, ClaimError>;
    /// Releases a claim before its expiry, for a payment that wasn't used after all.
    async fn release(&self, id: &str) -> Result<(), ClaimError>;
    /// Records that the claimed payment's settlement outcome is unknown, until the claim expires.
    async fn mark_unknown(&self, id: &str, unknown: UnknownSettlement) -> Result<(), ClaimError>;
    /// The claimed payment's unknown settlement, if one was recorded.
    async fn unknown(&self, id: &str) -> Result<Option<UnknownSettlement>, ClaimError>;
}
