//! Counters and claims in this process's memory. Exact within one instance; a second instance
//! has its own counts, so limits apply per instance and a payment could be replayed once per
//! instance. Say so wherever the gateway is run with more than one replica.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;

use super::{ClaimError, ClaimGuard, CounterStore, CounterUnavailable, UnknownSettlement};

struct Count {
    value: u64,
    expires: Instant,
}

struct Claim {
    expires: Instant,
    unknown: Option<UnknownSettlement>,
}

impl Claim {
    fn new(expires: Instant) -> Self {
        Self {
            expires,
            unknown: None,
        }
    }
}

#[derive(Default)]
pub struct MemoryStore {
    counters: DashMap<String, Count>,
    claims: DashMap<String, Claim>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drops expired counters and claims. Counter keys carry their window, so an expired counter
    /// is never read again; this only frees memory.
    pub fn sweep(&self) {
        let now = Instant::now();
        self.counters.retain(|_, count| count.expires > now);
        self.claims.retain(|_, claim| claim.expires > now);
    }

    /// Sweeps every `every` for as long as the store is alive.
    pub fn spawn_sweeper(self: &Arc<Self>, every: Duration) {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                let Some(store) = weak.upgrade() else { break };
                store.sweep();
            }
        });
    }

    pub fn len(&self) -> usize {
        self.counters.len()
    }

    pub fn is_empty(&self) -> bool {
        self.counters.is_empty()
    }
}

#[async_trait]
impl CounterStore for MemoryStore {
    async fn increment(&self, key: &str, ttl: Duration) -> Result<u64, CounterUnavailable> {
        let now = Instant::now();
        // The entry holds its shard's lock, so the read-modify-write is atomic.
        let value = match self.counters.entry(key.to_owned()) {
            Entry::Occupied(mut occupied) => {
                let count = occupied.get_mut();
                if count.expires <= now {
                    count.value = 1;
                    count.expires = now + ttl;
                } else {
                    count.value += 1;
                }
                count.value
            }
            Entry::Vacant(vacant) => {
                vacant.insert(Count {
                    value: 1,
                    expires: now + ttl,
                });
                1
            }
        };
        Ok(value)
    }
}

#[async_trait]
impl ClaimGuard for MemoryStore {
    async fn claim(&self, id: &str, ttl: Duration) -> Result<bool, ClaimError> {
        let now = Instant::now();
        Ok(match self.claims.entry(id.to_owned()) {
            Entry::Occupied(mut occupied) if occupied.get().expires <= now => {
                occupied.insert(Claim::new(now + ttl));
                true
            }
            Entry::Occupied(_) => false,
            Entry::Vacant(vacant) => {
                vacant.insert(Claim::new(now + ttl));
                true
            }
        })
    }

    async fn release(&self, id: &str) -> Result<(), ClaimError> {
        self.claims.remove(id);
        Ok(())
    }

    async fn mark_unknown(&self, id: &str, unknown: UnknownSettlement) -> Result<(), ClaimError> {
        if let Some(mut claim) = self.claims.get_mut(id) {
            claim.unknown = Some(unknown);
        }
        Ok(())
    }

    async fn unknown(&self, id: &str) -> Result<Option<UnknownSettlement>, ClaimError> {
        let now = Instant::now();
        Ok(self
            .claims
            .get(id)
            .filter(|claim| claim.expires > now)
            .and_then(|claim| claim.unknown.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn counts_and_expires() {
        let store = MemoryStore::new();
        assert_eq!(store.increment("a", Duration::from_secs(60)).await, Ok(1));
        assert_eq!(store.increment("a", Duration::from_secs(60)).await, Ok(2));
        assert_eq!(store.increment("b", Duration::from_secs(60)).await, Ok(1));
        assert_eq!(store.increment("c", Duration::ZERO).await, Ok(1));
        // An expired counter starts over.
        assert_eq!(store.increment("c", Duration::from_secs(60)).await, Ok(1));
        store.sweep();
        assert_eq!(store.len(), 3);
    }

    #[tokio::test]
    async fn claims_once_until_released() {
        let store = MemoryStore::new();
        assert_eq!(store.claim("p", Duration::from_secs(60)).await, Ok(true));
        assert_eq!(store.claim("p", Duration::from_secs(60)).await, Ok(false));
        store.release("p").await.unwrap();
        assert_eq!(store.claim("p", Duration::from_secs(60)).await, Ok(true));
        assert_eq!(store.claim("q", Duration::ZERO).await, Ok(true));
        assert_eq!(store.claim("q", Duration::from_secs(60)).await, Ok(true));
    }

    #[tokio::test]
    async fn remembers_an_unknown_settlement_while_claimed() {
        let store = MemoryStore::new();
        let unknown = UnknownSettlement {
            payment_response: Some("e30=".to_owned()),
        };
        assert_eq!(store.claim("p", Duration::from_secs(60)).await, Ok(true));
        assert_eq!(store.unknown("p").await, Ok(None));
        store.mark_unknown("p", unknown.clone()).await.unwrap();
        assert_eq!(store.unknown("p").await, Ok(Some(unknown.clone())));
        // Only a claimed payment is marked, and a new claim starts without the mark.
        store.mark_unknown("q", unknown.clone()).await.unwrap();
        assert_eq!(store.unknown("q").await, Ok(None));
        assert_eq!(store.claim("r", Duration::ZERO).await, Ok(true));
        store.mark_unknown("r", unknown).await.unwrap();
        assert_eq!(store.unknown("r").await, Ok(None));
        assert_eq!(store.claim("r", Duration::from_secs(60)).await, Ok(true));
        assert_eq!(store.unknown("r").await, Ok(None));
    }
}
