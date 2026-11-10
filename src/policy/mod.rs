//! The compiled policy: fetched from the platform in the background, validated, and kept for the
//! request path to read without locking.

pub mod fetch;
pub mod poll;
pub mod store;
pub mod validate;

pub use fetch::{FetchError, Fetched, PlatformClient};
pub use poll::Poller;
pub use store::{Loaded, Offer, PolicyHandle};
pub use validate::{ACCEPTED_SCHEMAS, InvalidPolicy, Validated, validate};
