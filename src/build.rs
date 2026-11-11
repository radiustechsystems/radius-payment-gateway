//! What this binary is: the crate version and the git commit it was built from (see `build.rs`).

/// `0.1.0+abc123def`, or `0.1.0+abc123def-dirty`, or `0.1.0+unknown`.
pub const ID: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "+",
    env!("RADIUS_GATEWAY_COMMIT")
);

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const COMMIT: &str = env!("RADIUS_GATEWAY_COMMIT");
