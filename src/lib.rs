//! `radius-gateway`: a reverse proxy that enforces a Radius Platform compiled policy in front of
//! an API. See the README for how it's deployed and `docs/gates/standard.md` in radius-platform
//! for what it must do.

pub mod build;
pub mod config;
pub mod counters;
pub mod error;
pub mod eval;
pub mod gate;
pub mod pages;
pub mod policy;
pub mod proxy;
pub mod server;
pub mod telemetry;
pub mod ticket;
pub mod x402;

pub use config::Config;
pub use server::App;
