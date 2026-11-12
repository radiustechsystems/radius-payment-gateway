//! Shared domain types and business logic for Radius platform services.
//!
//! This crate is transport-agnostic: it must not depend on HTTP frameworks,
//! OpenAPI tooling, or persistence layers. API applications map these types
//! to and from their own request/response DTOs.

pub mod endpoint;
pub mod matching;
pub mod payment;
pub mod pricing;
pub mod pricing_md;
pub mod slug;
pub mod validation;
pub mod wallet;
