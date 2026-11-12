//! `radius.policy/0.1`: how a project decides what happens to each request to its endpoints.
//!
//! - [`spec`] is the **authored** form sellers write (YAML or JSON) and the API stores: defaults,
//!   rules for every endpoint, and each endpoint's own ordered rules. A rule is a `match`, an
//!   optional `rate_limit` and `free_quota`, and an `action` (allow, deny or charge).
//! - [`compiled`] is the **compiled** form enforcement points read: one self-contained document
//!   per project with every reference resolved, so evaluating it needs no lookups.
//! - [`compile`](compile::compile) turns one into the other against a [`compile::Context`] the
//!   caller loads, reporting every problem keyed by field, plus [`compile::warnings`].
//!
//! - [`endpoint_rules`] edits the rules of one endpoint as a list of their own.
//! - [`switch`] moves a policy between test and production, taking the tokens it accepts
//!   along to their counterpart networks.
//! - [`offers`] reads what each endpoint costs from the compiled form, for pricing.md.
//! - [`eval`] is the reference evaluator of the compiled form: [`eval::select`], then
//!   [`eval::decide`] once the caller has counted the request.
//!
//! The crate does no IO and has no async code.

pub mod compile;
pub mod compiled;
pub mod endpoint_rules;
pub mod eval;
pub mod offers;
pub mod spec;
pub mod switch;
pub mod window;

pub use compile::{
    Context, ContextEndpoint, ContextWallet, Overlap, Warning, compile, overlaps, warnings,
};
pub use compiled::Compiled;
pub use spec::Spec;
pub use switch::{AcceptChange, switch_mode};
