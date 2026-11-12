//! The compiled form: one self-contained document per project that enforcement points read. It's
//! the wire contract between the platform and every enforcement point (the Rust evaluator in
//! [`crate::eval`] is the reference, the conformance vectors in `tests/vectors` the contract).
//!
//! Everything a decision needs is resolved: endpoints to methods and paths, windows to seconds,
//! wallets to addresses, and prices to each accepted asset's atomic units with its decimals and
//! facilitator. Evaluating it needs no lookups.

use alloy_primitives::{Address, U256};
use domain::matching::{MethodMatch, PathPattern};
use domain::pricing::catalog::{Mode, Scheme};
use domain::pricing::micros::Micros;
use domain::wallet::checksummed_serde;
use ipnet::IpNet;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::spec::{AgentMatch, ClientIp, Failure, Headers, LimitKey, SchemaId, Verdict};

/// A compiled policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Compiled {
    /// `radius.policy/0.2` when a rule matches on `agent`, otherwise `radius.policy/0.1`.
    pub schema: SchemaId,
    /// Increases with every change to the project's policy, endpoints or wallets it names.
    pub version: u64,
    pub project_id: Uuid,
    /// RFC 3339.
    pub generated_at: String,
    /// `test` or `production`: every accepted network is of this mode.
    #[schemars(with = "String")]
    pub mode: Mode,
    pub defaults: CompiledDefaults,
    /// In order: the first rule whose match holds is the only one applied. The top-level rules
    /// come first, then endpoints' rules, the most specific route's first (a literal segment
    /// before `:name`, `:name` before a trailing `*`). Where a less specific endpoint's rules
    /// would follow, an endpoint's rules end with `<slug>/_unmatched`, which gives its other
    /// requests `defaults.unmatched`: a request only ever meets one endpoint's rules.
    pub rules: Vec<CompiledRule>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompiledDefaults {
    pub unmatched: Verdict,
    pub failure: Failure,
    pub client_ip: ClientIp,
    pub headers: Headers,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompiledRule {
    /// Names the rule's counters. Stable across edits, and across renames made through the rule
    /// API; a rule renamed in a replaced document gets a new one, so its counters start over.
    pub uid: Uuid,
    /// The rule's key, for telemetry and messages: its authored id, after its endpoint's slug and a
    /// `/` for an endpoint's rule (`tx-lookup/freemium`). `<slug>/_unmatched` is the rule the
    /// compiler adds to end an endpoint's rules; authored ids never start with `_`.
    pub id: String,
    #[serde(rename = "match")]
    pub matcher: CompiledMatch,
    /// Beyond it, matching requests are denied with `429 rate_limited`. Checked first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<CompiledLimit>,
    /// Within it, matching requests are allowed free; beyond it, the action applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub free_quota: Option<CompiledLimit>,
    pub action: CompiledAction,
}

/// Which requests a rule is for. Fields present are ANDed; values in a list are ORed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompiledMatch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<CompiledEndpoint>,
    /// Normalized CIDRs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(with = "Vec<String>")]
    pub ip_in: Vec<IpNet>,
    /// Who the request's verified agent must be: a category, a Web Bot Auth signature agent
    /// origin, or both. Only in `radius.policy/0.2` documents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentMatch>,
}

/// An endpoint resolved to what a request is matched against.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompiledEndpoint {
    pub slug: String,
    /// HTTP methods; empty means any method.
    #[schemars(with = "Vec<String>")]
    pub methods: MethodMatch,
    /// `:name` matches one segment, a trailing `*` the path and everything below.
    #[schemars(with = "String")]
    pub path: PathPattern,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompiledLimit {
    pub key: LimitKey,
    pub quota: u64,
    /// The window in seconds; windows start at multiples of it since the Unix epoch.
    pub window_s: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
#[schemars(transform = charge_tag_alias)]
pub enum CompiledAction {
    Allow {},
    Deny {
        status: u16,
        code: String,
    },
    /// A payment. `x402`, its former name, is still accepted when reading older documents.
    #[serde(alias = "x402")]
    Charge {
        /// USD, e.g. `"0.001"`.
        #[schemars(with = "String")]
        price: Micros,
        description: String,
        /// One entry per accepted asset, in the order payers are offered them.
        accepts: Vec<PaymentRequirement>,
    },
}

/// One way to pay a charge action, resolved: what x402 calls a payment requirement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PaymentRequirement {
    #[schemars(with = "String")]
    pub scheme: Scheme,
    /// CAIP-2.
    pub network: String,
    /// The token's contract address, checksummed.
    #[serde(with = "checksummed_serde")]
    #[schemars(with = "String")]
    pub asset: Address,
    pub decimals: u8,
    /// The price in the token's smallest unit, as a decimal string.
    #[serde(serialize_with = "decimal", deserialize_with = "from_decimal")]
    #[schemars(with = "String")]
    pub amount: U256,
    #[serde(with = "checksummed_serde")]
    #[schemars(with = "String")]
    pub pay_to: Address,
    /// The facilitator's URL, or null where the network has no default and the seller names one.
    pub facilitator: Option<String>,
}

/// Lets the compiled schema accept `x402`, the charge action's former tag, which documents
/// compiled before the rename still carry until their policy is next written. Serde reads it
/// through the alias on [`CompiledAction::Charge`]; this keeps the published schema, which gates
/// validate against, in step with that. Drop both when the window in `docs/gates/changes.md`
/// ends.
fn charge_tag_alias(schema: &mut schemars::Schema) {
    let Some(variants) = schema
        .ensure_object()
        .get_mut("oneOf")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return;
    };
    for variant in variants {
        if let Some(tag) = variant.pointer_mut("/properties/type")
            && tag.get("const") == Some(&serde_json::json!("charge"))
        {
            *tag = serde_json::json!({ "type": "string", "enum": ["charge", "x402"] });
        }
    }
}

fn decimal<S: Serializer>(value: &U256, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(value)
}

fn from_decimal<'de, D: Deserializer<'de>>(deserializer: D) -> Result<U256, D::Error> {
    let text = String::deserialize(deserializer)?;
    U256::from_str_radix(&text, 10).map_err(serde::de::Error::custom)
}

impl Compiled {
    /// The JSON Schema of the compiled form.
    pub fn json_schema() -> serde_json::Value {
        serde_json::to_value(schemars::schema_for!(Compiled)).expect("schemas serialize")
    }
}
