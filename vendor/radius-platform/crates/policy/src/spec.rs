//! The authored form: what sellers write, what the API accepts and what the database stores.
//! JSON is canonical; YAML is the same document. Every object refuses unknown fields and tagged
//! enums are tagged by `type`, so typos fail loudly instead of being ignored.
//!
//! ```yaml
//! schema: radius.policy/0.1
//! defaults:
//!   unmatched: allow
//!   failure: { no_policy: allow, counter_error: within }
//!   client_ip: { header: cf-connecting-ip }
//!   headers: { ratelimit: true, retry_after: true }
//!   payment:
//!     accepts: [{ network: eip155:723487, asset: SBC }]
//!     pay_to: "0x…"
//! rules:
//!   - id: deny-abusive
//!     match: { ip_in: [203.0.113.0/24] }
//!     action: { type: deny, status: 403, code: source_blocked }
//! endpoints:
//!   tx-lookup:
//!     rules:
//!       - id: freemium
//!         free_quota: { key: ip, quota: 20, window: 5m }
//!         rate_limit: { key: ip, quota: 60, window: 1m }
//!         action: { type: charge, price: "0.001", description: "Transaction lookup, per call" }
//! ```
//!
//! Rules sit under the endpoint they're for. The top-level `rules` are for every endpoint (an IP
//! block, a first-party allow) and are tried first; then the rules of the endpoint the request is
//! for.
//!
//! A rule's `rate_limit` caps how many requests it lets through: beyond it they're denied with
//! `429 rate_limited`. Its `free_quota` lets some requests through free: beyond it, the action
//! applies. A rule can have both; then the rate limit applies first.
//!
//! Values are kept as written (prices, windows, CIDRs, addresses as text) and checked by
//! [`crate::compile`], which reports every problem keyed by field.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The `schema` value of this version.
pub const SCHEMA: &str = "radius.policy/0.1";

/// Which version of the policy format a document uses. Authored documents may name either; the
/// compiler emits `radius.policy/0.2` only for a policy with a rule that matches on `agent`, so
/// gates that don't know agent matching refuse that document instead of over-matching.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum SchemaId {
    #[default]
    #[serde(rename = "radius.policy/0.1")]
    V0_1,
    /// Adds `match.agent`.
    #[serde(rename = "radius.policy/0.2")]
    V0_2,
}

/// A project's policy as authored.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(title = "radius.policy/0.2")]
pub struct Spec {
    /// `radius.policy/0.1` or `radius.policy/0.2`; both accept every field.
    pub schema: SchemaId,
    #[serde(default)]
    pub defaults: Defaults,
    /// Rules for every endpoint, tried before the endpoint's own. In order; the first rule whose
    /// `match` holds is the only one applied.
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// Each endpoint's rules, by the endpoint's slug. At most 200 rules in all, counting the
    /// top-level ones.
    #[serde(default)]
    pub endpoints: BTreeMap<String, Endpoint>,
}

/// What a policy does with one endpoint's requests.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    /// Tried in order after the top-level rules; the first whose `match` holds is the only one
    /// applied. A request no rule decides gets `defaults.unmatched`.
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// What applies when no rule decides, and how enforcement points behave.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    /// What a request that matches no rule gets. Defaults to `allow`.
    #[serde(default)]
    pub unmatched: Verdict,
    #[serde(default)]
    pub failure: Failure,
    /// Where the client's IP address comes from. Defaults to `remote_addr`.
    #[serde(default)]
    pub client_ip: ClientIp,
    #[serde(default)]
    pub headers: Headers,
    /// How charge actions are paid unless they say otherwise. Without it, actions accept the
    /// mode's default token and must name their own `pay_to`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment: Option<Payment>,
}

/// Allow or deny.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    #[default]
    Allow,
    Deny,
}

/// What enforcement points do when something they rely on isn't there.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Failure {
    /// Only when no policy has ever been fetched; a stale policy keeps being enforced.
    #[serde(default)]
    pub no_policy: Verdict,
    /// When the counter store fails: `within` reads every counter as within its limit (requests
    /// aren't rate limited and a free quota lets them through), `over` as beyond it.
    #[serde(default)]
    pub counter_error: CounterError,
}

/// How a limit reads when its counter can't be updated.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CounterError {
    #[default]
    Within,
    Over,
}

/// Where the client's IP address comes from: the connection (`remote_addr`), or a header set by
/// a trusted proxy (`{ header: cf-connecting-ip }`; for a list, its first entry).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum ClientIp {
    RemoteAddr(RemoteAddr),
    Header(HeaderSource),
}

impl Default for ClientIp {
    fn default() -> Self {
        Self::RemoteAddr(RemoteAddr::RemoteAddr)
    }
}

/// The literal `remote_addr`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum RemoteAddr {
    #[serde(rename = "remote_addr")]
    RemoteAddr,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HeaderSource {
    /// The header's name, e.g. `cf-connecting-ip` or `x-forwarded-for`.
    pub header: String,
}

/// Response headers enforcement points add.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Headers {
    /// `RateLimit-Limit`, `RateLimit-Remaining` and `RateLimit-Reset` on rules with a rate limit or
    /// a free quota (the rate limit's, when a rule has both).
    #[serde(default = "yes")]
    pub ratelimit: bool,
    /// `Retry-After` on denials past a rate limit or a free quota.
    #[serde(default = "yes")]
    pub retry_after: bool,
}

fn yes() -> bool {
    true
}

impl Default for Headers {
    fn default() -> Self {
        Self {
            ratelimit: true,
            retry_after: true,
        }
    }
}

/// How charge actions are paid by default.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Payment {
    /// The networks and tokens payers may use, on the project's mode. Defaults to the mode's
    /// default token.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepts: Vec<Accept>,
    /// A registered wallet's address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pay_to: Option<String>,
}

/// One way to pay, by catalog IDs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Accept {
    /// CAIP-2 network ID, e.g. `eip155:723487`.
    pub network: String,
    /// The token's symbol on that network (`SBC`), or its contract address.
    pub asset: String,
    /// Defaults to `exact`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
}

/// A condition and what to do about it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// A slug, unique in its list (the top-level rules, or one endpoint's): lowercase letters,
    /// digits, `-` and `_`.
    pub id: String,
    /// Which requests the rule is for. Fields are ANDed; an empty match matches every request (of
    /// its endpoint, for an endpoint's rule).
    #[serde(rename = "match", default, skip_serializing_if = "Match::is_empty")]
    pub matcher: Match,
    /// How many matching requests the rule lets through; beyond it they're denied with
    /// `429 rate_limited`. Checked before the free quota.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<Limit>,
    /// How many matching requests are allowed free; beyond it, the action applies. Without one,
    /// the action applies to every matching request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub free_quota: Option<Limit>,
    pub action: Action,
}

/// Which requests a rule is for, besides the endpoint it sits under. Fields are ANDed; values in a
/// list are ORed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Match {
    /// CIDR ranges (IPv4 or IPv6) the client's address is in.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_in: Vec<String>,
    /// Who the agent is, as the gate verified it: its Cloudflare category, its Web Bot Auth
    /// signature, or both. A request from an agent the gate couldn't verify, or from a browser,
    /// doesn't match. Compiles to `radius.policy/0.2`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<AgentMatch>,
}

impl Match {
    pub fn is_empty(&self) -> bool {
        self.ip_in.is_empty() && self.agent.is_none()
    }
}

/// Which verified agents a rule is for. At least one field; fields are ANDed and values in a list
/// ORed. Each field is something the gate verified itself: a gate that can't verify one treats it
/// as absent, so the rule doesn't match.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentMatch {
    /// The agent's category as Cloudflare verified it, one of these.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub category: Vec<AgentCategory>,
    /// The origin of the agent's Web Bot Auth key directory, one of these (`https://` and a host,
    /// no path): the request carried a `Signature-Agent` naming it and a signature the gate
    /// verified against that directory.
    /// Known origins: `https://chatgpt.com` (OpenAI's agent) and
    /// `https://agent.bot.goog` (Google-Agent).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signature_agent: Vec<String>,
}

/// What a verified bot or agent does, Cloudflare's verified bot categories in snake case
/// (`Search Engine Crawler` is `search_engine_crawler`). A closed set: a gate that meets a
/// category it doesn't know treats the request as having none.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AgentCategory {
    AcademicResearch,
    Accessibility,
    AdvertisingAndMarketing,
    Aggregator,
    AiAssistant,
    AiCrawler,
    AiSearch,
    Archiver,
    FeedFetcher,
    MonitoringAndAnalytics,
    PagePreview,
    SearchEngineCrawler,
    SearchEngineOptimization,
    Security,
    SocialMediaMarketing,
    Webhooks,
    Other,
}

/// A number of requests per window: a rule's rate limit or its free quota.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Limit {
    pub key: LimitKey,
    /// Requests per window. At least 1.
    pub quota: u64,
    /// A fixed window aligned to the Unix epoch: a whole number and `s`, `m`, `h` or `d`, from
    /// `1s` to `30d`.
    pub window: String,
}

/// What a limit counts by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LimitKey {
    /// The client's IP address (`defaults.client_ip`).
    Ip,
    /// The caller the identify hook verified, or the IP address without one.
    Caller,
    /// One counter for everyone.
    Global,
    /// The verified agent: its Web Bot Auth signature agent origin, else its Cloudflare
    /// category, else the IP address. Gives each operator's agents (OpenAI's, Google's) one
    /// allowance of their own instead of sharing their egress IPs' counters. Compiles to
    /// `radius.policy/0.2`.
    Agent,
}

/// What a rule does, tagged by `type`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    /// Let the request through.
    Allow {},
    /// Refuse it with a 4xx `status` and a slug `code`.
    Deny { status: u16, code: String },
    /// Require a payment (`charge`; `x402`, its former name, is still accepted on input).
    #[serde(alias = "x402")]
    Charge(Charge),
}

/// A payment requirement. It inherits `defaults.payment` and may override `accepts` and
/// `pay_to`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Charge {
    /// USD, as a decimal string with up to 6 places, above 0.
    pub price: String,
    /// Shown to the payer.
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepts: Option<Vec<Accept>>,
    /// A registered wallet's address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pay_to: Option<String>,
}

impl Spec {
    /// An empty policy: allow everything.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every rule: the top-level rules, then each endpoint's, by slug. A request tries the
    /// top-level rules, then only the rules of the most specific endpoint it matches, so the order
    /// between endpoints doesn't matter here; the compiled form orders them by how specific their
    /// route is (see [`crate::compile::by_specificity`]).
    pub fn all_rules(&self) -> impl Iterator<Item = Located<'_>> {
        let top = self.rules.iter().enumerate().map(|(index, rule)| Located {
            endpoint: None,
            index,
            rule,
        });
        let endpoints = self.endpoints.iter().flat_map(|(slug, endpoint)| {
            endpoint
                .rules
                .iter()
                .enumerate()
                .map(move |(index, rule)| Located {
                    endpoint: Some(slug.as_str()),
                    index,
                    rule,
                })
        });
        top.chain(endpoints)
    }

    /// How many rules the policy has, top-level and endpoints' together.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
            + self
                .endpoints
                .values()
                .map(|endpoint| endpoint.rules.len())
                .sum::<usize>()
    }

    pub fn from_json(text: &str) -> Result<Self, String> {
        serde_json::from_str(text).map_err(|error| error.to_string())
    }

    pub fn from_yaml(text: &str) -> Result<Self, String> {
        serde_yaml_ng::from_str(text).map_err(|error| error.to_string())
    }

    pub fn to_yaml(&self) -> String {
        serde_yaml_ng::to_string(self).expect("policies serialize to YAML")
    }
}

/// A rule and where it sits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Located<'a> {
    /// The endpoint's slug, or `None` for a top-level rule.
    pub endpoint: Option<&'a str>,
    /// Its index in that list.
    pub index: usize,
    pub rule: &'a Rule,
}

impl Located<'_> {
    /// Where the rule is, for error keys: `rules[0]` or `endpoints.tx-lookup.rules[0]`.
    pub fn field(&self) -> String {
        rule_field(self.endpoint, self.index)
    }

    /// The rule's name in the policy and the compiled form: its id, after its endpoint's slug and
    /// a `/` for an endpoint's rule (`tx-lookup/freemium`).
    pub fn key(&self) -> String {
        rule_key(self.endpoint, &self.rule.id)
    }
}

/// `rules[<index>]`, or `endpoints.<slug>.rules[<index>]`.
pub fn rule_field(endpoint: Option<&str>, index: usize) -> String {
    match endpoint {
        Some(slug) => format!("endpoints.{slug}.rules[{index}]"),
        None => format!("rules[{index}]"),
    }
}

/// `<id>`, or `<slug>/<id>` for an endpoint's rule.
pub fn rule_key(endpoint: Option<&str>, id: &str) -> String {
    match endpoint {
        Some(slug) => format!("{slug}/{id}"),
        None => id.to_owned(),
    }
}

/// The JSON Schema of the authored form.
pub fn json_schema() -> serde_json::Value {
    serde_json::to_value(schemars::schema_for!(Spec)).expect("schemas serialize")
}
