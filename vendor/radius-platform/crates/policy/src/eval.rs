//! The reference evaluator of the compiled form, in two steps so it stays pure:
//!
//! 1. [`select`] finds the first rule whose match holds. A rule without a rate limit or a free
//!    quota decides at once ([`Step::Done`]); a rule with either asks the caller to count the
//!    request ([`Step::Count`]), on one counter per limit: the rate limit's, then the free
//!    quota's.
//! 2. The caller adds one to each counter named in [`Count::counters`] (expiring after its
//!    `reset_s`) and passes the new values, or the store's failure, to [`decide`].
//!
//! Past the rate limit a request is denied with `429 rate_limited`; otherwise, within the free
//! quota it's allowed, and beyond it the rule's action applies.
//!
//! Counters use fixed windows aligned to the Unix epoch. The key holds the rule's stable `uid`,
//! which limit it is (`rate` or `free`), the window's index and the resolved key value, so a store
//! only needs an atomic increment with an expiry. Every request that reaches a rule counts against
//! each of its limits, paid, free or denied.
//!
//! Every [`Decision`] names the rule that made it (none for unmatched requests), for telemetry.
//! The conformance vectors in `tests/vectors` pin this behavior for every implementation.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use domain::matching::{HttpMethod, MethodMatch};
use domain::pricing::micros::Micros;
use ipnet::Ipv6Net;
use serde::{Deserialize, Serialize};

use crate::compile::canonical_net;
use crate::compiled::{
    Compiled, CompiledAction, CompiledEndpoint, CompiledLimit, CompiledMatch, CompiledRule,
    PaymentRequirement,
};
use crate::spec::{AgentCategory, ClientIp, CounterError, LimitKey, Verdict};

/// What the evaluator knows about a request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Upper case, e.g. `GET`.
    pub method: String,
    /// The request path, e.g. `/tx/0xabc`. A query string is ignored.
    pub path: String,
    /// Resolved per `defaults.client_ip` (see [`client_ip`]).
    #[serde(default)]
    pub client_ip: Option<IpAddr>,
    /// Who the seller's identify hook verified the caller as, if anyone.
    #[serde(default)]
    pub caller: Option<Caller>,
    /// The agent as the gate verified it; none for browsers and unverified agents.
    #[serde(default)]
    pub agent: Option<Agent>,
    /// Unix time in seconds.
    pub now: u64,
}

/// A caller the seller's own authentication verified.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Caller {
    pub id: String,
}

/// What the gate verified about the request's agent. Absent fields weren't verified.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Agent {
    /// Its category, as Cloudflare verified it.
    #[serde(default)]
    pub category: Option<AgentCategory>,
    /// The origin of the key directory its Web Bot Auth signature verified against, as the
    /// compiler writes origins (`https://radiustech.xyz`).
    #[serde(default)]
    pub signature_agent: Option<String>,
}

/// The first step's result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step<'p> {
    Done(Decision),
    Count(Count<'p>),
}

/// A request to count before deciding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Count<'p> {
    pub rule: &'p CompiledRule,
    /// The rate limit's counter, then the free quota's, for the limits the rule has.
    pub counters: Vec<Counter>,
}

/// Which of a rule's limits a counter is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitKind {
    RateLimit,
    FreeQuota,
}

impl LimitKind {
    fn tag(self) -> &'static str {
        match self {
            Self::RateLimit => "rate",
            Self::FreeQuota => "free",
        }
    }
}

/// One counter to add the request to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Counter {
    pub limit: LimitKind,
    /// `<uid>:<rate|free>:<window index>:ip:<address or IPv6 /64>`, `…:caller:<id>` or `…:global`.
    pub key: String,
    /// Seconds until the window ends: the counter's expiry and `Retry-After`.
    pub reset_s: u64,
}

/// The counter store couldn't be reached or failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CounterUnavailable;

/// What to do with a request.
// No `deny_unknown_fields`: serde doesn't support it with a flattened enum, and every
// `Decision` would fail to deserialize.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    /// The deciding rule's `id`; none when no rule matched or there's no policy.
    pub rule: Option<String>,
    #[serde(flatten)]
    pub outcome: Outcome,
    /// Response headers to add, e.g. `RateLimit-Remaining` or `Retry-After`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Outcome {
    Allow,
    Deny {
        status: u16,
        code: String,
    },
    /// Answer with a 402 offering every entry of `accepts`.
    PaymentRequired {
        price: Micros,
        description: String,
        accepts: Vec<PaymentRequirement>,
    },
}

/// The denial for unmatched requests under `defaults.unmatched: deny`.
pub const UNMATCHED: (u16, &str) = (403, "no_matching_rule");
/// The denial when no policy was ever fetched and `failure.no_policy` is `deny`.
pub const NO_POLICY: (u16, &str) = (503, "policy_unavailable");
/// The denial past a rule's rate limit.
pub const RATE_LIMITED: (u16, &str) = (429, "rate_limited");

impl Decision {
    fn allow(rule: Option<&str>) -> Self {
        Self {
            rule: rule.map(str::to_owned),
            outcome: Outcome::Allow,
            headers: BTreeMap::new(),
        }
    }

    fn deny(rule: Option<&str>, (status, code): (u16, &str)) -> Self {
        Self {
            rule: rule.map(str::to_owned),
            outcome: Outcome::Deny {
                status,
                code: code.to_owned(),
            },
            headers: BTreeMap::new(),
        }
    }
}

/// The decision when no policy has ever been fetched (`failure.no_policy`, which enforcement
/// points take from their configuration).
pub fn no_policy(no_policy: Verdict) -> Decision {
    match no_policy {
        Verdict::Allow => Decision::allow(None),
        Verdict::Deny => Decision::deny(None, NO_POLICY),
    }
}

/// The client's address per `defaults.client_ip`: the connection's, or the first address in the
/// named header (see [`parse_ip`]). `header` looks a request header up by its lower-case name.
pub fn client_ip<'h>(
    policy: &Compiled,
    header: impl Fn(&str) -> Option<&'h str>,
    remote_addr: Option<IpAddr>,
) -> Option<IpAddr> {
    match &policy.defaults.client_ip {
        ClientIp::RemoteAddr(_) => remote_addr,
        ClientIp::Header(source) => header(&source.header.to_ascii_lowercase())
            .and_then(|value| value.split(',').next())
            .and_then(parse_ip),
    }
}

/// An address as proxies write it in a header: `203.0.113.5`, `203.0.113.5:4711`,
/// `2001:db8::1`, `[2001:db8::1]` or `[2001:db8::1]:443`, ignoring surrounding whitespace.
pub fn parse_ip(text: &str) -> Option<IpAddr> {
    let text = text.trim();
    text.parse::<IpAddr>()
        .ok()
        .or_else(|| text.parse::<SocketAddr>().ok().map(|addr| addr.ip()))
        .or_else(|| {
            text.strip_prefix('[')
                .and_then(|rest| rest.strip_suffix(']'))
                .and_then(|inner| inner.parse::<Ipv6Addr>().ok())
                .map(IpAddr::V6)
        })
}

/// IPv4-mapped IPv6 addresses (`::ffff:203.0.113.5`) as IPv4.
fn canonical(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

pub(crate) fn endpoint_matches(endpoint: &CompiledEndpoint, request: &Request) -> bool {
    let method = match &endpoint.methods {
        MethodMatch::Any => true,
        MethodMatch::Only(methods) => {
            HttpMethod::parse(&request.method).is_some_and(|method| methods.contains(&method))
        }
    };
    method && endpoint.path.matches(&request.path)
}

pub(crate) fn matches(matcher: &CompiledMatch, request: &Request) -> bool {
    let endpoint = matcher
        .endpoint
        .as_ref()
        .is_none_or(|endpoint| endpoint_matches(endpoint, request));
    let ip = matcher.ip_in.is_empty()
        || request.client_ip.map(canonical).is_some_and(|ip| {
            matcher
                .ip_in
                .iter()
                .any(|net| canonical_net(*net).contains(&ip))
        });
    let agent = matcher.agent.as_ref().is_none_or(|wanted| {
        let agent = request.agent.clone().unwrap_or_default();
        let category = wanted.category.is_empty()
            || agent.category.is_some_and(|c| wanted.category.contains(&c));
        let signed = wanted.signature_agent.is_empty()
            || agent
                .signature_agent
                .is_some_and(|origin| wanted.signature_agent.contains(&origin));
        category && signed
    });
    endpoint && ip && agent
}

/// IPv4 clients count per address, IPv6 clients per /64: hosts usually get a whole /64, so
/// per-address counters would let one client spread its requests over 2^64 of them.
fn ip_part(request: &Request) -> String {
    match request.client_ip.map(canonical) {
        Some(IpAddr::V4(ip)) => format!("ip:{ip}"),
        Some(IpAddr::V6(ip)) => format!("ip:{}", Ipv6Net::new_assert(ip, 64).trunc()),
        None => "ip:unknown".to_owned(),
    }
}

/// The verified agent a request counts as: its signature agent origin, else its category, else
/// its IP address.
fn agent_part(request: &Request) -> String {
    let agent = request.agent.as_ref();
    if let Some(origin) = agent.and_then(|agent| agent.signature_agent.as_ref()) {
        return format!("agent:sig:{origin}");
    }
    if let Some(category) = agent.and_then(|agent| agent.category) {
        let name = serde_json::to_value(category)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_default();
        return format!("agent:cat:{name}");
    }
    ip_part(request)
}

/// Finds the rule that applies: the first whose match holds. The compiler orders endpoints' rules
/// most specific route first and ends an endpoint's rules with `<slug>/_unmatched` where needed
/// ([`crate::compile::UNMATCHED_RULE`]), so first-match already gives a request only its most
/// specific endpoint's rules.
pub fn select<'p>(policy: &'p Compiled, request: &Request) -> Step<'p> {
    let Some(rule) = policy.rules.iter().find(|r| matches(&r.matcher, request)) else {
        return Step::Done(match policy.defaults.unmatched {
            Verdict::Allow => Decision::allow(None),
            Verdict::Deny => Decision::deny(None, UNMATCHED),
        });
    };
    let counters: Vec<Counter> = limits(rule)
        .map(|(kind, limit)| {
            let part = match limit.key {
                LimitKey::Ip => ip_part(request),
                LimitKey::Caller => match &request.caller {
                    Some(caller) => format!("caller:{}", caller.id),
                    None => ip_part(request),
                },
                LimitKey::Global => "global".to_owned(),
                LimitKey::Agent => agent_part(request),
            };
            // Compiled policies never have an empty window; a hand-written one counts per second.
            let window_s = limit.window_s.max(1);
            let window = request.now / window_s;
            Counter {
                limit: kind,
                key: format!("{}:{}:{window}:{part}", rule.uid, kind.tag()),
                reset_s: window_s - request.now % window_s,
            }
        })
        .collect();
    if counters.is_empty() {
        return Step::Done(apply(rule, &rule.action));
    }
    Step::Count(Count { rule, counters })
}

/// The rule's limits in the order they're checked: the rate limit, then the free quota.
fn limits(rule: &CompiledRule) -> impl Iterator<Item = (LimitKind, CompiledLimit)> {
    [
        (LimitKind::RateLimit, rule.rate_limit),
        (LimitKind::FreeQuota, rule.free_quota),
    ]
    .into_iter()
    .filter_map(|(kind, limit)| limit.map(|limit| (kind, limit)))
}

/// The rule's action as a decision.
fn apply(rule: &CompiledRule, action: &CompiledAction) -> Decision {
    let outcome = match action {
        CompiledAction::Allow {} => Outcome::Allow,
        CompiledAction::Deny { status, code } => Outcome::Deny {
            status: *status,
            code: code.clone(),
        },
        CompiledAction::Charge {
            price,
            description,
            accepts,
        } => Outcome::PaymentRequired {
            price: *price,
            description: description.clone(),
            accepts: accepts.clone(),
        },
    };
    Decision {
        rule: Some(rule.id.clone()),
        outcome,
        headers: BTreeMap::new(),
    }
}

/// Decides a counted request. `counts` holds each counter's value after adding this request, in
/// the order of [`Count::counters`], or the store's failure. Past the rate limit the request is
/// denied with `429 rate_limited`; otherwise within the free quota it's allowed, and beyond it the
/// rule's action applies. A failed counter reads per `failure.counter_error`: `within` as within
/// its limit, `over` as beyond it.
pub fn decide(
    policy: &Compiled,
    counted: &Count<'_>,
    counts: &[Result<u64, CounterUnavailable>],
) -> Decision {
    let rule = counted.rule;
    let over_on_error = policy.defaults.failure.counter_error == CounterError::Over;
    // Each limit with its counter and whether this request is beyond it.
    let checked: Vec<(LimitKind, CompiledLimit, &Counter, Option<u64>, bool)> = limits(rule)
        .zip(&counted.counters)
        .enumerate()
        .map(|(index, ((kind, limit), counter))| {
            let count = counts
                .get(index)
                .copied()
                .unwrap_or(Err(CounterUnavailable))
                .ok();
            let over = count.map_or(over_on_error, |count| count > limit.quota);
            (kind, limit, counter, count, over)
        })
        .collect();
    let rate = checked.iter().find(|c| c.0 == LimitKind::RateLimit);
    let free = checked.iter().find(|c| c.0 == LimitKind::FreeQuota);
    let (mut decision, deciding) = match (rate, free) {
        (Some(rate), _) if rate.4 => (Decision::deny(Some(&rule.id), RATE_LIMITED), Some(rate)),
        (_, Some(free)) if !free.4 => (Decision::allow(Some(&rule.id)), Some(free)),
        (_, free) => (apply(rule, &rule.action), free),
    };
    let headers = &policy.defaults.headers;
    // The rate limit's headers when the rule has one, else the free quota's; none from a failed
    // counter.
    if headers.ratelimit
        && let Some((_, limit, counter, Some(count), _)) = rate.or(free)
    {
        decision
            .headers
            .insert("RateLimit-Limit".to_owned(), limit.quota.to_string());
        decision.headers.insert(
            "RateLimit-Remaining".to_owned(),
            limit.quota.saturating_sub(*count).to_string(),
        );
        decision
            .headers
            .insert("RateLimit-Reset".to_owned(), counter.reset_s.to_string());
    }
    if headers.retry_after
        && matches!(decision.outcome, Outcome::Deny { .. })
        && let Some((_, _, counter, Some(_), _)) = deciding
    {
        decision
            .headers
            .insert("Retry-After".to_owned(), counter.reset_s.to_string());
    }
    decision
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_addresses_parse_with_ports_and_brackets() {
        for (text, ip) in [
            ("203.0.113.5", "203.0.113.5"),
            (" 203.0.113.5:4711 ", "203.0.113.5"),
            ("2001:db8::1", "2001:db8::1"),
            ("[2001:db8::1]", "2001:db8::1"),
            ("[2001:db8::1]:443", "2001:db8::1"),
        ] {
            assert_eq!(parse_ip(text), Some(ip.parse().unwrap()), "{text}");
        }
        for text in [
            "",
            "unknown",
            "[203.0.113.5]",
            "2001:db8::1]",
            "203.0.113.5:port",
        ] {
            assert_eq!(parse_ip(text), None, "{text}");
        }
    }
}
