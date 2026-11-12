//! What each endpoint of a project costs, read from the compiled policy the gateway enforces, so
//! pricing.md can't disagree with what agents are charged.
//!
//! For each endpoint, [`offers`] walks the compiled rules in order, as [`crate::eval::select`]
//! does for a request to it, and takes the first rule that applies to every such request. A more
//! specific endpoint's rules are skipped: they only match requests that endpoint governs (`GET
//! /files/:id`'s charge matches `/files/x`, the sample for `/files/*`, but never `/files/a/b`).
//! A less specific endpoint's rules are walked like any other, as the gate walks them: a document
//! compiled since endpoints were ordered by specificity ends an endpoint's rules with
//! `<slug>/_unmatched` before them, and an older one still lets them decide, so pricing.md agrees
//! with what agents are charged either way. What decides:
//!
//! - an x402 rule lists the endpoint with its price, free quota and rate limit;
//! - an allow or deny rule leaves it out, as do the defaults when no rule applies
//!   (`defaults.unmatched` never charges);
//! - rules limited to some IP addresses (`ip_in`) are skipped: they decide only for those
//!   addresses. An endpoint that only charges some addresses is left out as
//!   [`LeftOutReason::OnlySomeIps`];
//! - rules for some verified agents (`agent`) are skipped while looking for what every caller
//!   pays. An endpoint that otherwise charges no one but charges some verified agents is listed
//!   with that charge and who pays it (`Listing::agents`), so a catalog that only charges agents
//!   still publishes.
//!
//! Nothing about the policy itself (versions, rule IDs, wallets) reaches the listings.

use domain::matching::{MethodMatch, PathPattern, Segment, cmp_specificity};
use domain::pricing::catalog;
use domain::pricing_md::{Limit, Listing, PaymentOption, QuotaKey};
use serde::Serialize;

use crate::compiled::{Compiled, CompiledAction, CompiledLimit, CompiledRule, PaymentRequirement};
use crate::eval::{self, Request};
use crate::spec::AgentMatch;
use crate::spec::{LimitKey, Verdict};

/// One of a project's endpoints, as the API stores it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointRoute {
    pub slug: String,
    pub name: String,
    pub methods: MethodMatch,
    pub path: PathPattern,
    /// Every endpoint is enabled today. A paused endpoint (a later feature) is left out as
    /// [`LeftOutReason::Paused`] whatever its rules say.
    pub enabled: bool,
}

/// What pricing.md does with one endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(
    clippy::large_enum_variant,
    reason = "a project's offers are a few dozen, built once per render; boxing buys nothing"
)]
pub enum Offer {
    Listed(Listing),
    LeftOut {
        slug: String,
        name: String,
        reason: LeftOutReason,
    },
}

/// Why an endpoint isn't in pricing.md.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeftOutReason {
    /// Requests to it are free.
    NoCharge,
    /// Requests to it are refused.
    Denied,
    /// Only requests from some IP addresses pay.
    OnlySomeIps,
    /// It's turned off.
    Paused,
}

/// What each of `endpoints` costs under `compiled`, in the order given.
pub fn offers(compiled: &Compiled, endpoints: &[EndpointRoute]) -> Vec<Offer> {
    endpoints
        .iter()
        .map(|endpoint| offer(compiled, endpoint))
        .collect()
}

fn offer(compiled: &Compiled, endpoint: &EndpointRoute) -> Offer {
    let left_out = |reason| Offer::LeftOut {
        slug: endpoint.slug.clone(),
        name: endpoint.name.clone(),
        reason,
    };
    if !endpoint.enabled {
        return left_out(LeftOutReason::Paused);
    }
    let request = sample_request(endpoint);
    let mut charges_some_ips = false;
    // The first charge for some verified agents, listed when no charge applies to everyone.
    let mut agent_charge: Option<&CompiledRule> = None;
    for rule in &compiled.rules {
        // A more specific endpoint governs the requests its rules match, not this one.
        if rule.matcher.endpoint.as_ref().is_some_and(|matcher| {
            matcher.slug != endpoint.slug
                && cmp_specificity(
                    (&matcher.methods, &matcher.path),
                    (&endpoint.methods, &endpoint.path),
                )
                .is_lt()
        }) {
            continue;
        }
        let for_endpoint = rule
            .matcher
            .endpoint
            .as_ref()
            .is_none_or(|matcher| eval::endpoint_matches(matcher, &request));
        let charges = for_endpoint && matches!(rule.action, CompiledAction::Charge { .. });
        if !rule.matcher.ip_in.is_empty() {
            charges_some_ips |= charges;
            continue;
        }
        if rule.matcher.agent.is_some() {
            if charges && agent_charge.is_none() {
                agent_charge = Some(rule);
            }
            continue;
        }
        if !eval::matches(&rule.matcher, &request) {
            continue;
        }
        return match &rule.action {
            CompiledAction::Charge { .. } => {
                listed(endpoint, rule).unwrap_or_else(|| left_out(LeftOutReason::NoCharge))
            }
            CompiledAction::Deny { .. } => left_out(LeftOutReason::Denied),
            CompiledAction::Allow {} => not_charged(endpoint, agent_charge, charges_some_ips),
        };
    }
    match compiled.defaults.unmatched {
        Verdict::Deny => left_out(LeftOutReason::Denied),
        Verdict::Allow => not_charged(endpoint, agent_charge, charges_some_ips),
    }
}

/// An endpoint no charge applies to everyone of: listed with what some verified agents pay, if
/// any do, else left out.
fn not_charged(
    endpoint: &EndpointRoute,
    agent_charge: Option<&CompiledRule>,
    charges_some_ips: bool,
) -> Offer {
    if let Some(offer) = agent_charge.and_then(|rule| listed(endpoint, rule)) {
        return offer;
    }
    Offer::LeftOut {
        slug: endpoint.slug.clone(),
        name: endpoint.name.clone(),
        reason: if charges_some_ips {
            LeftOutReason::OnlySomeIps
        } else {
            LeftOutReason::NoCharge
        },
    }
}

/// `endpoint` listed with `rule`'s charge, and who pays it when the rule is for some agents.
fn listed(endpoint: &EndpointRoute, rule: &CompiledRule) -> Option<Offer> {
    let CompiledAction::Charge { price, accepts, .. } = &rule.action else {
        return None;
    };
    Some(Offer::Listed(Listing {
        slug: endpoint.slug.clone(),
        name: endpoint.name.clone(),
        methods: endpoint.methods.clone(),
        path: endpoint.path.clone(),
        price: *price,
        free_quota: rule.free_quota.map(limit),
        rate_limit: rule.rate_limit.map(limit),
        // The gateway counts a rule's limits per rule, so endpoints charged by the same rule
        // share them.
        limits_rule: (rule.free_quota.is_some() || rule.rate_limit.is_some())
            .then(|| rule.uid.to_string()),
        shared_with: Vec::new(),
        payment: payment(accepts),
        agents: rule.matcher.agent.as_ref().map(who_pays),
    }))
}

/// Which verified agents a charge is for, in words: `Agents signed by chatgpt.com`,
/// `Verified agents in ai_assistant or ai_search`, or both.
fn who_pays(agent: &AgentMatch) -> String {
    let hosts: Vec<&str> = agent
        .signature_agent
        .iter()
        .map(|origin| origin.trim_start_matches("https://"))
        .collect();
    let categories: Vec<String> = agent
        .category
        .iter()
        .filter_map(|category| serde_json::to_value(category).ok())
        .filter_map(|value| value.as_str().map(str::to_owned))
        .collect();
    match (hosts.is_empty(), categories.is_empty()) {
        (false, true) => format!("Agents signed by {}", hosts.join(" or ")),
        (true, false) => format!("Verified agents in {}", categories.join(" or ")),
        _ => format!(
            "Agents signed by {}, in {}",
            hosts.join(" or "),
            categories.join(" or ")
        ),
    }
}

/// A request the endpoint answers: its first method (`GET` for any), and its path with `x` for
/// each parameter and for a wildcard, so `/files/*` samples `/files/x`: a request below the
/// pattern's literal part, which a rule for `/files` alone wouldn't match.
pub fn sample_request(endpoint: &EndpointRoute) -> Request {
    let method = match &endpoint.methods {
        MethodMatch::Any => "GET".to_owned(),
        MethodMatch::Only(methods) => methods
            .first()
            .map_or("GET", |method| method.as_str())
            .to_owned(),
    };
    let mut path = String::new();
    for segment in endpoint.path.segments() {
        match segment {
            Segment::Literal(text) => {
                path.push('/');
                path.push_str(text);
            }
            Segment::Param(_) | Segment::Wildcard => path.push_str("/x"),
        }
    }
    if path.is_empty() {
        path.push('/');
    }
    Request {
        method,
        path,
        client_ip: None,
        caller: None,
        agent: None,
        now: 0,
    }
}

fn limit(limit: CompiledLimit) -> Limit {
    Limit {
        quota: limit.quota,
        window_s: limit.window_s,
        per: match limit.key {
            LimitKey::Ip => QuotaKey::Ip,
            LimitKey::Caller => QuotaKey::Caller,
            LimitKey::Global => QuotaKey::Global,
            LimitKey::Agent => QuotaKey::Agent,
        },
    }
}

/// The tokens and networks an action accepts, by their catalog names, without repeats.
fn payment(accepts: &[PaymentRequirement]) -> Vec<PaymentOption> {
    let mut options: Vec<PaymentOption> = Vec::new();
    for requirement in accepts {
        let network = catalog::network(&requirement.network);
        let option = PaymentOption {
            token: network
                .and_then(|network| catalog::asset(network, requirement.asset))
                .map_or_else(
                    || requirement.asset.to_string(),
                    |asset| asset.symbol.to_owned(),
                ),
            network: network.map_or_else(
                || requirement.network.clone(),
                |network| network.label.to_owned(),
            ),
        };
        if !options.contains(&option) {
            options.push(option);
        }
    }
    options
}
