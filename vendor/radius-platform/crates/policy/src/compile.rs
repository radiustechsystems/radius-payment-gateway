//! Compiles an authored [`Spec`] into the self-contained [`Compiled`] form, checking everything
//! a decision will rely on. The caller loads the [`Context`] (the project's endpoints and the
//! organization's wallets) from its own storage; compiling does no IO.
//!
//! Errors are keyed by field, like `rules[3].rate_limit.window` or
//! `endpoints.tx-lookup.rules[0].free_quota.window`, with messages the UI shows as written. IP
//! ranges, windows, prices and addresses are trimmed before they're parsed, here and in
//! [`warnings`].
//! [`warnings`] reports rules that can never apply; they don't stop a policy from compiling.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::str::FromStr;

use alloy_primitives::Address;
use domain::matching::{
    MethodMatch, PathPattern, cmp_specificity, paths_intersect, route_label, routes_intersect,
};
use domain::payment::{PaymentOption, PaymentOptionDraft, validate_accepts};
use domain::pricing::catalog::{AddressFamily, Mode};
use domain::pricing::micros::{Micros, micros_to_atomic};
use domain::validation::FieldErrors;
use domain::wallet::parse_evm_address;
use ipnet::{IpNet, Ipv4Net};
use serde::Serialize;
use uuid::Uuid;

use crate::compiled::{
    Compiled, CompiledAction, CompiledDefaults, CompiledEndpoint, CompiledLimit, CompiledMatch,
    CompiledRule, PaymentRequirement,
};
use crate::eval::UNMATCHED;
use crate::spec::{
    Accept, Action, ClientIp, Limit, LimitKey, Located, Match, Rule, SchemaId, Spec, Verdict,
    rule_key,
};
use crate::window;

/// The most rules a policy may have.
pub const MAX_RULES: usize = 200;
/// The longest slug: rule IDs and deny codes.
pub const MAX_SLUG_CHARS: usize = 64;
pub const MAX_DESCRIPTION_CHARS: usize = 200;

/// An endpoint of the project, as rules match it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextEndpoint {
    pub slug: String,
    pub methods: MethodMatch,
    pub path: PathPattern,
}

/// A wallet registered in the organization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextWallet {
    pub name: String,
    pub address: Address,
    pub address_family: AddressFamily,
}

/// What compiling needs besides the policy, loaded by the caller. Payment options come from the
/// catalog in [`domain::pricing::catalog`].
pub struct Context<'a> {
    pub project_id: Uuid,
    /// The version this compilation becomes.
    pub version: u64,
    /// RFC 3339.
    pub generated_at: &'a str,
    /// The project's mode: every accepted network must be of it.
    pub mode: Mode,
    pub endpoints: &'a [ContextEndpoint],
    pub wallets: &'a [ContextWallet],
    /// Each existing rule's stable ID, by its key ([`crate::spec::rule_key`]: `freemium` for a
    /// top-level rule, `tx-lookup/freemium` for an endpoint's). Rules without one get an ID derived
    /// from the project and the key, so compiling is deterministic.
    pub uids: &'a BTreeMap<String, Uuid>,
}

/// A rule that can never apply. Warnings don't stop a policy from compiling.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Warning {
    /// E.g. `rules[3]` or `endpoints.tx-lookup.rules[0]`.
    pub field: String,
    /// The rule's key: its slug, after its endpoint's (`tx-lookup/freemium`).
    pub rule: String,
    pub message: String,
}

/// An endpoint whose route overlaps a less specific endpoint's that has rules: the requests both
/// match follow only the more specific endpoint's rules, so the other's don't apply to them. Like
/// warnings, overlaps don't stop a policy from compiling.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Overlap {
    /// The more specific endpoint's slug, whose rules decide the requests both match.
    pub endpoint: String,
    /// The less specific endpoint's slug, whose rules don't apply to them.
    pub less_specific: String,
    pub message: String,
}

/// Whether `text` is a slug: lowercase letters, digits, `-` and `_`, starting with a letter or
/// digit.
pub fn check_slug(text: &str) -> Result<(), String> {
    let mut chars = text.chars();
    let first = chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    let rest = chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_');
    if text.is_empty() {
        Err("Enter a slug, like tx-freemium".to_owned())
    } else if text.chars().count() > MAX_SLUG_CHARS {
        Err(format!("Use at most {MAX_SLUG_CHARS} characters"))
    } else if !(first && rest) {
        Err("Use lowercase letters, digits, - and _, starting with a letter or digit".to_owned())
    } else {
        Ok(())
    }
}

fn check_description(text: &str) -> Result<String, String> {
    let text = text.trim();
    if text.is_empty() {
        Err("Enter a description for payers".to_owned())
    } else if text.chars().count() > MAX_DESCRIPTION_CHARS {
        Err(format!("Use at most {MAX_DESCRIPTION_CHARS} characters"))
    } else {
        Ok(text.to_owned())
    }
}

/// Whether `name` is an HTTP header name (an RFC 9110 token).
fn check_header_name(name: &str) -> Result<(), String> {
    let token = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b));
    token
        .then_some(())
        .ok_or_else(|| format!("{name:?} isn't a header name, like cf-connecting-ip"))
}

/// A CIDR range, or a single address as its own range, ignoring surrounding whitespace.
/// Normalized to the network address, with IPv4-mapped ranges as IPv4 (see [`canonical_net`]).
pub fn parse_cidr(text: &str) -> Result<IpNet, String> {
    let text = text.trim();
    IpNet::from_str(text)
        .or_else(|_| IpAddr::from_str(text).map(IpNet::from))
        .map(|net| canonical_net(net).trunc())
        .map_err(|_| format!("{text:?} isn't a CIDR range, like 203.0.113.0/24 or 2001:db8::/32"))
}

/// An IPv4-mapped IPv6 range (`::ffff:203.0.113.0/120`) as the IPv4 range it maps
/// (`203.0.113.0/24`), since client addresses are compared in that form; any other range as is.
pub fn canonical_net(net: IpNet) -> IpNet {
    match net {
        IpNet::V6(v6) if v6.prefix_len() >= 96 => v6
            .trunc()
            .addr()
            .to_ipv4_mapped()
            .and_then(|v4| Ipv4Net::new(v4, v6.prefix_len() - 96).ok())
            .map_or(net, IpNet::V4),
        _ => net,
    }
}

fn drafts(accepts: &[Accept]) -> Vec<PaymentOptionDraft> {
    accepts
        .iter()
        .map(|accept| PaymentOptionDraft {
            network: accept.network.clone(),
            asset: accept.asset.clone(),
            scheme: accept.scheme.clone(),
        })
        .collect()
}

struct Compiler<'a> {
    ctx: &'a Context<'a>,
    errors: FieldErrors,
}

impl Compiler<'_> {
    /// The registered wallet at `text`, if it can be paid on every one of `options`.
    fn wallet(&mut self, text: &str, field: &str, options: &[PaymentOption]) -> Option<Address> {
        let address = self.errors.check(field, parse_evm_address(text.trim()))?;
        let Some(wallet) = self.ctx.wallets.iter().find(|w| w.address == address) else {
            self.errors.add(
                field,
                "No wallet with this address is registered in the organization. Register it first",
            );
            return None;
        };
        if let Some(option) = options.iter().find(|o| !o.pays_to(wallet.address_family)) {
            self.errors.add(
                field,
                format!(
                    "{} can't receive payments on {}",
                    wallet.name, option.network.label
                ),
            );
            return None;
        }
        Some(address)
    }

    /// The payment options `accepts` names. Each must have a facilitator to verify and settle
    /// its payments: a network without one (Base, until one is chosen) is refused.
    fn accepts(&mut self, accepts: &[Accept], field: &str) -> Option<Vec<PaymentOption>> {
        match validate_accepts(self.ctx.mode, &drafts(accepts), field) {
            Ok(options) => {
                let mut settled = true;
                for (index, option) in options.iter().enumerate() {
                    if option.network.facilitator.is_none() {
                        self.errors.add(
                            format!("{field}[{index}].network"),
                            format!(
                                "Payments on {} can't be settled yet. Choose another network",
                                option.network.label
                            ),
                        );
                        settled = false;
                    }
                }
                settled.then_some(options)
            }
            Err(errors) => {
                for (key, message) in errors.iter() {
                    self.errors.add(key, message);
                }
                None
            }
        }
    }

    /// A rate limit or free quota, checked; errors on `<field>.quota` and `<field>.window`.
    fn limit(&mut self, limit: Option<&Limit>, field: &str) -> Option<CompiledLimit> {
        let limit = limit?;
        if limit.quota == 0 {
            self.errors
                .add(format!("{field}.quota"), "Use a quota of at least 1");
        }
        let window_s = self
            .errors
            .check(&format!("{field}.window"), window::parse(&limit.window))?;
        Some(CompiledLimit {
            key: limit.key,
            quota: limit.quota,
            window_s,
        })
    }

    /// The project's endpoint `slug`, resolved; an error on `field` if there's none.
    fn endpoint(&mut self, slug: &str, field: &str) -> Option<CompiledEndpoint> {
        let found = self.ctx.endpoints.iter().find(|e| e.slug == slug);
        if found.is_none() {
            self.errors.add(
                field,
                format!("There's no endpoint {slug:?} in this project"),
            );
        }
        found.map(|e| CompiledEndpoint {
            slug: e.slug.clone(),
            methods: e.methods.clone(),
            path: e.path.clone(),
        })
    }

    fn matcher(
        &mut self,
        matcher: &Match,
        endpoint: Option<CompiledEndpoint>,
        prefix: &str,
    ) -> CompiledMatch {
        let mut ip_in = Vec::new();
        for (index, text) in matcher.ip_in.iter().enumerate() {
            if let Some(net) = self
                .errors
                .check(&format!("{prefix}.ip_in[{index}]"), parse_cidr(text))
            {
                ip_in.push(net);
            }
        }
        let agent = matcher.agent.clone().map(|mut agent| {
            if agent.category.is_empty() && agent.signature_agent.is_empty() {
                self.errors.add(
                    format!("{prefix}.agent"),
                    "Name at least one category or signature agent".to_owned(),
                );
            }
            agent.category.sort();
            agent.category.dedup();
            let mut origins = Vec::new();
            for (index, text) in agent.signature_agent.iter().enumerate() {
                if let Some(origin) = self.errors.check(
                    &format!("{prefix}.agent.signature_agent[{index}]"),
                    parse_origin(text),
                ) {
                    origins.push(origin);
                }
            }
            origins.sort();
            origins.dedup();
            agent.signature_agent = origins;
            agent
        });
        CompiledMatch {
            endpoint,
            ip_in,
            agent,
        }
    }

    fn rule(
        &mut self,
        located: Located<'_>,
        endpoint: Option<CompiledEndpoint>,
        defaults: &(Option<Vec<PaymentOption>>, Option<Address>),
    ) -> Option<CompiledRule> {
        let rule = located.rule;
        let prefix = located.field();
        let matcher = self.matcher(&rule.matcher, endpoint, &format!("{prefix}.match"));
        let rate_limit = self.limit(rule.rate_limit.as_ref(), &format!("{prefix}.rate_limit"));
        let free_quota = self.limit(rule.free_quota.as_ref(), &format!("{prefix}.free_quota"));
        let action = match &rule.action {
            Action::Allow {} => Some(CompiledAction::Allow {}),
            Action::Deny { status, code } => {
                if !(400..=499).contains(status) {
                    self.errors.add(
                        format!("{prefix}.action.status"),
                        "Use a 4xx status, like 403 or 429",
                    );
                } else if *status == 402 {
                    self.errors.add(
                        format!("{prefix}.action.status"),
                        "402 is for payments. Use a charge action, or another 4xx status",
                    );
                }
                self.errors
                    .check(&format!("{prefix}.action.code"), check_slug(code));
                Some(CompiledAction::Deny {
                    status: *status,
                    code: code.clone(),
                })
            }
            Action::Charge(charge) => {
                let price = self.errors.check(
                    &format!("{prefix}.action.price"),
                    Micros::parse(charge.price.trim()).map_err(|error| error.to_string()),
                );
                let description = self.errors.check(
                    &format!("{prefix}.action.description"),
                    check_description(&charge.description),
                );
                let options = match &charge.accepts {
                    Some(accepts) => self.accepts(accepts, &format!("{prefix}.action.accepts")),
                    None => defaults.0.clone(),
                };
                let pay_to_field = format!("{prefix}.action.pay_to");
                let pay_to = match (&charge.pay_to, &options) {
                    (Some(text), Some(options)) => self.wallet(text, &pay_to_field, options),
                    (Some(_), None) => None,
                    (None, _) if defaults.1.is_none() => {
                        self.errors.add(
                            pay_to_field,
                            "Choose a wallet to receive payments, here or in defaults.payment.pay_to",
                        );
                        None
                    }
                    (None, _) => defaults.1,
                };
                match (price, description, options, pay_to) {
                    (Some(price), Some(description), Some(options), Some(pay_to)) => {
                        Some(CompiledAction::Charge {
                            price,
                            description,
                            accepts: options
                                .iter()
                                .map(|option| PaymentRequirement {
                                    scheme: option.scheme,
                                    network: option.network.caip2(),
                                    asset: option.asset.address,
                                    decimals: option.asset.decimals,
                                    amount: micros_to_atomic(price, option.asset.decimals),
                                    pay_to,
                                    facilitator: option.network.facilitator.map(str::to_owned),
                                })
                                .collect(),
                        })
                    }
                    _ => None,
                }
            }
        }?;
        let key = located.key();
        let uid = self
            .ctx
            .uids
            .get(&key)
            .copied()
            .unwrap_or_else(|| Uuid::new_v5(&self.ctx.project_id, key.as_bytes()));
        Some(CompiledRule {
            uid,
            id: key,
            matcher,
            rate_limit,
            free_quota,
            action,
        })
    }
}

/// Compiles `spec` against `ctx`, or reports every problem keyed by field.
pub fn compile(spec: &Spec, ctx: &Context<'_>) -> Result<Compiled, FieldErrors> {
    let mut compiler = Compiler {
        ctx,
        errors: FieldErrors::new(),
    };

    if let ClientIp::Header(source) = &spec.defaults.client_ip {
        compiler.errors.check(
            "defaults.client_ip.header",
            check_header_name(&source.header),
        );
    }

    let payment = spec.defaults.payment.clone().unwrap_or_default();
    let default_options = if payment.accepts.is_empty() {
        Some(vec![PaymentOption::default_for(ctx.mode)])
    } else {
        compiler.accepts(&payment.accepts, "defaults.payment.accepts")
    };
    let default_pay_to = match (&payment.pay_to, &default_options) {
        (Some(text), Some(options)) => compiler.wallet(text, "defaults.payment.pay_to", options),
        _ => None,
    };
    let defaults = (default_options, default_pay_to);

    if spec.rule_count() > MAX_RULES {
        compiler
            .errors
            .add("rules", format!("Use at most {MAX_RULES} rules"));
    }
    let mut endpoints = BTreeMap::new();
    for slug in spec.endpoints.keys() {
        let resolved = compiler.endpoint(slug, &format!("endpoints.{slug}"));
        endpoints.insert(slug.as_str(), resolved);
    }
    let mut seen = BTreeSet::new();
    let mut rules = Vec::with_capacity(spec.rule_count());
    for entry in in_order(spec, ctx.endpoints) {
        let located = match entry {
            Entry::Rule(located) => located,
            Entry::Terminal(endpoint) => {
                rules.push(terminal(endpoint, spec, ctx));
                continue;
            }
        };
        let rule = located.rule;
        let field = format!("{}.id", located.field());
        if compiler
            .errors
            .check(&field, check_slug(&rule.id))
            .is_some()
            && !seen.insert((located.endpoint, rule.id.as_str()))
        {
            let message = match located.endpoint {
                Some(slug) => format!("Another rule of {slug:?} is already called {:?}", rule.id),
                None => format!("Another rule is already called {:?}", rule.id),
            };
            compiler.errors.add(field, message);
        }
        let endpoint = match located.endpoint {
            // An unknown endpoint was reported on `endpoints.<slug>`; its rules are still checked.
            Some(slug) => match endpoints.get(slug).cloned().flatten() {
                Some(endpoint) => Some(endpoint),
                None => {
                    compiler.rule(located, None, &defaults);
                    continue;
                }
            },
            None => None,
        };
        rules.extend(compiler.rule(located, endpoint, &defaults));
    }

    // Only a policy that matches on agents needs a gate that knows how: everyone else's stays 0.1.
    let uses_agents = |rule: &CompiledRule| {
        rule.matcher.agent.is_some()
            || [rule.rate_limit, rule.free_quota]
                .iter()
                .flatten()
                .any(|limit| limit.key == LimitKey::Agent)
    };
    let schema = if rules.iter().any(uses_agents) {
        SchemaId::V0_2
    } else {
        SchemaId::V0_1
    };
    let errors = compiler.errors;
    errors.into_result(|| Compiled {
        schema,
        version: ctx.version,
        project_id: ctx.project_id,
        generated_at: ctx.generated_at.to_owned(),
        mode: ctx.mode,
        defaults: CompiledDefaults {
            unmatched: spec.defaults.unmatched,
            failure: spec.defaults.failure,
            client_ip: spec.defaults.client_ip.clone(),
            headers: spec.defaults.headers,
        },
        rules,
    })
}

/// The `id` after an endpoint's slug of the rule the compiler adds to give an endpoint's
/// requests `defaults.unmatched` (`get-forecast-list/_unmatched`). Authored ids can't start
/// with `_`, so it never names a seller's rule.
pub const UNMATCHED_RULE: &str = "_unmatched";

/// The project's endpoints, most specific first ([`cmp_specificity`]), then by slug. A request
/// several endpoints match is governed by the first of them.
pub fn by_specificity(endpoints: &[ContextEndpoint]) -> Vec<&ContextEndpoint> {
    let mut sorted: Vec<&ContextEndpoint> = endpoints.iter().collect();
    sorted.sort_by(|a, b| {
        cmp_specificity((&a.methods, &a.path), (&b.methods, &b.path)).then(a.slug.cmp(&b.slug))
    });
    sorted
}

/// A step of the compiled rule list: an authored rule, or the rule that ends an endpoint's.
enum Entry<'s, 'c> {
    Rule(Located<'s>),
    Terminal(&'c ContextEndpoint),
}

/// The compiled rules' order: the top-level rules, then each endpoint's rules, most specific
/// endpoint first ([`by_specificity`]), each followed by its [`terminal`] where it needs one.
/// Rules of endpoints the project doesn't have come last; they don't compile, but are checked.
///
/// A request is governed by the most specific endpoint it matches: when none of that endpoint's
/// rules decides, it gets `defaults.unmatched`, and never a less specific endpoint's rules. The
/// first endpoint in this order that matches a request is the most specific, so its rules come
/// before every other matching endpoint's, and its terminal, which matches all its requests, stops
/// the rest. A terminal is left out where nothing could follow it: when the endpoint has a rule
/// for every request (no `ip_in`), or no later endpoint matching some of its requests has rules.
fn in_order<'s, 'c>(spec: &'s Spec, endpoints: &'c [ContextEndpoint]) -> Vec<Entry<'s, 'c>> {
    let order = by_specificity(endpoints);
    let rules_of = |slug: &str| spec.endpoints.get(slug).map_or(&[][..], |e| &e.rules[..]);
    let rules_in = |endpoint: Option<&str>| -> Vec<Entry<'s, 'c>> {
        spec.all_rules()
            .filter(|located| located.endpoint == endpoint)
            .map(Entry::Rule)
            .collect()
    };
    let mut entries = rules_in(None);
    for (position, endpoint) in order.iter().enumerate() {
        entries.extend(rules_in(Some(&endpoint.slug)));
        let catch_all = rules_of(&endpoint.slug)
            .iter()
            .any(|rule| rule.matcher.is_empty());
        let reached = order[position + 1..].iter().any(|later| {
            !rules_of(&later.slug).is_empty()
                && routes_intersect(
                    (&endpoint.methods, &endpoint.path),
                    (&later.methods, &later.path),
                )
        });
        if reached && !catch_all {
            entries.push(Entry::Terminal(endpoint));
        }
    }
    for slug in spec.endpoints.keys() {
        if !endpoints.iter().any(|e| &e.slug == slug) {
            entries.extend(rules_in(Some(slug)));
        }
    }
    entries
}

/// The rule that ends `endpoint`'s rules: it matches every request to the endpoint and gives it
/// `defaults.unmatched`, so none reaches a less specific endpoint's rules.
fn terminal(endpoint: &ContextEndpoint, spec: &Spec, ctx: &Context<'_>) -> CompiledRule {
    let id = rule_key(Some(&endpoint.slug), UNMATCHED_RULE);
    CompiledRule {
        uid: Uuid::new_v5(&ctx.project_id, id.as_bytes()),
        id,
        matcher: CompiledMatch {
            endpoint: Some(CompiledEndpoint {
                slug: endpoint.slug.clone(),
                methods: endpoint.methods.clone(),
                path: endpoint.path.clone(),
            }),
            ip_in: Vec::new(),
            agent: None,
        },
        rate_limit: None,
        free_quota: None,
        action: match spec.defaults.unmatched {
            Verdict::Allow => CompiledAction::Allow {},
            Verdict::Deny => CompiledAction::Deny {
                status: UNMATCHED.0,
                code: UNMATCHED.1.to_owned(),
            },
        },
    }
}

/// Whether every request `later` matches is also matched by `earlier`. Endpoints' rules only
/// meet top-level rules and their own endpoint's.
fn covers(earlier: &Located<'_>, later: &Located<'_>) -> bool {
    let endpoint = earlier.endpoint.is_none() || earlier.endpoint == later.endpoint;
    let (earlier, later) = (&earlier.rule.matcher, &later.rule.matcher);
    let ip = earlier.ip_in.is_empty() || {
        let outer: Vec<IpNet> = earlier
            .ip_in
            .iter()
            .filter_map(|t| parse_cidr(t).ok())
            .collect();
        !later.ip_in.is_empty()
            && later.ip_in.iter().all(|text| {
                parse_cidr(text).is_ok_and(|inner| outer.iter().any(|net| net.contains(&inner)))
            })
    };
    let agent = match (&earlier.agent, &later.agent) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(outer), Some(inner)) => {
            within(&outer.category, &inner.category)
                && within(&outer.signature_agent, &inner.signature_agent)
        }
    };
    endpoint && ip && agent
}

/// Whether a list field of an earlier rule's `agent` holds for every request a later rule's does:
/// the earlier one doesn't constrain it, or the later one names only values the earlier one does.
fn within<T: PartialEq>(outer: &[T], inner: &[T]) -> bool {
    outer.is_empty() || (!inner.is_empty() && inner.iter().all(|value| outer.contains(value)))
}

/// A Web Bot Auth signature agent as an origin: `https://`, then a host and an optional port, in
/// lower case, with no path, query or credentials. One trailing `/` and the default port (`:443`)
/// are dropped, so the origin reads as gates compare it.
fn parse_origin(text: &str) -> Result<String, String> {
    let invalid = || format!("{text:?} isn't an origin, like https://radiustech.xyz");
    let lower = text.trim().to_ascii_lowercase();
    let rest = lower.strip_prefix("https://").ok_or_else(invalid)?;
    let host = rest.strip_suffix('/').unwrap_or(rest);
    let host = host.strip_suffix(":443").unwrap_or(host);
    let valid = !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'));
    if valid {
        Ok(format!("https://{host}"))
    } else {
        Err(invalid())
    }
}

/// Endpoints that overlap a less specific one with rules: the requests both match follow only
/// the more specific endpoint's rules (see [`by_specificity`]), so the other's don't apply to
/// them. One per such pair, most specific endpoint first.
pub fn overlaps(spec: &Spec, endpoints: &[ContextEndpoint]) -> Vec<Overlap> {
    let rules_of = |slug: &str| spec.endpoints.get(slug).map_or(&[][..], |e| &e.rules[..]);
    let order = by_specificity(endpoints);
    let mut overlaps = Vec::new();
    for (position, winner) in order.iter().enumerate() {
        for loser in &order[position + 1..] {
            let (won, lost) = (rules_of(&winner.slug), rules_of(&loser.slug));
            let Some(methods) = winner.methods.intersection(&loser.methods) else {
                continue;
            };
            if lost.is_empty() || !paths_intersect(&winner.path, &loser.path) {
                continue;
            }
            overlaps.push(Overlap {
                endpoint: winner.slug.clone(),
                less_specific: loser.slug.clone(),
                message: overlap_message(
                    winner,
                    loser,
                    &route_label(&methods, &winner.path),
                    won,
                    lost,
                    spec.defaults.unmatched,
                ),
            });
        }
    }
    overlaps
}

/// E.g. "GET /forecast/list is more specific than GET /forecast/:region, so GET /forecast/list
/// follows its own rules (none: free) and GET /forecast/:region's charge doesn't apply to it."
fn overlap_message(
    winner: &ContextEndpoint,
    loser: &ContextEndpoint,
    requests: &str,
    won: &[Rule],
    lost: &[Rule],
    unmatched: Verdict,
) -> String {
    let outcome = match unmatched {
        Verdict::Allow => "free",
        Verdict::Deny => "refused",
    };
    let own = if won.is_empty() {
        format!(" (none: {outcome})")
    } else if won.iter().any(|rule| rule.matcher.is_empty()) {
        String::new()
    } else {
        format!(" ({outcome} when none of them matches)")
    };
    let loser_label = route_label(&loser.methods, &loser.path);
    let theirs = if lost
        .iter()
        .any(|rule| matches!(rule.action, Action::Charge(_)))
    {
        format!("{loser_label}'s charge doesn't apply to it")
    } else {
        format!("{loser_label}'s rules don't apply to it")
    };
    format!(
        "{} is more specific than {loser_label}, so {requests} follows its own rules{own} and {theirs}.",
        route_label(&winner.methods, &winner.path),
    )
}

/// Rules that can never apply: an earlier rule already matches every request they would, so it
/// always decides first. Limits don't change that: past a rate limit the earlier rule denies the
/// request, within a free quota it allows it, and otherwise its action applies; either way the
/// request goes no further.
pub fn warnings(spec: &Spec) -> Vec<Warning> {
    let rules: Vec<Located<'_>> = spec.all_rules().collect();
    let mut warnings = Vec::new();
    for (position, rule) in rules.iter().enumerate() {
        let shadow = rules[..position]
            .iter()
            .find(|earlier| covers(earlier, rule));
        if let Some(earlier) = shadow {
            let every = if earlier.endpoint.is_none() && earlier.rule.matcher.is_empty() {
                "every request"
            } else {
                "every request this rule does"
            };
            warnings.push(Warning {
                field: rule.field(),
                rule: rule.key(),
                message: format!(
                    "Never applies: {:?} before it matches {every}",
                    earlier.key()
                ),
            });
        }
        // One operator's agents leave from shared addresses, so a per-IP limit on them is spent
        // by all of that operator's users at once.
        let per_ip = [&rule.rule.rate_limit, &rule.rule.free_quota]
            .into_iter()
            .flatten()
            .any(|limit| limit.key == LimitKey::Ip);
        if rule.rule.matcher.agent.is_some() && per_ip {
            warnings.push(Warning {
                field: rule.field(),
                rule: rule.key(),
                message: "Counts verified agents per IP: one operator's agents share addresses, \
                          so they'd share one allowance. Count by agent instead"
                    .to_owned(),
            });
        }
    }
    warnings
}
