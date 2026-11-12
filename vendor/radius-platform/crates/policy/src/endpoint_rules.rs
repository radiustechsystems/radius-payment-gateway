//! An endpoint's rules (`endpoints.<slug>.rules`), edited as a list of their own with the
//! endpoint. Each can have its own condition (IP ranges), limits and action, so one
//! endpoint can charge different prices to different requests. The first that matches decides,
//! after the top-level rules, as for every rule.
//!
//! [`set_endpoint_rules`] replaces an endpoint's rules, naming new ones after their action.

use domain::matching::unique_slug;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::spec::{Action, Charge, Limit, Match, Rule, Spec};

/// A rule of one endpoint, whose id may be left out.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EndpointRule {
    /// The rule's id among the endpoint's rules. Omit it for a new rule, which is named after its
    /// action (`charge`, `allow`, `deny`); keep it so the rule keeps its counters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Which of the endpoint's requests it's for. Empty for all of them.
    #[serde(rename = "match", default, skip_serializing_if = "Match::is_empty")]
    pub matcher: Match,
    /// Beyond it, requests are denied with `429 rate_limited`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<Limit>,
    /// Within it, requests are allowed free; beyond it, the action applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub free_quota: Option<Limit>,
    pub action: Action,
}

impl EndpointRule {
    /// Charges every request `price` (USD), the default for a new endpoint.
    pub fn charge(price: &str, description: &str) -> Self {
        Self {
            id: None,
            matcher: Match::default(),
            rate_limit: None,
            free_quota: None,
            action: Action::Charge(Charge {
                price: price.to_owned(),
                description: description.to_owned(),
                accepts: None,
                pay_to: None,
            }),
        }
    }

    fn of(rule: &Rule) -> Self {
        Self {
            id: Some(rule.id.clone()),
            matcher: rule.matcher.clone(),
            rate_limit: rule.rate_limit.clone(),
            free_quota: rule.free_quota.clone(),
            action: rule.action.clone(),
        }
    }

    fn into_rule(self, id: String) -> Rule {
        Rule {
            id,
            matcher: self.matcher,
            rate_limit: self.rate_limit,
            free_quota: self.free_quota,
            action: self.action,
        }
    }
}

/// What a new rule is named after.
fn name_for(action: &Action) -> &'static str {
    match action {
        Action::Allow {} => "allow",
        Action::Deny { .. } => "deny",
        Action::Charge(_) => "charge",
    }
}

/// The rules of `endpoint`, in the order they're tried.
pub fn endpoint_rules(spec: &Spec, endpoint: &str) -> Vec<EndpointRule> {
    spec.endpoints
        .get(endpoint)
        .map(|endpoint| endpoint.rules.iter().map(EndpointRule::of).collect())
        .unwrap_or_default()
}

/// `spec` with `endpoint`'s rules replaced by `rules`, in order. Rules without an id are named
/// after their action (`charge`, `charge-2`); a given id is kept, and the compiler reports one that
/// another of the endpoint's rules already has. No rules removes the endpoint from the policy.
pub fn set_endpoint_rules(spec: &Spec, endpoint: &str, rules: Vec<EndpointRule>) -> Spec {
    let mut taken: Vec<String> = rules.iter().filter_map(|rule| rule.id.clone()).collect();
    let rules: Vec<Rule> = rules
        .into_iter()
        .map(|rule| {
            let id = match &rule.id {
                Some(id) => id.clone(),
                None => {
                    let id = unique_slug(name_for(&rule.action), |candidate| {
                        taken.iter().any(|t| t == candidate)
                    });
                    taken.push(id.clone());
                    id
                }
            };
            rule.into_rule(id)
        })
        .collect();
    let mut spec = spec.clone();
    if rules.is_empty() {
        spec.endpoints.remove(endpoint);
    } else {
        spec.endpoints.entry(endpoint.to_owned()).or_default().rules = rules;
    }
    spec
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{Endpoint, LimitKey};

    fn rule(id: &str) -> Rule {
        Rule {
            id: id.to_owned(),
            matcher: Match::default(),
            rate_limit: None,
            free_quota: None,
            action: Action::Allow {},
        }
    }

    fn ids<'a>(spec: &'a Spec, endpoint: &str) -> Vec<&'a str> {
        spec.endpoints[endpoint]
            .rules
            .iter()
            .map(|rule| rule.id.as_str())
            .collect()
    }

    fn policy() -> Spec {
        Spec {
            rules: vec![Rule {
                matcher: Match {
                    ip_in: vec!["203.0.113.0/24".to_owned()],
                    agent: None,
                },
                ..rule("deny-abusive")
            }],
            endpoints: [
                (
                    "get-tx".to_owned(),
                    Endpoint {
                        rules: vec![rule("free"), rule("paid")],
                    },
                ),
                (
                    "get-price".to_owned(),
                    Endpoint {
                        rules: vec![rule("free")],
                    },
                ),
            ]
            .into(),
            ..Spec::new()
        }
    }

    #[test]
    fn reads_an_endpoints_rules() {
        let rules = endpoint_rules(&policy(), "get-tx");
        assert_eq!(
            rules
                .iter()
                .map(|rule| rule.id.as_deref().unwrap())
                .collect::<Vec<_>>(),
            ["free", "paid"]
        );
        assert!(endpoint_rules(&policy(), "post-quote").is_empty());
    }

    #[test]
    fn replaces_an_endpoints_rules_and_leaves_the_others() {
        let partners = EndpointRule {
            matcher: Match {
                ip_in: vec!["198.51.100.0/24".to_owned()],
                agent: None,
            },
            ..EndpointRule::charge("0.0005", "Partner price")
        };
        let kept = EndpointRule {
            id: Some("paid".to_owned()),
            ..EndpointRule::charge("0.002", "Lookup")
        };
        let spec = set_endpoint_rules(&policy(), "get-tx", vec![partners, kept]);
        assert_eq!(ids(&spec, "get-tx"), ["charge", "paid"]);
        assert_eq!(
            spec.endpoints["get-tx"].rules[0].matcher.ip_in,
            ["198.51.100.0/24"]
        );
        assert_eq!(ids(&spec, "get-price"), ["free"]);
        assert_eq!(spec.rules, policy().rules);
    }

    #[test]
    fn new_rules_are_named_after_their_action_within_the_endpoint() {
        let spec = set_endpoint_rules(
            &policy(),
            "post-quote",
            vec![
                EndpointRule {
                    free_quota: Some(Limit {
                        key: LimitKey::Ip,
                        quota: 10,
                        window: "1m".to_owned(),
                    }),
                    ..EndpointRule::charge("0.01", "Quote")
                },
                EndpointRule::charge("0.02", "Quote"),
                EndpointRule {
                    id: Some("charge-3".to_owned()),
                    ..EndpointRule::charge("0.03", "Quote")
                },
                EndpointRule {
                    action: Action::Allow {},
                    ..EndpointRule::charge("0", "")
                },
            ],
        );
        assert_eq!(
            ids(&spec, "post-quote"),
            ["charge", "charge-2", "charge-3", "allow"]
        );
    }

    #[test]
    fn no_rules_removes_the_endpoint() {
        let spec = set_endpoint_rules(&policy(), "get-tx", vec![]);
        assert!(!spec.endpoints.contains_key("get-tx"));
        assert_eq!(ids(&spec, "get-price"), ["free"]);
    }
}
