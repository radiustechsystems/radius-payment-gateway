//! Moving a policy between modes. Every token a policy accepts belongs to a network of its mode,
//! so a switch has to take the policy's tokens along: each moves to the same token on its
//! network's counterpart (SBC on Radius testnet becomes SBC on Radius), and one the new mode can't
//! take yet (Base has no facilitator) falls back to the new mode's default. The switch never
//! fails on a token of the old mode; it tells the caller what it changed instead.

use std::collections::BTreeSet;
use std::str::FromStr;

use alloy_primitives::Address;
use domain::payment::{PaymentOption, asset_named, switch_option};
use domain::pricing::catalog::{self, Mode, Scheme};
use domain::wallet::checksummed;

use crate::spec::{Accept, Action, Rule, Spec, rule_field, rule_key};

/// One accepted token and what it becomes after the switch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptChange {
    /// Where it's accepted: `defaults.payment.accepts`, or a charge rule's own
    /// `rules[0].action.accepts` or `endpoints.<slug>.rules[1].action.accepts`.
    pub field: String,
    /// The rule's key, for a rule's own `accepts` ([`rule_key`]).
    pub rule: Option<String>,
    pub from: PaymentOption,
    pub to: PaymentOption,
    /// Why `to` isn't the same token on `from`'s counterpart network: the switch fell back to the
    /// new mode's default.
    pub reason: Option<String>,
}

const DEFAULTS: &str = "defaults.payment.accepts";

/// `spec` with every token it accepts moved to `to`, and what each became. Without
/// `defaults.payment.accepts` the policy accepts the mode's default, so that's listed as the
/// change and the document is left as it is. Nothing changes when `from` is `to`.
pub fn switch_mode(spec: &Spec, from: Mode, to: Mode) -> (Spec, Vec<AcceptChange>) {
    let mut spec = spec.clone();
    let mut changes = Vec::new();
    if from == to {
        return (spec, changes);
    }
    match spec
        .defaults
        .payment
        .as_mut()
        .filter(|payment| !payment.accepts.is_empty())
    {
        Some(payment) => {
            payment.accepts = switch_accepts(&payment.accepts, to, DEFAULTS, None, &mut changes);
        }
        None => changes.push(AcceptChange {
            field: DEFAULTS.to_owned(),
            rule: None,
            from: PaymentOption::default_for(from),
            to: PaymentOption::default_for(to),
            reason: None,
        }),
    }
    for (index, rule) in spec.rules.iter_mut().enumerate() {
        switch_rule(rule, None, index, to, &mut changes);
    }
    for (slug, endpoint) in &mut spec.endpoints {
        for (index, rule) in endpoint.rules.iter_mut().enumerate() {
            switch_rule(rule, Some(slug), index, to, &mut changes);
        }
    }
    (spec, changes)
}

/// Moves a charge rule's own `accepts`, if it has them.
fn switch_rule(
    rule: &mut Rule,
    endpoint: Option<&str>,
    index: usize,
    mode: Mode,
    changes: &mut Vec<AcceptChange>,
) {
    let key = rule_key(endpoint, &rule.id);
    let field = format!("{}.action.accepts", rule_field(endpoint, index));
    if let Action::Charge(charge) = &mut rule.action
        && let Some(accepts) = &charge.accepts
    {
        charge.accepts = Some(switch_accepts(accepts, mode, &field, Some(&key), changes));
    }
}

/// `accepts` moved to `mode`, each change recorded under `field`. A token the catalog doesn't
/// have is left as written, for the compiler to report.
fn switch_accepts(
    accepts: &[Accept],
    mode: Mode,
    field: &str,
    rule: Option<&str>,
    changes: &mut Vec<AcceptChange>,
) -> Vec<Accept> {
    let mut moved = Vec::with_capacity(accepts.len());
    let mut seen = BTreeSet::new();
    for accept in accepts {
        let Some(from) = resolve(accept) else {
            moved.push(accept.clone());
            continue;
        };
        let (to, reason) = switch_option(&from, mode);
        changes.push(AcceptChange {
            field: field.to_owned(),
            rule: rule.map(str::to_owned),
            from,
            to,
            reason,
        });
        // Two tokens that fall back to the same default are accepted once.
        if seen.insert((to.network.chain_id(), to.asset.address)) {
            moved.push(accept_for(&to, accept));
        }
    }
    moved
}

/// The catalog option `accept` names, whatever its mode.
fn resolve(accept: &Accept) -> Option<PaymentOption> {
    let network = catalog::network(accept.network.trim())?;
    let asset = asset_named(network, accept.asset.trim())?;
    let scheme = match accept.scheme.as_deref().map(str::trim) {
        None | Some("") => Scheme::Exact,
        Some(text) => Scheme::parse(text)?,
    };
    Some(PaymentOption {
        network,
        asset,
        scheme,
    })
}

/// `option` written the way `like` was: the asset by its address if `like` gave one, else by its
/// symbol, and the scheme only if `like` named one.
fn accept_for(option: &PaymentOption, like: &Accept) -> Accept {
    let by_address = Address::from_str(like.asset.trim()).is_ok();
    Accept {
        network: option.network.caip2(),
        asset: if by_address {
            checksummed(&option.asset.address)
        } else {
            option.asset.symbol.to_owned()
        },
        scheme: like
            .scheme
            .as_ref()
            .map(|_| option.scheme.as_str().to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{Charge, Payment};

    const RADIUS_TESTNET: &str = "eip155:72344";
    const BASE_SEPOLIA: &str = "eip155:84532";
    const RADIUS: &str = "eip155:723487";
    const BASE_SEPOLIA_USDC: &str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";

    fn accept(network: &str, asset: &str) -> Accept {
        Accept {
            network: network.to_owned(),
            asset: asset.to_owned(),
            scheme: None,
        }
    }

    fn charge(id: &str, accepts: Option<Vec<Accept>>) -> Rule {
        Rule {
            id: id.to_owned(),
            matcher: Default::default(),
            rate_limit: None,
            free_quota: None,
            action: Action::Charge(Charge {
                price: "0.001".to_owned(),
                description: id.to_owned(),
                accepts,
                pay_to: None,
            }),
        }
    }

    fn spec_accepting(accepts: Vec<Accept>) -> Spec {
        let mut spec = Spec::new();
        spec.defaults.payment = Some(Payment {
            accepts,
            pay_to: None,
        });
        spec
    }

    /// `(field, rule, from, to, reason)` of a change, by labels.
    fn summary(change: &AcceptChange) -> (&str, Option<&str>, String, String, Option<&str>) {
        let label =
            |option: &PaymentOption| format!("{} on {}", option.asset.symbol, option.network.label);
        (
            &change.field,
            change.rule.as_deref(),
            label(&change.from),
            label(&change.to),
            change.reason.as_deref(),
        )
    }

    #[test]
    fn moves_the_accepted_tokens_to_their_counterpart_networks() {
        let spec = spec_accepting(vec![accept(RADIUS_TESTNET, "SBC")]);
        let (live, changes) = switch_mode(&spec, Mode::Test, Mode::Production);
        assert_eq!(
            live.defaults.payment.as_ref().unwrap().accepts,
            [accept(RADIUS, "SBC")]
        );
        assert_eq!(
            changes.iter().map(summary).collect::<Vec<_>>(),
            [(
                DEFAULTS,
                None,
                "SBC on Radius testnet".to_owned(),
                "SBC on Radius".to_owned(),
                None
            )]
        );

        // And back.
        let (test, changes) = switch_mode(&live, Mode::Production, Mode::Test);
        assert_eq!(
            test.defaults.payment.unwrap().accepts,
            [accept(RADIUS_TESTNET, "SBC")]
        );
        assert_eq!(changes.len(), 1);
    }

    #[test]
    fn falls_back_to_the_default_for_a_token_the_new_mode_cant_take_yet() {
        // Base can't settle payments yet, so both of Base Sepolia's tokens become the live
        // default, which is also where Radius testnet's SBC goes: accepted once, in the form
        // the first was written in (by address).
        let spec = spec_accepting(vec![
            accept(BASE_SEPOLIA, BASE_SEPOLIA_USDC),
            accept(BASE_SEPOLIA, "SBC"),
            accept(RADIUS_TESTNET, "SBC"),
        ]);
        let (live, changes) = switch_mode(&spec, Mode::Test, Mode::Production);
        assert_eq!(
            live.defaults.payment.unwrap().accepts,
            [accept(RADIUS, "0x33ad9e4BD16B69B5BFdED37D8B5D9fF9aba014Fb")]
        );
        let reason = Some("Payments on Base can't be settled yet");
        assert_eq!(
            changes.iter().map(summary).collect::<Vec<_>>(),
            [
                (
                    DEFAULTS,
                    None,
                    "USDC on Base Sepolia".to_owned(),
                    "SBC on Radius".to_owned(),
                    reason
                ),
                (
                    DEFAULTS,
                    None,
                    "SBC on Base Sepolia".to_owned(),
                    "SBC on Radius".to_owned(),
                    reason
                ),
                (
                    DEFAULTS,
                    None,
                    "SBC on Radius testnet".to_owned(),
                    "SBC on Radius".to_owned(),
                    None
                ),
            ]
        );
    }

    #[test]
    fn moves_each_charge_rules_own_tokens_and_names_the_rule() {
        let mut spec = Spec::new();
        spec.rules.push(charge(
            "premium",
            Some(vec![Accept {
                scheme: Some("exact".to_owned()),
                ..accept(RADIUS_TESTNET, "SBC")
            }]),
        ));
        spec.rules.push(charge("inherits", None));
        spec.endpoints
            .entry("price".to_owned())
            .or_default()
            .rules
            .push(charge("metered", Some(vec![accept(BASE_SEPOLIA, "USDC")])));

        let (live, changes) = switch_mode(&spec, Mode::Test, Mode::Production);
        let accepts = |rule: &Rule| match &rule.action {
            Action::Charge(charge) => charge.accepts.clone(),
            _ => unreachable!(),
        };
        assert_eq!(
            accepts(&live.rules[0]),
            Some(vec![Accept {
                scheme: Some("exact".to_owned()),
                ..accept(RADIUS, "SBC")
            }])
        );
        assert_eq!(accepts(&live.rules[1]), None);
        assert_eq!(
            accepts(&live.endpoints["price"].rules[0]),
            Some(vec![accept(RADIUS, "SBC")])
        );
        assert_eq!(
            changes.iter().map(summary).collect::<Vec<_>>(),
            [
                (
                    DEFAULTS,
                    None,
                    "SBC on Radius testnet".to_owned(),
                    "SBC on Radius".to_owned(),
                    None
                ),
                (
                    "rules[0].action.accepts",
                    Some("premium"),
                    "SBC on Radius testnet".to_owned(),
                    "SBC on Radius".to_owned(),
                    None
                ),
                (
                    "endpoints.price.rules[0].action.accepts",
                    Some("price/metered"),
                    "USDC on Base Sepolia".to_owned(),
                    "SBC on Radius".to_owned(),
                    Some("Payments on Base can't be settled yet")
                ),
            ]
        );
    }

    #[test]
    fn a_policy_on_the_default_token_lists_the_new_default_and_keeps_its_document() {
        let spec = Spec::new();
        let (live, changes) = switch_mode(&spec, Mode::Test, Mode::Production);
        assert_eq!(live, spec);
        assert_eq!(
            changes.iter().map(summary).collect::<Vec<_>>(),
            [(
                DEFAULTS,
                None,
                "SBC on Radius testnet".to_owned(),
                "SBC on Radius".to_owned(),
                None
            )]
        );
    }

    #[test]
    fn the_same_mode_and_unknown_tokens_change_nothing() {
        let spec = spec_accepting(vec![accept(RADIUS_TESTNET, "SBC")]);
        let (same, changes) = switch_mode(&spec, Mode::Test, Mode::Test);
        assert_eq!(same, spec);
        assert!(changes.is_empty());

        // A token the catalog doesn't have is left for the compiler to refuse.
        let spec = spec_accepting(vec![accept("eip155:1", "DAI")]);
        let (live, changes) = switch_mode(&spec, Mode::Test, Mode::Production);
        assert_eq!(live, spec);
        assert!(changes.is_empty());
    }
}
