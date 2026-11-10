//! Checks a compiled policy is one this gateway can enforce in full (gate standard, 9.2), before
//! it replaces the one in force. Serde does most of it: the embedded reference types know the
//! closed sets (action types, limit keys, client IP sources, schemes, agent categories). What's
//! left is the schema version, the project, and payment options without a facilitator.

use policy::Compiled;
use policy::compiled::CompiledAction;
use policy::spec::LimitKey;
use serde_json::Value;
use uuid::Uuid;

use crate::x402::domains;

/// The `schema` values this gateway enforces. A document naming another is refused.
pub const ACCEPTED_SCHEMAS: &[&str] = &["radius.policy/0.1", "radius.policy/0.2"];

#[derive(Debug, thiserror::Error)]
pub enum InvalidPolicy {
    #[error("the document isn't JSON: {0}")]
    NotJson(String),
    #[error("schema {0:?} isn't one this gateway accepts ({accepted})", accepted = ACCEPTED_SCHEMAS.join(", "))]
    Schema(String),
    /// The platform added a field this build's pinned `policy` crate doesn't know. The format is
    /// allowed to grow additively, so the fix is a newer pin, not a platform change.
    #[error(
        "the document has fields this gateway's policy crate doesn't know ({0}); update the pinned radius-platform revision"
    )]
    UnknownField(String),
    #[error("the document can't be read: {0}")]
    Shape(String),
    #[error("the document can't be enforced: {}", .0.join("; "))]
    Problems(Vec<String>),
}

/// A policy this gateway can enforce, and what it noticed on the way.
pub struct Validated {
    pub compiled: Compiled,
    pub warnings: Vec<String>,
}

pub fn validate(body: &[u8], expected_project: Uuid) -> Result<Validated, InvalidPolicy> {
    let value: Value =
        serde_json::from_slice(body).map_err(|error| InvalidPolicy::NotJson(error.to_string()))?;
    // Checked first, so a future version is reported as such rather than as a parse error.
    let schema = value
        .get("schema")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !ACCEPTED_SCHEMAS.contains(&schema) {
        return Err(InvalidPolicy::Schema(schema.to_owned()));
    }

    let compiled: Compiled = serde_path_to_error::deserialize(&value).map_err(|error| {
        let message = format!("{}: {}", error.path(), error.inner());
        if message.contains("unknown field") {
            InvalidPolicy::UnknownField(message)
        } else {
            InvalidPolicy::Shape(message)
        }
    })?;

    let mut problems = Vec::new();
    let mut warnings = Vec::new();
    if compiled.version == 0 {
        problems.push("version must be 1 or more".to_owned());
    }
    if compiled.project_id != expected_project {
        problems.push(format!(
            "project_id {} isn't the configured project {expected_project}",
            compiled.project_id
        ));
    }
    for (index, rule) in compiled.rules.iter().enumerate() {
        let at = format!("rules[{index}] ({})", rule.id);
        if let CompiledAction::Charge { accepts, .. } = &rule.action {
            if accepts.is_empty() {
                problems.push(format!("{at}: action.accepts offers no way to pay"));
            }
            for (option, accept) in accepts.iter().enumerate() {
                if accept.facilitator.as_deref().is_none_or(str::is_empty) {
                    problems.push(format!(
                        "{at}: action.accepts[{option}] names no facilitator, so it can't be paid"
                    ));
                }
                if domains::exact_extra(&accept.network, accept.asset).is_none() {
                    warnings.push(format!(
                        "{at}: {} on {} isn't a token this gateway knows; its facilitator's /supported must describe it or buyers can't sign for it",
                        accept.asset, accept.network
                    ));
                }
            }
        }
        if rule.matcher.agent.is_some() {
            warnings.push(format!(
                "{at}: matches on agent, which this gateway can't verify, so the rule never matches"
            ));
        }
        if [rule.rate_limit, rule.free_quota]
            .iter()
            .flatten()
            .any(|limit| limit.key == LimitKey::Agent)
        {
            warnings.push(format!(
                "{at}: counts by agent, which this gateway can't verify, so it counts by IP"
            ));
        }
    }
    if !problems.is_empty() {
        return Err(InvalidPolicy::Problems(problems));
    }
    Ok(Validated { compiled, warnings })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROJECT: &str = "01a1c14b-cc9f-7033-92d3-bd51d003d97e";

    fn document(rules: Value) -> Value {
        serde_json::json!({
            "schema": "radius.policy/0.1",
            "version": 3,
            "project_id": PROJECT,
            "generated_at": "2026-11-10T14:16:13Z",
            "mode": "test",
            "defaults": {
                "unmatched": "allow",
                "failure": { "counter_error": "within", "no_policy": "allow" },
                "client_ip": "remote_addr",
                "headers": { "ratelimit": true, "retry_after": true }
            },
            "rules": rules
        })
    }

    fn charge(facilitator: Value) -> Value {
        serde_json::json!({
            "uid": "01a1c163-8a2c-765b-8cb1-2effb614f242",
            "id": "charge",
            "match": {},
            "action": {
                "type": "charge",
                "price": "0.01",
                "description": "All endpoints",
                "accepts": [{
                    "scheme": "exact",
                    "network": "eip155:72344",
                    "asset": "0x33ad9e4BD16B69B5BFdED37D8B5D9fF9aba014Fb",
                    "decimals": 6,
                    "amount": "10000",
                    "pay_to": "0x4373dD700774F8C3f649AC58B7EDCC112785Fe6e",
                    "facilitator": facilitator
                }]
            }
        })
    }

    fn run(value: &Value) -> Result<Validated, InvalidPolicy> {
        validate(
            &serde_json::to_vec(value).unwrap(),
            PROJECT.parse().unwrap(),
        )
    }

    #[test]
    fn accepts_the_live_shape() {
        let doc = document(serde_json::json!([charge(serde_json::json!(
            "https://facilitator.testnet.radiustech.xyz"
        ))]));
        let validated = run(&doc).unwrap();
        assert_eq!(validated.compiled.version, 3);
        assert!(validated.warnings.is_empty(), "{:?}", validated.warnings);
    }

    #[test]
    fn refuses_unknown_schemas_first() {
        let mut doc = document(serde_json::json!([]));
        doc["schema"] = "radius.policy/9.9".into();
        doc["rules"] = "not even a list".into();
        assert!(matches!(run(&doc), Err(InvalidPolicy::Schema(s)) if s == "radius.policy/9.9"));
    }

    #[test]
    fn refuses_another_project() {
        let mut doc = document(serde_json::json!([]));
        doc["project_id"] = "00000000-0000-7000-8000-000000000000".into();
        assert!(matches!(run(&doc), Err(InvalidPolicy::Problems(_))));
    }

    #[test]
    fn refuses_options_without_a_facilitator() {
        let doc = document(serde_json::json!([charge(Value::Null)]));
        let Err(InvalidPolicy::Problems(problems)) = run(&doc) else {
            panic!("accepted a null facilitator");
        };
        assert!(problems[0].contains("names no facilitator"), "{problems:?}");
    }

    #[test]
    fn refuses_unknown_action_types_and_names_unknown_fields() {
        let mut rule = charge(serde_json::json!("https://f.example"));
        rule["action"]["type"] = "subscribe".into();
        assert!(matches!(
            run(&document(serde_json::json!([rule]))),
            Err(InvalidPolicy::Shape(_))
        ));

        let mut doc = document(serde_json::json!([]));
        doc["brand_new_field"] = true.into();
        assert!(matches!(run(&doc), Err(InvalidPolicy::UnknownField(_))));
    }

    #[test]
    fn warns_about_unknown_tokens() {
        let mut rule = charge(serde_json::json!("https://f.example"));
        rule["action"]["accepts"][0]["asset"] = "0x036CbD53842c5426634e7929541eC2318f3dCF7e".into();
        let validated = run(&document(serde_json::json!([rule]))).unwrap();
        assert_eq!(validated.warnings.len(), 1);
        assert!(validated.warnings[0].contains("/supported"));
    }
}
