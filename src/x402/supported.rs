//! What a facilitator supports (`GET /supported`): the payment kinds, with each asset's transfer
//! method and EIP-712 domain, and the extensions it accepts. The challenge is built from it, so
//! buyers sign what the facilitator can settle.

use serde::Deserialize;
use serde_json::{Value, json};

/// The gas-sponsoring extension: the facilitator submits the buyer's EIP-2612 permit for Permit2
/// itself, so a wallet that holds only the token can pay. Declared in a challenge as the x402
/// extension spec (`specs/extensions/eip2612_gas_sponsoring.md`) and the Radius SDK write it.
pub const EIP2612_GAS_SPONSORING: &str = "eip2612GasSponsoring";

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Supported {
    #[serde(default)]
    pub kinds: Vec<Kind>,
    #[serde(default)]
    pub extensions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Kind {
    #[serde(default)]
    pub x402_version: u8,
    #[serde(default)]
    pub scheme: String,
    #[serde(default)]
    pub network: String,
    #[serde(default)]
    pub asset: Option<String>,
    #[serde(default)]
    pub extra: Option<Value>,
}

impl Supported {
    pub fn declares(&self, extension: &str) -> bool {
        self.extensions.iter().any(|name| name == extension)
    }

    /// The `extra` to offer for `asset` on `network` under the `exact` scheme, from the kind the
    /// facilitator advertises for it. With a choice of transfer methods, EIP-3009 comes first:
    /// one signature moves the tokens, with no Permit2 allowance to arrange and no extension to
    /// carry. Permit2 is for tokens the facilitator only settles that way.
    pub fn exact_extra(&self, network: &str, asset: &str) -> Option<Value> {
        let kinds: Vec<&Kind> = self
            .kinds
            .iter()
            .filter(|kind| {
                kind.x402_version == 2
                    && kind.scheme == "exact"
                    && kind.network == network
                    && kind
                        .asset
                        .as_deref()
                        .is_some_and(|a| a.eq_ignore_ascii_case(asset))
            })
            .collect();
        let method = |kind: &&Kind| {
            kind.extra
                .as_ref()
                .and_then(|extra| extra.get("assetTransferMethod"))
                .and_then(Value::as_str)
                .unwrap_or("eip3009")
                .to_owned()
        };
        ["eip3009", "permit2"]
            .iter()
            .find_map(|wanted| kinds.iter().find(|kind| method(kind) == *wanted))
            .or(kinds.first())
            .map(|kind| kind.extra.clone().unwrap_or_else(|| json!({})))
    }
}

/// The declaration of the gas-sponsoring extension, for `PaymentRequired.extensions`.
pub fn gas_sponsoring_declaration() -> Value {
    let address = json!({ "type": "string", "pattern": "^0x[a-fA-F0-9]{40}$" });
    let integer = json!({ "type": "string", "pattern": "^[0-9]+$" });
    json!({
        "info": {
            "description": "The facilitator accepts EIP-2612 gasless Permit to `Permit2` canonical contract.",
            "version": "1"
        },
        "schema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "from": address,
                "asset": address,
                "spender": address,
                "amount": integer,
                "nonce": integer,
                "deadline": integer,
                "signature": { "type": "string", "pattern": "^0x[a-fA-F0-9]+$" },
                "version": { "type": "string", "pattern": "^[0-9]+(\\.[0-9]+)*$" }
            },
            "required": ["from", "asset", "spender", "amount", "nonce", "deadline", "signature", "version"]
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SBC: &str = "0x33ad9e4BD16B69B5BFdED37D8B5D9fF9aba014Fb";

    fn kind(transfer_method: &str) -> Value {
        json!({
            "x402Version": 2, "scheme": "exact", "network": "eip155:72344", "asset": SBC,
            "extra": { "assetTransferMethod": transfer_method, "name": "Stable Coin", "version": "1" }
        })
    }

    fn radius(kinds: Vec<Value>) -> Supported {
        serde_json::from_value(json!({
            "kinds": kinds,
            "extensions": ["eip2612GasSponsoring"],
            "signers": {}
        }))
        .unwrap()
    }

    #[test]
    fn prefers_eip3009_when_offered() {
        let supported = radius(vec![kind("permit2"), kind("eip3009")]);
        let extra = supported
            .exact_extra("eip155:72344", &SBC.to_lowercase())
            .unwrap();
        assert_eq!(extra["assetTransferMethod"], "eip3009");
        assert_eq!(extra["name"], "Stable Coin");
        assert!(supported.exact_extra("eip155:8453", SBC).is_none());
    }

    #[test]
    fn offers_permit2_for_tokens_only_settled_that_way() {
        let supported = radius(vec![kind("permit2")]);
        let extra = supported.exact_extra("eip155:72344", SBC).unwrap();
        assert_eq!(extra["assetTransferMethod"], "permit2");
    }
}
