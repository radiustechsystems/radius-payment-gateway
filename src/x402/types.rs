//! The x402 version 2 messages the gateway sends and reads, as JSON in base64 headers.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// The challenge a 402 carries.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequired {
    pub x402_version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub resource: ResourceInfo,
    pub accepts: Vec<PaymentRequirements>,
    /// Extensions the facilitator accepts, declared for the buyer (`eip2612GasSponsoring`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceInfo {
    pub url: String,
    pub description: String,
}

/// One way to pay, as x402 spells it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirements {
    pub scheme: String,
    /// CAIP-2.
    pub network: String,
    /// The token's smallest unit, as a decimal string.
    pub amount: String,
    pub asset: String,
    pub pay_to: String,
    pub max_timeout_seconds: u32,
    #[serde(default)]
    pub extra: Value,
}

impl PaymentRequirements {
    /// Whether a client's `accepted` is this requirement: scheme, network and amount exactly,
    /// addresses case-insensitively.
    pub fn matches(&self, accepted: &Map<String, Value>) -> bool {
        let text = |key: &str| accepted.get(key).and_then(Value::as_str);
        let same = |a: &str, b: Option<&str>| b.is_some_and(|b| a.eq_ignore_ascii_case(b));
        text("scheme") == Some(self.scheme.as_str())
            && text("network") == Some(self.network.as_str())
            && text("amount") == Some(self.amount.as_str())
            && same(&self.asset, text("asset"))
            && same(&self.pay_to, text("payTo"))
    }
}

/// `POST /verify`'s answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponse {
    pub is_valid: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invalid_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

/// `POST /settle`'s answer, and the `PAYMENT-RESPONSE` header.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettleResponse {
    pub success: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<String>,
    /// Empty when nothing was broadcast.
    #[serde(default)]
    pub transaction: String,
    #[serde(default)]
    pub network: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    #[serde(flatten)]
    pub rest: Map<String, Value>,
}

/// JSON as the x402 headers carry it: base64 of UTF-8.
pub fn encode_header<T: Serialize>(value: &T) -> String {
    STANDARD.encode(serde_json::to_vec(value).expect("x402 messages serialize"))
}

pub fn decode_header(text: &str) -> Option<Value> {
    let bytes = STANDARD.decode(text.trim()).ok()?;
    serde_json::from_slice(&bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn round_trips_through_base64() {
        let required = PaymentRequired {
            x402_version: 2,
            error: None,
            resource: ResourceInfo {
                url: "https://a.example/x".into(),
                description: "d".into(),
            },
            accepts: vec![],
            extensions: None,
        };
        let encoded = encode_header(&required);
        let decoded = decode_header(&encoded).unwrap();
        assert_eq!(decoded["x402Version"], 2);
        assert_eq!(decoded["resource"]["url"], "https://a.example/x");
        assert!(decoded.get("error").is_none());
        assert!(decode_header("not base64!").is_none());
        assert!(decode_header(&STANDARD.encode("not json")).is_none());
    }

    #[test]
    fn matches_addresses_case_insensitively() {
        let offered = PaymentRequirements {
            scheme: "exact".into(),
            network: "eip155:72344".into(),
            amount: "10000".into(),
            asset: "0x33ad9e4BD16B69B5BFdED37D8B5D9fF9aba014Fb".into(),
            pay_to: "0x4373dD700774F8C3f649AC58B7EDCC112785Fe6e".into(),
            max_timeout_seconds: 60,
            extra: json!({}),
        };
        let mut accepted = json!({
            "scheme": "exact", "network": "eip155:72344", "amount": "10000",
            "asset": "0x33ad9e4bd16b69b5bfded37d8b5d9ff9aba014fb",
            "payTo": "0x4373DD700774F8C3F649AC58B7EDCC112785FE6E",
            "maxTimeoutSeconds": 60
        });
        assert!(offered.matches(accepted.as_object().unwrap()));
        accepted["amount"] = "9999".into();
        assert!(!offered.matches(accepted.as_object().unwrap()));
    }
}
