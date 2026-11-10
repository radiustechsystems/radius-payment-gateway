//! A payment's identity, so one payment can't pay for two requests however the client encodes
//! the header.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// SHA-256 hex, never logged. For an authorization with a payer and a nonce (`exact` on EVM:
/// EIP-3009), those and the token identify it, so a re-encoded copy can't pass as a new payment.
/// Anything else is identified by its header.
pub fn payment_id(payload: &Value, raw_header: &str) -> String {
    let text = |pointer: &str| payload.pointer(pointer).and_then(Value::as_str);
    let identity = match (
        text("/accepted/network"),
        text("/accepted/asset"),
        text("/payload/authorization/from"),
        text("/payload/authorization/nonce"),
    ) {
        (Some(network), Some(asset), Some(from), Some(nonce)) => {
            format!("{network}:{asset}:{from}:{nonce}").to_lowercase()
        }
        _ => raw_header.trim().to_owned(),
    };
    let digest = Sha256::digest(identity.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn identifies_by_token_payer_and_nonce() {
        let a = json!({
            "accepted": { "network": "eip155:72344", "asset": "0xAbC" },
            "payload": { "authorization": { "from": "0xF00", "nonce": "0x01" }, "signature": "0x1" }
        });
        let mut b = a.clone();
        b["payload"]["signature"] = "0x2".into();
        b["accepted"]["asset"] = "0xabc".into();
        assert_eq!(payment_id(&a, "AAA"), payment_id(&b, "BBB"));
        let mut c = a.clone();
        c["payload"]["authorization"]["nonce"] = "0x02".into();
        assert_ne!(payment_id(&a, "AAA"), payment_id(&c, "AAA"));
        // Without an authorization, the header itself is the identity.
        let d = json!({ "accepted": {}, "payload": {} });
        assert_eq!(payment_id(&d, " X "), payment_id(&d, "X"));
        assert_ne!(payment_id(&d, "X"), payment_id(&d, "Y"));
    }
}
