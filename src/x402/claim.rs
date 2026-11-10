//! A payment's identity, so one payment can't pay for two requests however the client encodes
//! the header.

use std::str::FromStr;

use alloy_primitives::{Address, U256, address};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The Permit2 contract, at the same address on every EVM chain. A Permit2 nonce is single-use
/// per owner in this contract, whatever the token or spender, so the contract is its namespace.
/// The payload doesn't name it: `permit2Authorization.spender` is x402's proxy, not Permit2.
const PERMIT2: Address = address!("0x000000000022D473030F116dDEE9F6B43aC78BA3");

/// SHA-256 hex, never logged. A payment the chain can execute once is identified by what makes
/// it single-use there, spelled one way, so a re-encoded copy can't pass as a new payment:
/// Permit2 (`exact` on EVM with `permit2Authorization`) by network, Permit2, owner and nonce;
/// EIP-3009 (`authorization`) by network, token, payer and nonce. `permit2Authorization` is
/// read first because facilitators settle it when a payload carries both. Anything else is
/// identified by its header.
pub fn payment_id(payload: &Value, raw_header: &str) -> String {
    let text = |pointer: &str| payload.pointer(pointer).and_then(Value::as_str);
    let network = text("/accepted/network");
    let identity = match (
        network,
        text("/payload/permit2Authorization/from"),
        text("/payload/permit2Authorization/nonce"),
    ) {
        (Some(network), Some(owner), Some(nonce)) => format!(
            "{network}:{PERMIT2:#x}:{}:{}",
            address(owner),
            number(nonce)
        ),
        _ => match (
            network,
            text("/accepted/asset"),
            text("/payload/authorization/from"),
            text("/payload/authorization/nonce"),
        ) {
            (Some(network), Some(asset), Some(from), Some(nonce)) => format!(
                "{network}:{}:{}:{}",
                address(asset),
                address(from),
                number(nonce)
            ),
            _ => raw_header.trim().to_owned(),
        },
    };
    let digest = Sha256::digest(identity.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// An address in lower-case hex with `0x`; text that isn't one, trimmed and in lower case.
fn address(text: &str) -> String {
    let text = text.trim().to_lowercase();
    Address::from_str(&text).map_or(text, |address| format!("{address:#x}"))
}

/// A decimal or `0x` hex integer (a Permit2 nonce, or an EIP-3009 nonce as 32 bytes of hex) in
/// decimal, so leading zeros, hex case and base don't matter; other text, trimmed and in lower
/// case. Two nonces equal as numbers are taken for one payment: at worst a payment is refused.
fn number(text: &str) -> String {
    let text = text.trim().to_lowercase();
    U256::from_str(&text).map_or(text, |number| number.to_string())
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

    #[test]
    fn identifies_a_payment_by_its_signer_and_nonce_spelled_one_way() {
        let sbc = "0x33ad9e4BD16B69B5BFdED37D8B5D9fF9aba014Fb";
        let usdc = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
        let payer = "0x857b06519E91e3A54538791bDbb0E22373e36b66";
        let other = "0x4373dD700774F8C3f649AC58B7EDCC112785Fe6e";
        let eip3009 = json!({
            "accepted": { "network": "eip155:72344", "asset": sbc },
            "payload": { "authorization": { "from": payer, "nonce": "0x00ff" } }
        });
        let permit2 = json!({
            "accepted": { "network": "eip155:72344", "asset": sbc },
            "payload": {
                "permit2Authorization": { "permitted": { "token": sbc }, "from": payer, "nonce": "255" }
            }
        });
        // `base` with the member at each pointer set, created if absent.
        let with = |base: &Value, changes: &[(&str, Value)]| {
            let mut payment = base.clone();
            for (pointer, value) in changes {
                let (parent, key) = pointer.rsplit_once('/').unwrap();
                payment.pointer_mut(parent).unwrap()[key] = value.clone();
            }
            payment
        };
        let cases = [
            (
                "EIP-3009, the payer in upper case",
                &eip3009,
                vec![("/payload/authorization/from", payer.to_uppercase().into())],
                true,
            ),
            (
                "EIP-3009, the nonce in upper case without its leading zeros",
                &eip3009,
                vec![("/payload/authorization/nonce", "0xFF".into())],
                true,
            ),
            (
                "Permit2 for another token, since its nonces are per owner",
                &permit2,
                vec![
                    ("/accepted/asset", usdc.into()),
                    ("/payload/permit2Authorization/permitted/token", usdc.into()),
                ],
                true,
            ),
            (
                "Permit2 beside an EIP-3009 authorization, which facilitators don't settle",
                &permit2,
                vec![(
                    "/payload/authorization",
                    json!({ "from": payer, "nonce": "0x1" }),
                )],
                true,
            ),
            (
                "Permit2 on another network",
                &permit2,
                vec![("/accepted/network", "eip155:723487".into())],
                false,
            ),
            (
                "Permit2 from another owner",
                &permit2,
                vec![("/payload/permit2Authorization/from", other.into())],
                false,
            ),
            (
                "Permit2 with another nonce",
                &permit2,
                vec![("/payload/permit2Authorization/nonce", "256".into())],
                false,
            ),
        ];
        for (case, base, changes, same) in cases {
            let changed = with(base, &changes);
            assert_eq!(
                payment_id(base, "A") == payment_id(&changed, "B"),
                same,
                "{case}"
            );
        }
    }
}
