//! What the `exact` scheme needs to offer a token when its facilitator's `/supported` can't be
//! read: the transfer method and the token's EIP-712 domain. The compiled form doesn't carry them
//! (gate standard, 6.1), so gates keep them per asset. A wrong entry can't move money: buyers'
//! signatures would fail verification.

use alloy_primitives::Address;
use serde_json::{Value, json};

/// SBC, "Stable Coin" version "1", on Radius and Radius testnet. SBC has no EIP-3009, so it's
/// paid through Permit2.
const SBC: Address = Address::new([
    0x33, 0xad, 0x9e, 0x4b, 0xd1, 0x6b, 0x69, 0xb5, 0xbf, 0xde, 0xd3, 0x7d, 0x8b, 0x5d, 0x9f, 0xf9,
    0xab, 0xa0, 0x14, 0xfb,
]);

struct Known {
    network: &'static str,
    asset: Address,
    transfer_method: &'static str,
    name: &'static str,
    version: &'static str,
}

const KNOWN: &[Known] = &[
    Known {
        network: "eip155:723487",
        asset: SBC,
        transfer_method: "permit2",
        name: "Stable Coin",
        version: "1",
    },
    Known {
        network: "eip155:72344",
        asset: SBC,
        transfer_method: "permit2",
        name: "Stable Coin",
        version: "1",
    },
];

/// The `extra` for the token, if known.
pub fn exact_extra(network: &str, asset: Address) -> Option<Value> {
    KNOWN
        .iter()
        .find(|known| known.network == network && known.asset == asset)
        .map(|known| {
            json!({
                "assetTransferMethod": known.transfer_method,
                "name": known.name,
                "version": known.version,
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn knows_sbc_on_radius() {
        let sbc: Address = "0x33ad9e4BD16B69B5BFdED37D8B5D9fF9aba014Fb"
            .parse()
            .unwrap();
        let extra = exact_extra("eip155:72344", sbc).unwrap();
        assert_eq!(extra["assetTransferMethod"], "permit2");
        assert_eq!(extra["name"], "Stable Coin");
        assert_eq!(extra["version"], "1");
        assert!(exact_extra("eip155:723487", sbc).is_some());
        assert!(exact_extra("eip155:8453", sbc).is_none());
    }
}
