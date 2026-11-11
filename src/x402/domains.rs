//! What the `exact` scheme needs to offer a token when its facilitator's `/supported` can't be
//! read: the transfer method and the token's EIP-712 domain. The compiled form doesn't carry them
//! (gate standard, 6.1), so gates keep them per asset. A wrong entry can't move money: buyers'
//! signatures would fail verification.

use alloy_primitives::Address;
use serde_json::{Value, json};

/// SBC, "Stable Coin" version "1", on Radius and Radius testnet. SBC implements EIP-3009
/// (`transferWithAuthorization`), which the Radius facilitator settles.
const SBC: Address = Address::new([
    0x33, 0xad, 0x9e, 0x4b, 0xd1, 0x6b, 0x69, 0xb5, 0xbf, 0xde, 0xd3, 0x7d, 0x8b, 0x5d, 0x9f, 0xf9,
    0xab, 0xa0, 0x14, 0xfb,
]);
/// USDC on Base Sepolia: its EIP-712 domain is "USDC" version "2" (read from the contract).
const USDC_BASE_SEPOLIA: Address = Address::new([
    0x03, 0x6c, 0xbd, 0x53, 0x84, 0x2c, 0x54, 0x26, 0x63, 0x4e, 0x79, 0x29, 0x54, 0x1e, 0xc2, 0x31,
    0x8f, 0x3d, 0xcf, 0x7e,
]);
/// USDC on Base: "USD Coin" version "2" (read from the contract).
const USDC_BASE: Address = Address::new([
    0x83, 0x35, 0x89, 0xfc, 0xd6, 0xed, 0xb6, 0xe0, 0x8f, 0x4c, 0x7c, 0x32, 0xd4, 0xf7, 0x1b, 0x54,
    0xbd, 0xa0, 0x29, 0x13,
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
        transfer_method: "eip3009",
        name: "Stable Coin",
        version: "1",
    },
    Known {
        network: "eip155:72344",
        asset: SBC,
        transfer_method: "eip3009",
        name: "Stable Coin",
        version: "1",
    },
    Known {
        network: "eip155:84532",
        asset: USDC_BASE_SEPOLIA,
        transfer_method: "eip3009",
        name: "USDC",
        version: "2",
    },
    Known {
        network: "eip155:8453",
        asset: USDC_BASE,
        transfer_method: "eip3009",
        name: "USD Coin",
        version: "2",
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
        assert_eq!(extra["assetTransferMethod"], "eip3009");
        assert_eq!(extra["name"], "Stable Coin");
        assert_eq!(extra["version"], "1");
        assert!(exact_extra("eip155:723487", sbc).is_some());
        assert!(exact_extra("eip155:8453", sbc).is_none());
        let usdc: Address = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
            .parse()
            .unwrap();
        assert_eq!(exact_extra("eip155:84532", usdc).unwrap()["name"], "USDC");
        let usdc: Address = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
            .parse()
            .unwrap();
        assert_eq!(
            exact_extra("eip155:8453", usdc).unwrap()["name"],
            "USD Coin"
        );
    }
}
