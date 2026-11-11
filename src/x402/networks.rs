//! The networks a browser may be asked to pay on: what a wallet needs to add the chain, and a
//! public RPC the page reads balances from. The policy's catalog knows the networks; this is the
//! client-facing part of them.

use serde_json::{Value, json};

pub struct NetworkInfo {
    pub caip2: &'static str,
    pub chain_id: u64,
    pub name: &'static str,
    pub rpc: &'static str,
    pub explorer: &'static str,
    pub native_symbol: &'static str,
    pub faucet: Option<&'static str>,
    pub testnet: bool,
}

pub const KNOWN: &[NetworkInfo] = &[
    NetworkInfo {
        caip2: "eip155:72344",
        chain_id: 72344,
        name: "Radius Testnet",
        rpc: "https://rpc.testnet.radiustech.xyz",
        explorer: "https://testnet.radiustech.xyz",
        native_symbol: "RUSD",
        faucet: Some("https://testnet.radiustech.xyz/wallet"),
        testnet: true,
    },
    NetworkInfo {
        caip2: "eip155:723487",
        chain_id: 723487,
        name: "Radius",
        rpc: "https://rpc.radiustech.xyz",
        explorer: "https://network.radiustech.xyz",
        native_symbol: "RUSD",
        faucet: None,
        testnet: false,
    },
    NetworkInfo {
        caip2: "eip155:84532",
        chain_id: 84532,
        name: "Base Sepolia",
        rpc: "https://sepolia.base.org",
        explorer: "https://sepolia.basescan.org",
        native_symbol: "ETH",
        faucet: None,
        testnet: true,
    },
    NetworkInfo {
        caip2: "eip155:8453",
        chain_id: 8453,
        name: "Base",
        rpc: "https://mainnet.base.org",
        explorer: "https://basescan.org",
        native_symbol: "ETH",
        faucet: None,
        testnet: false,
    },
];

pub fn info(caip2: &str) -> Option<&'static NetworkInfo> {
    KNOWN.iter().find(|network| network.caip2 == caip2)
}

impl NetworkInfo {
    /// Whether this is Base or Base Sepolia, which radius-cli pays only when asked to.
    pub fn is_base(&self) -> bool {
        matches!(self.chain_id, 8453 | 84532)
    }

    /// What the page's script needs: the `wallet_addEthereumChain` parameters, the RPC to read
    /// balances from, and where to look up transactions.
    pub fn to_json(&self) -> Value {
        json!({
            "chainId": self.chain_id,
            "chainName": self.name,
            "rpcUrls": [self.rpc],
            "blockExplorerUrls": [self.explorer],
            "nativeCurrency": { "name": self.native_symbol, "symbol": self.native_symbol, "decimals": 18 },
            "faucet": self.faucet,
            "testnet": self.testnet,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn knows_radius_and_base() {
        assert_eq!(info("eip155:72344").unwrap().name, "Radius Testnet");
        assert!(info("eip155:84532").unwrap().is_base());
        assert!(!info("eip155:723487").unwrap().is_base());
        assert!(info("eip155:1").is_none());
        let json = info("eip155:8453").unwrap().to_json();
        assert_eq!(json["chainId"], 8453);
        assert_eq!(json["rpcUrls"][0], "https://mainnet.base.org");
    }
}
