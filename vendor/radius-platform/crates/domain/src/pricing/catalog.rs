//! Every payment option the platform offers: modes, networks, the assets on each network, and
//! schemes. Forms, validation and the policy all read this registry, so adding a network or a
//! token is a new entry here (plus an address validator if it brings a new address format), not a
//! migration or a new form component.
//!
//! Networks are identified by their CAIP-2 ID (`eip155:8453`) and assets by their contract address
//! on that network (or its symbol there, in policies).

use std::fmt;

use alloy_chains::{Chain, NamedChain};
use alloy_primitives::{Address, ChainId, address};
use serde::{Deserialize, Serialize};

/// Whether a payment option can be chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Available,
    /// Listed so the UI can show what's next, but not selectable.
    ComingSoon,
}

/// Test settings pay with testnet tokens; production settings move real money.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Test,
    Production,
}

impl Mode {
    pub const ALL: [Mode; 2] = [Mode::Test, Mode::Production];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Test => "test",
            Self::Production => "production",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|mode| mode.as_str() == text)
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Test => "Test",
            Self::Production => "Production",
        }
    }

    /// The mode a project switches to from this one.
    pub const fn other(self) -> Self {
        match self {
            Self::Test => Self::Production,
            Self::Production => Self::Test,
        }
    }
}

/// How a payer proves payment. x402 is the only one today; MPP comes later.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    X402,
}

/// The x402 payment scheme. `exact` charges the listed price; `upto` comes later.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scheme {
    Exact,
}

impl Scheme {
    pub const ALL: [Scheme; 1] = [Scheme::Exact];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|scheme| scheme.as_str() == text)
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Exact => "Exact amount",
        }
    }

    pub const fn status(self) -> Status {
        match self {
            Self::Exact => Status::Available,
        }
    }
}

/// How prices are set. `flat` is one price per call; per-parameter and `upto` come later.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PriceModelKind {
    Flat,
}

impl PriceModelKind {
    pub const ALL: [PriceModelKind; 1] = [PriceModelKind::Flat];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Flat => "flat",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Flat => "Price per call",
        }
    }

    pub const fn status(self) -> Status {
        match self {
            Self::Flat => Status::Available,
        }
    }
}

/// The address format a network uses. A wallet registered for one family works on every network
/// of that family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressFamily {
    /// 20-byte hex addresses, EIP-55 checksummed.
    Evm,
}

impl AddressFamily {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Evm => "evm",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        (text == "evm").then_some(Self::Evm)
    }
}

/// How a token is moved on the payer's behalf once they sign. The gate and facilitator need it
/// to build and settle the payment; nothing in the MVP signs yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TransferMethod {
    /// EIP-3009 `transferWithAuthorization`.
    Eip3009,
    /// ERC-2612 `permit`, signed against the token's EIP-712 domain.
    Erc2612Permit {
        eip712_name: &'static str,
        eip712_version: &'static str,
    },
}

/// A chain payments settle on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Network {
    pub chain: Chain,
    pub label: &'static str,
    pub mode: Mode,
    pub address_family: AddressFamily,
    pub status: Status,
    /// The facilitator that verifies and settles payments on this network by default (the same
    /// defaults radius-sdk 0.6 uses). None where there is no default, like Base: sellers name
    /// their own.
    pub facilitator: Option<&'static str>,
    /// The same network in the other mode (Radius testnet for Radius), where a project's accepted
    /// tokens move when it switches modes. Every network has one, so the two modes offer the
    /// same networks, and each network's tokens are the same on both; keep it that way when
    /// adding a network or a token.
    pub counterpart: Chain,
}

impl Network {
    pub fn chain_id(&self) -> ChainId {
        self.chain.id()
    }

    /// The same network in the other mode.
    pub fn counterpart(&self) -> &'static Network {
        NETWORKS
            .iter()
            .find(|network| network.chain == self.counterpart)
            .expect("every network's counterpart is in the catalog")
    }

    /// The CAIP-2 ID, e.g. `eip155:8453`, which identifies the network everywhere outside Rust.
    pub fn caip2(&self) -> String {
        caip2(self.chain)
    }

    /// The assets that can be paid with on this network.
    pub fn assets(&self) -> impl Iterator<Item = &'static Asset> + '_ {
        ASSETS.iter().filter(move |asset| asset.chain == self.chain)
    }
}

/// A token on one network. The same symbol can differ between networks (SBC has 18 decimals on
/// Base but 6 on Base Sepolia and Radius), so decimals always come from this entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Asset {
    pub chain: Chain,
    pub symbol: &'static str,
    pub label: &'static str,
    pub address: Address,
    pub decimals: u8,
    pub transfer_method: TransferMethod,
    pub schemes: &'static [Scheme],
    pub status: Status,
}

/// `eip155:<chain id>`: the CAIP-2 ID of an EVM chain.
pub fn caip2(chain: Chain) -> String {
    format!("eip155:{}", chain.id())
}

pub const RADIUS_TESTNET: Chain = Chain::from_named(NamedChain::RadiusTestnet);
pub const RADIUS: Chain = Chain::from_named(NamedChain::Radius);
pub const BASE_SEPOLIA: Chain = Chain::from_named(NamedChain::BaseSepolia);
pub const BASE: Chain = Chain::from_named(NamedChain::Base);

const EXACT: &[Scheme] = &[Scheme::Exact];
/// EIP-712 domain of SBC on Base and Base Sepolia, per the Stable Coin Inc. facilitator docs.
const SBC_PERMIT: TransferMethod = TransferMethod::Erc2612Permit {
    eip712_name: "Stable Coin",
    eip712_version: "1",
};

/// Every network, test networks first. Each network belongs to exactly one mode and has its
/// counterpart in the other.
pub const NETWORKS: &[Network] = &[
    Network {
        chain: RADIUS_TESTNET,
        label: "Radius testnet",
        mode: Mode::Test,
        address_family: AddressFamily::Evm,
        status: Status::Available,
        facilitator: Some("https://facilitator.testnet.radiustech.xyz"),
        counterpart: RADIUS,
    },
    Network {
        chain: BASE_SEPOLIA,
        label: "Base Sepolia",
        mode: Mode::Test,
        address_family: AddressFamily::Evm,
        status: Status::Available,
        facilitator: Some("https://x402.org/facilitator"),
        counterpart: BASE,
    },
    Network {
        chain: RADIUS,
        label: "Radius",
        mode: Mode::Production,
        address_family: AddressFamily::Evm,
        status: Status::Available,
        facilitator: Some("https://facilitator.radiustech.xyz"),
        counterpart: RADIUS_TESTNET,
    },
    Network {
        chain: BASE,
        label: "Base",
        mode: Mode::Production,
        address_family: AddressFamily::Evm,
        status: Status::Available,
        facilitator: None,
        counterpart: BASE_SEPOLIA,
    },
];

/// Every asset. Addresses and decimals come from the Stable Coin Inc. x402 facilitator docs and
/// SBC token list, and Circle's USDC addresses; `tests/onchain_catalog.rs` checks them on-chain.
pub const ASSETS: &[Asset] = &[
    Asset {
        chain: RADIUS_TESTNET,
        symbol: "SBC",
        label: "Stable Coin (SBC)",
        address: address!("0x33ad9e4BD16B69B5BFdED37D8B5D9fF9aba014Fb"),
        decimals: 6,
        transfer_method: TransferMethod::Eip3009,
        schemes: EXACT,
        status: Status::Available,
    },
    Asset {
        chain: BASE_SEPOLIA,
        symbol: "USDC",
        label: "USD Coin (USDC)",
        address: address!("0x036CbD53842c5426634e7929541eC2318f3dCF7e"),
        decimals: 6,
        transfer_method: TransferMethod::Eip3009,
        schemes: EXACT,
        status: Status::Available,
    },
    Asset {
        chain: BASE_SEPOLIA,
        symbol: "SBC",
        label: "Stable Coin (SBC)",
        address: address!("0xf9FB20B8E097904f0aB7d12e9DbeE88f2dcd0F16"),
        decimals: 6,
        transfer_method: SBC_PERMIT,
        schemes: EXACT,
        status: Status::Available,
    },
    Asset {
        chain: RADIUS,
        symbol: "SBC",
        label: "Stable Coin (SBC)",
        address: address!("0x33ad9e4BD16B69B5BFdED37D8B5D9fF9aba014Fb"),
        decimals: 6,
        transfer_method: TransferMethod::Eip3009,
        schemes: EXACT,
        status: Status::Available,
    },
    Asset {
        chain: BASE,
        symbol: "USDC",
        label: "USD Coin (USDC)",
        address: address!("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
        decimals: 6,
        transfer_method: TransferMethod::Eip3009,
        schemes: EXACT,
        status: Status::Available,
    },
    Asset {
        chain: BASE,
        symbol: "SBC",
        label: "Stable Coin (SBC)",
        address: address!("0xfdcC3dd6671eaB0709A4C0f3F53De9a333d80798"),
        // 18, unlike SBC on every other network.
        decimals: 18,
        transfer_method: SBC_PERMIT,
        schemes: EXACT,
        status: Status::Available,
    },
];

// Prices have six decimal places, so every token needs at least six (see `micros_to_atomic`).
const _: () = {
    let mut i = 0;
    while i < ASSETS.len() {
        assert!(
            ASSETS[i].decimals >= 6,
            "catalog assets need at least 6 decimals"
        );
        i += 1;
    }
};

/// The network with this CAIP-2 ID.
pub fn network(caip2_id: &str) -> Option<&'static Network> {
    NETWORKS.iter().find(|network| network.caip2() == caip2_id)
}

/// The asset at `address` on `network`.
pub fn asset(network: &Network, address: Address) -> Option<&'static Asset> {
    network.assets().find(|asset| asset.address == address)
}

/// The networks of a mode, in catalog order.
pub fn networks(mode: Mode) -> impl Iterator<Item = &'static Network> {
    NETWORKS.iter().filter(move |network| network.mode == mode)
}

/// The settings a new project starts with, and that a mode switch falls back to: the first
/// available network of the mode and its first available asset and scheme.
pub fn default_for(mode: Mode) -> (&'static Network, &'static Asset, Scheme) {
    let network = networks(mode)
        .find(|network| network.status == Status::Available)
        .expect("every mode has an available network");
    let asset = network
        .assets()
        .find(|asset| asset.status == Status::Available)
        .expect("every available network has an available asset");
    let scheme = asset.schemes[0];
    (network, asset, scheme)
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_caip2_ids_from_chain_ids() {
        assert_eq!(caip2(RADIUS_TESTNET), "eip155:72344");
        assert_eq!(caip2(RADIUS), "eip155:723487");
        assert_eq!(caip2(BASE_SEPOLIA), "eip155:84532");
        assert_eq!(caip2(BASE), "eip155:8453");
    }

    #[test]
    fn chains_have_the_documented_ids() {
        assert_eq!(RADIUS_TESTNET.id(), 72344);
        assert_eq!(RADIUS.id(), 723487);
        assert_eq!(BASE_SEPOLIA.id(), 84532);
        assert_eq!(BASE.id(), 8453);
        // Named chains compare equal to the same ID looked up at runtime.
        assert_eq!(RADIUS, Chain::from_id(723487));
    }

    #[test]
    fn lists_the_mvp_options_by_mode() {
        let labels = |mode| networks(mode).map(|n| n.label).collect::<Vec<_>>();
        assert_eq!(labels(Mode::Test), ["Radius testnet", "Base Sepolia"]);
        assert_eq!(labels(Mode::Production), ["Radius", "Base"]);

        let symbols = |chain: Chain| {
            NETWORKS
                .iter()
                .find(|n| n.chain == chain)
                .unwrap()
                .assets()
                .map(|a| a.symbol)
                .collect::<Vec<_>>()
        };
        assert_eq!(symbols(RADIUS_TESTNET), ["SBC"]);
        assert_eq!(symbols(BASE_SEPOLIA), ["USDC", "SBC"]);
        assert_eq!(symbols(RADIUS), ["SBC"]);
        assert_eq!(symbols(BASE), ["USDC", "SBC"]);
        assert!(NETWORKS.iter().all(|n| n.status == Status::Available));
        assert!(ASSETS.iter().all(|a| a.status == Status::Available));
    }

    #[test]
    fn each_network_has_its_counterpart_in_the_other_mode_with_the_same_tokens() {
        for network in NETWORKS {
            let counterpart = network.counterpart();
            assert_eq!(counterpart.mode, network.mode.other(), "{}", network.label);
            assert_eq!(
                counterpart.counterpart().chain,
                network.chain,
                "{}",
                network.label
            );
            assert_eq!(counterpart.address_family, network.address_family);
            let symbols =
                |network: &Network| network.assets().map(|a| a.symbol).collect::<Vec<_>>();
            assert_eq!(symbols(counterpart), symbols(network), "{}", network.label);
        }
        assert_eq!(Mode::Test.other(), Mode::Production);
        assert_eq!(Mode::Production.other(), Mode::Test);
    }

    #[test]
    fn every_asset_is_on_a_listed_network() {
        for asset in ASSETS {
            assert!(
                NETWORKS.iter().any(|n| n.chain == asset.chain),
                "{}",
                asset.label
            );
            assert!(!asset.schemes.is_empty());
        }
    }

    #[test]
    fn sbc_decimals_depend_on_the_network() {
        let sbc = |chain| {
            ASSETS
                .iter()
                .find(|a| a.chain == chain && a.symbol == "SBC")
                .unwrap()
        };
        assert_eq!(sbc(BASE).decimals, 18);
        assert_eq!(sbc(BASE_SEPOLIA).decimals, 6);
        assert_eq!(sbc(RADIUS).decimals, 6);
        assert!(matches!(
            sbc(BASE).transfer_method,
            TransferMethod::Erc2612Permit {
                eip712_name: "Stable Coin",
                ..
            }
        ));
    }

    #[test]
    fn looks_up_networks_and_assets_by_id() {
        let base = network("eip155:8453").unwrap();
        assert_eq!(base.label, "Base");
        assert!(network("eip155:1").is_none());
        let usdc = asset(base, address!("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")).unwrap();
        assert_eq!(usdc.symbol, "USDC");
        // Radius SBC's address isn't an asset on Base.
        assert!(asset(base, address!("0x33ad9e4BD16B69B5BFdED37D8B5D9fF9aba014Fb")).is_none());
    }

    #[test]
    fn defaults_to_the_first_available_entries() {
        let (network, asset, scheme) = default_for(Mode::Test);
        assert_eq!(
            (network.label, asset.symbol, scheme),
            ("Radius testnet", "SBC", Scheme::Exact)
        );
        let (network, asset, _) = default_for(Mode::Production);
        assert_eq!((network.label, asset.symbol), ("Radius", "SBC"));
    }

    #[test]
    fn networks_name_their_default_facilitator() {
        let facilitators: Vec<_> = NETWORKS.iter().map(|n| (n.label, n.facilitator)).collect();
        assert_eq!(
            facilitators,
            [
                (
                    "Radius testnet",
                    Some("https://facilitator.testnet.radiustech.xyz")
                ),
                ("Base Sepolia", Some("https://x402.org/facilitator")),
                ("Radius", Some("https://facilitator.radiustech.xyz")),
                ("Base", None),
            ]
        );
    }
}
