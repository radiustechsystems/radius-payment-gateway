//! What payers may pay with: payment options, each a network, an asset on it and a scheme, all
//! from the [catalog](crate::pricing::catalog). A 402 challenge offers every accepted option and
//! the payer picks one, as x402's `accepts` list allows.
//!
//! A project's mode decides which networks its options may use, so a project never mixes test
//! and real money.

use std::collections::BTreeSet;
use std::str::FromStr;

use alloy_primitives::Address;

use crate::pricing::catalog::{self, AddressFamily, Asset, Mode, Network, Scheme, Status};
use crate::validation::FieldErrors;

/// One way to pay: an asset on a network, with a scheme.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaymentOption {
    pub network: &'static Network,
    pub asset: &'static Asset,
    pub scheme: Scheme,
}

/// A payment option as sent by a client. `scheme` defaults to `exact`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PaymentOptionDraft {
    /// CAIP-2 ID, e.g. `eip155:84532`.
    pub network: String,
    /// The asset's symbol on `network` (`SBC`), or its contract address.
    pub asset: String,
    pub scheme: Option<String>,
}

impl PaymentOption {
    /// The first available asset and scheme of a mode's first available network: what a project
    /// accepts until it chooses.
    pub fn default_for(mode: Mode) -> Self {
        let (network, asset, scheme) = catalog::default_for(mode);
        Self {
            network,
            asset,
            scheme,
        }
    }

    /// Whether a wallet of `family` can receive payments made with this option.
    pub fn pays_to(&self, family: AddressFamily) -> bool {
        self.network.address_family == family
    }
}

/// Problems with `options` that would stop payers from using them: an option that's no longer
/// available, or a scheme the asset doesn't support. Keys are `<prefix>[i].<field>`.
pub fn check_usable(options: &[PaymentOption], prefix: &str) -> FieldErrors {
    let mut errors = FieldErrors::new();
    for (index, option) in options.iter().enumerate() {
        let field = |name: &str| format!("{prefix}[{index}].{name}");
        if option.network.status != Status::Available {
            errors.add(
                field("network"),
                format!("{} isn't available yet", option.network.label),
            );
        }
        if option.asset.status != Status::Available {
            errors.add(
                field("asset"),
                format!("{} isn't available yet", option.asset.label),
            );
        }
        if !option.asset.schemes.contains(&option.scheme) {
            errors.add(
                field("scheme"),
                format!(
                    "{} doesn't support the {} scheme",
                    option.asset.symbol,
                    option.scheme.as_str()
                ),
            );
        } else if option.scheme.status() != Status::Available {
            errors.add(
                field("scheme"),
                format!("The {} scheme isn't available yet", option.scheme.as_str()),
            );
        }
    }
    errors
}

/// The catalog asset `text` names on `network`: its symbol, or its contract address.
pub fn asset_named(network: &Network, text: &str) -> Option<&'static Asset> {
    match Address::from_str(text) {
        Ok(address) => catalog::asset(network, address),
        Err(_) => network.assets().find(|asset| asset.symbol == text),
    }
}

/// What `option` becomes when its project switches to `mode`: the same token on its network's
/// counterpart in `mode` (SBC on Radius testnet becomes SBC on Radius), or, when that network
/// can't take it yet, `mode`'s default and the reason. An option already of `mode` stays as it is.
pub fn switch_option(option: &PaymentOption, mode: Mode) -> (PaymentOption, Option<String>) {
    if option.network.mode == mode {
        return (*option, None);
    }
    let network = option.network.counterpart();
    debug_assert_eq!(network.mode, mode);
    let reason = if network.facilitator.is_none() {
        format!("Payments on {} can't be settled yet", network.label)
    } else if network.status != Status::Available {
        format!("{} isn't available yet", network.label)
    } else {
        match network
            .assets()
            .find(|asset| asset.symbol == option.asset.symbol)
        {
            None => format!("{} isn't on {}", option.asset.symbol, network.label),
            Some(asset) if asset.status != Status::Available => {
                format!("{} isn't available on {} yet", asset.label, network.label)
            }
            Some(asset) if !asset.schemes.contains(&option.scheme) => format!(
                "{} on {} doesn't support the {} scheme",
                asset.symbol,
                network.label,
                option.scheme.as_str()
            ),
            Some(asset) => {
                return (
                    PaymentOption {
                        network,
                        asset,
                        scheme: option.scheme,
                    },
                    None,
                );
            }
        }
    };
    (PaymentOption::default_for(mode), Some(reason))
}

/// Checks a list of payment options against the catalog for `mode`: at least one, each network of
/// the mode, each asset on its network, each scheme supported by its asset, every option
/// available, and no option twice. Errors are keyed `<prefix>` (for the list) and
/// `<prefix>[i].network`, `.asset` or `.scheme`.
pub fn validate_accepts(
    mode: Mode,
    drafts: &[PaymentOptionDraft],
    prefix: &str,
) -> Result<Vec<PaymentOption>, FieldErrors> {
    let mut errors = FieldErrors::new();
    if drafts.is_empty() {
        errors.add(prefix, "Choose at least one network and token");
        return Err(errors);
    }
    let mut options = Vec::with_capacity(drafts.len());
    let mut seen = BTreeSet::new();
    for (index, draft) in drafts.iter().enumerate() {
        let field = |name: &str| format!("{prefix}[{index}].{name}");
        let Some(network) = catalog::network(draft.network.trim()) else {
            errors.add(field("network"), "Choose a network from the list");
            continue;
        };
        if network.mode != mode {
            errors.add(
                field("network"),
                format!(
                    "{} is a {} network. Choose a {} network",
                    network.label, network.mode, mode
                ),
            );
            continue;
        }
        let Some(asset) = asset_named(network, draft.asset.trim()) else {
            errors.add(
                field("asset"),
                format!("Choose an asset available on {}", network.label),
            );
            continue;
        };
        let scheme = match draft.scheme.as_deref().map(str::trim) {
            None | Some("") => Scheme::Exact,
            Some(text) => match Scheme::parse(text) {
                Some(scheme) => scheme,
                None => {
                    errors.add(
                        field("scheme"),
                        format!("Unknown scheme {text:?}. Use exact"),
                    );
                    continue;
                }
            },
        };
        if !seen.insert((network.caip2(), asset.address)) {
            errors.add(
                field("asset"),
                format!("{} on {} is listed twice", asset.symbol, network.label),
            );
            continue;
        }
        options.push(PaymentOption {
            network,
            asset,
            scheme,
        });
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    check_usable(&options, prefix).into_result(|| options)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE_USDC: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
    const BASE_SBC: &str = "0xfdcC3dd6671eaB0709A4C0f3F53De9a333d80798";
    const BASE_SEPOLIA_USDC: &str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";

    fn option(network: &str, asset: &str) -> PaymentOptionDraft {
        PaymentOptionDraft {
            network: network.to_owned(),
            asset: asset.to_owned(),
            scheme: None,
        }
    }

    #[test]
    fn accepts_several_networks_and_tokens_of_the_mode_by_symbol_or_address() {
        let valid = validate_accepts(
            Mode::Production,
            &[
                option("eip155:723487", "SBC"),
                option("eip155:8453", BASE_USDC),
                option("eip155:8453", &BASE_SBC.to_lowercase()),
            ],
            "accepts",
        )
        .unwrap();
        let labels: Vec<_> = valid
            .iter()
            .map(|o| (o.network.label, o.asset.symbol, o.asset.decimals))
            .collect();
        assert_eq!(
            labels,
            [
                ("Radius", "SBC", 6),
                ("Base", "USDC", 6),
                ("Base", "SBC", 18)
            ]
        );
        assert!(valid.iter().all(|o| o.scheme == Scheme::Exact));
        assert!(valid.iter().all(|o| o.pays_to(AddressFamily::Evm)));
    }

    #[test]
    fn needs_at_least_one_option() {
        let errors = validate_accepts(Mode::Test, &[], "accepts").unwrap_err();
        assert_eq!(
            errors.get("accepts"),
            Some("Choose at least one network and token")
        );
    }

    #[test]
    fn rejects_a_network_from_the_other_mode() {
        let errors = validate_accepts(
            Mode::Test,
            &[option("eip155:72344", "SBC"), option("eip155:8453", "USDC")],
            "accepts",
        )
        .unwrap_err();
        assert_eq!(
            errors.get("accepts[1].network"),
            Some("Base is a production network. Choose a test network")
        );
    }

    #[test]
    fn rejects_an_asset_that_isnt_on_the_network() {
        for asset in [BASE_SEPOLIA_USDC, "DAI", "usdc"] {
            let errors =
                validate_accepts(Mode::Production, &[option("eip155:8453", asset)], "accepts")
                    .unwrap_err();
            assert_eq!(
                errors.get("accepts[0].asset"),
                Some("Choose an asset available on Base"),
                "{asset}"
            );
        }
    }

    #[test]
    fn rejects_duplicates_unknown_networks_and_schemes() {
        let errors = validate_accepts(
            Mode::Production,
            &[
                option("eip155:8453", BASE_USDC),
                option("eip155:8453", "USDC"),
            ],
            "accepts",
        )
        .unwrap_err();
        assert_eq!(
            errors.get("accepts[1].asset"),
            Some("USDC on Base is listed twice")
        );
        let errors =
            validate_accepts(Mode::Production, &[option("eip155:1", "USDC")], "a").unwrap_err();
        assert_eq!(
            errors.get("a[0].network"),
            Some("Choose a network from the list")
        );
        let mut upto = option("eip155:8453", "USDC");
        upto.scheme = Some("upto".to_owned());
        let errors = validate_accepts(Mode::Production, &[upto], "a").unwrap_err();
        assert_eq!(
            errors.get("a[0].scheme"),
            Some("Unknown scheme \"upto\". Use exact")
        );
    }

    #[test]
    fn a_switch_moves_an_option_to_its_counterpart_network_or_the_default() {
        let resolve = |network, asset| {
            validate_accepts(
                catalog::network(network).unwrap().mode,
                &[option(network, asset)],
                "accepts",
            )
            .unwrap()[0]
        };
        let labels = |option: &PaymentOption| (option.network.label, option.asset.symbol);

        // The same token on the counterpart, both ways.
        let (live, reason) = switch_option(&resolve("eip155:72344", "SBC"), Mode::Production);
        assert_eq!((labels(&live), reason), (("Radius", "SBC"), None));
        let (test, reason) = switch_option(&resolve("eip155:723487", "SBC"), Mode::Test);
        assert_eq!((labels(&test), reason), (("Radius testnet", "SBC"), None));
        // Already of the mode: nothing changes.
        let (same, reason) = switch_option(&resolve("eip155:723487", "SBC"), Mode::Production);
        assert_eq!((labels(&same), reason), (("Radius", "SBC"), None));

        // Base can't settle payments yet, so Base Sepolia's tokens fall back to the default.
        let (live, reason) = switch_option(&resolve("eip155:84532", "USDC"), Mode::Production);
        assert_eq!(labels(&live), ("Radius", "SBC"));
        assert_eq!(
            reason.as_deref(),
            Some("Payments on Base can't be settled yet")
        );

        // A token the counterpart lacks falls back too.
        static ONLY_HERE: Asset = Asset {
            symbol: "ONLY",
            ..catalog::ASSETS[0]
        };
        let mut only = resolve("eip155:72344", "SBC");
        only.asset = &ONLY_HERE;
        let (live, reason) = switch_option(&only, Mode::Production);
        assert_eq!(labels(&live), ("Radius", "SBC"));
        assert_eq!(reason.as_deref(), Some("ONLY isn't on Radius"));
    }

    #[test]
    fn rejects_options_that_are_coming_soon_or_unsupported() {
        static SOON: Network = Network {
            status: Status::ComingSoon,
            ..catalog::NETWORKS[3]
        };
        let mut options = [PaymentOption::default_for(Mode::Production)];
        options[0].network = &SOON;
        assert_eq!(
            check_usable(&options, "accepts").get("accepts[0].network"),
            Some("Base isn't available yet")
        );

        static SOON_ASSET: Asset = Asset {
            status: Status::ComingSoon,
            ..catalog::ASSETS[0]
        };
        let mut options = [PaymentOption::default_for(Mode::Test)];
        options[0].asset = &SOON_ASSET;
        assert_eq!(
            check_usable(&options, "accepts").get("accepts[0].asset"),
            Some("Stable Coin (SBC) isn't available yet")
        );

        static NO_SCHEMES: Asset = Asset {
            schemes: &[],
            ..catalog::ASSETS[0]
        };
        options[0].asset = &NO_SCHEMES;
        assert_eq!(
            check_usable(&options, "accepts").get("accepts[0].scheme"),
            Some("SBC doesn't support the exact scheme")
        );
    }
}
