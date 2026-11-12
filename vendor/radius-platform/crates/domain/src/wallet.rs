//! Wallets: the addresses an organization's payments settle to.
//!
//! Endpoints and the policy only ever see a wallet's ID and address. Where the wallet came from is
//! its [`WalletKind`]: today only addresses the customer registers ([`WalletKind::External`]);
//! later, wallets a provider manages for them, without changing how endpoints point at wallets.

use std::str::FromStr;

use alloy_primitives::Address;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::pricing::catalog::AddressFamily;
use crate::validation::FieldErrors;

/// Where a wallet comes from, tagged by `type`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WalletKind {
    /// A wallet the customer controls and registered by address.
    External,
}

impl WalletKind {
    /// The `wallets.kind` column.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::External => "external",
        }
    }

    /// From the `wallets.kind`, `provider` and `provider_ref` columns.
    pub fn from_columns(
        kind: &str,
        _provider: Option<&str>,
        _provider_ref: Option<&str>,
    ) -> Option<Self> {
        (kind == "external").then_some(Self::External)
    }
}

/// A registered wallet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wallet {
    pub id: Uuid,
    pub kind: WalletKind,
    pub address_family: AddressFamily,
    /// Fixed once registered: a different address is a new wallet.
    pub address: Address,
    pub name: String,
    pub description: Option<String>,
}

/// Parses an EVM address the way people paste them: `0x` and 40 hex digits. All-lowercase or
/// all-uppercase input carries no checksum; mixed case must be a valid EIP-55 checksum, so a typo
/// in a checksummed address is caught. The zero address is refused: payments sent there are lost.
pub fn parse_evm_address(text: &str) -> Result<Address, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("Enter an address".to_owned());
    }
    let digits = text
        .strip_prefix("0x")
        .ok_or_else(|| "Start the address with 0x".to_owned())?;
    let address = Address::from_str(text)
        .map_err(|_| "Enter 0x followed by 40 hexadecimal characters".to_owned())?;
    let has_lower = digits.bytes().any(|b| b.is_ascii_lowercase());
    let has_upper = digits.bytes().any(|b| b.is_ascii_uppercase());
    if has_lower && has_upper && Address::parse_checksummed(text, None).is_err() {
        return Err("Check the address: its capitalization doesn't match its checksum".to_owned());
    }
    if address.is_zero() {
        return Err("Enter an address other than the zero address".to_owned());
    }
    Ok(address)
}

/// The EIP-55 form used for storage and display, e.g. `0x33ad9e4BD16B69B5BFdED37D8B5D9fF9aba014Fb`.
pub fn checksummed(address: &Address) -> String {
    address.to_checksum(None)
}

/// Serde for [`Address`] in its EIP-55 checksummed form. Alloy's own serde writes lowercase hex;
/// stored and displayed addresses should match what people see in wallets and explorers.
pub mod checksummed_serde {
    use alloy_primitives::Address;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(address: &Address, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&address.to_checksum(None))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Address, D::Error> {
        Address::deserialize(deserializer)
    }
}

pub const MAX_WALLET_NAME_CHARS: usize = 100;
pub const MAX_WALLET_DESCRIPTION_CHARS: usize = 500;

/// Name and description of a wallet being registered or renamed.
pub fn validate_wallet_name(name: &str) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("Enter a name".to_owned());
    }
    if name.chars().count() > MAX_WALLET_NAME_CHARS {
        return Err(format!("Use at most {MAX_WALLET_NAME_CHARS} characters"));
    }
    Ok(name.to_owned())
}

/// Trimmed; empty is no description.
pub fn validate_wallet_description(description: Option<&str>) -> Result<Option<String>, String> {
    let description = description.map(str::trim).filter(|d| !d.is_empty());
    match description {
        Some(d) if d.chars().count() > MAX_WALLET_DESCRIPTION_CHARS => Err(format!(
            "Use at most {MAX_WALLET_DESCRIPTION_CHARS} characters"
        )),
        other => Ok(other.map(str::to_owned)),
    }
}

/// A wallet to register, as typed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WalletDraft {
    pub address: String,
    pub name: String,
    pub description: Option<String>,
}

/// A wallet ready to insert.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewWallet {
    pub kind: WalletKind,
    pub address_family: AddressFamily,
    pub address: Address,
    pub name: String,
    pub description: Option<String>,
}

/// Checks a wallet to register. `address_taken` says whether the organization already has a
/// wallet at the parsed address (addresses are unique per organization).
pub fn validate_new_wallet(
    draft: &WalletDraft,
    address_taken: impl FnOnce(&Address) -> bool,
) -> Result<NewWallet, FieldErrors> {
    let mut errors = FieldErrors::new();
    let address = errors.check("address", parse_evm_address(&draft.address));
    if let Some(address) = address
        && address_taken(&address)
    {
        errors.add(
            "address",
            "This address is already registered as a wallet. Choose it instead",
        );
    }
    let name = errors.check("name", validate_wallet_name(&draft.name));
    let description = errors.check(
        "description",
        validate_wallet_description(draft.description.as_deref()),
    );
    match (address, name, description) {
        (Some(address), Some(name), Some(description)) if errors.is_empty() => Ok(NewWallet {
            kind: WalletKind::External,
            address_family: AddressFamily::Evm,
            address,
            name,
            description,
        }),
        _ => Err(errors),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHECKSUMMED: &str = "0x33ad9e4BD16B69B5BFdED37D8B5D9fF9aba014Fb";

    #[test]
    fn accepts_lowercase_uppercase_and_valid_checksums() {
        let address = parse_evm_address(CHECKSUMMED).unwrap();
        assert_eq!(
            parse_evm_address(&CHECKSUMMED.to_lowercase()).unwrap(),
            address
        );
        let upper = format!("0x{}", CHECKSUMMED[2..].to_uppercase());
        assert_eq!(parse_evm_address(&upper).unwrap(), address);
        assert_eq!(
            parse_evm_address(&format!("  {CHECKSUMMED} ")).unwrap(),
            address
        );
        assert_eq!(checksummed(&address), CHECKSUMMED);
    }

    #[test]
    fn rejects_an_invalid_checksum() {
        // One letter's case flipped.
        let bad = CHECKSUMMED.replace("BD16", "bD16");
        assert_eq!(
            parse_evm_address(&bad).unwrap_err(),
            "Check the address: its capitalization doesn't match its checksum"
        );
    }

    #[test]
    fn rejects_the_zero_address_and_wrong_lengths() {
        assert_eq!(
            parse_evm_address(&format!("0x{}", "0".repeat(40))).unwrap_err(),
            "Enter an address other than the zero address"
        );
        for text in [
            "0x1234",
            &format!("{CHECKSUMMED}00"),
            "0xZZad9e4BD16B69B5BFdED37D8B5D9fF9aba014Fb",
        ] {
            assert_eq!(
                parse_evm_address(text).unwrap_err(),
                "Enter 0x followed by 40 hexadecimal characters",
                "{text}"
            );
        }
        assert_eq!(
            parse_evm_address(&CHECKSUMMED[2..]).unwrap_err(),
            "Start the address with 0x"
        );
        assert_eq!(parse_evm_address("").unwrap_err(), "Enter an address");
    }

    #[test]
    fn serializes_checksummed() {
        #[derive(Serialize, Deserialize)]
        struct Holder(#[serde(with = "checksummed_serde")] Address);
        let address = parse_evm_address(CHECKSUMMED).unwrap();
        let json = serde_json::to_string(&Holder(address)).unwrap();
        assert_eq!(json, format!("\"{CHECKSUMMED}\""));
        assert_eq!(serde_json::from_str::<Holder>(&json).unwrap().0, address);
    }

    #[test]
    fn validates_a_new_wallet() {
        let draft = WalletDraft {
            address: CHECKSUMMED.to_lowercase(),
            name: " Treasury ".to_owned(),
            description: Some("  ".to_owned()),
        };
        let wallet = validate_new_wallet(&draft, |_| false).unwrap();
        assert_eq!(checksummed(&wallet.address), CHECKSUMMED);
        assert_eq!(wallet.name, "Treasury");
        assert_eq!(wallet.description, None);
        assert_eq!(wallet.kind, WalletKind::External);

        let errors = validate_new_wallet(&draft, |_| true).unwrap_err();
        assert_eq!(
            errors.get("address"),
            Some("This address is already registered as a wallet. Choose it instead")
        );

        let empty = validate_new_wallet(&WalletDraft::default(), |_| false).unwrap_err();
        assert_eq!(empty.get("address"), Some("Enter an address"));
        assert_eq!(empty.get("name"), Some("Enter a name"));
    }

    #[test]
    fn kinds_round_trip_through_columns() {
        assert_eq!(
            WalletKind::from_columns(WalletKind::External.as_str(), None, None),
            Some(WalletKind::External)
        );
        assert_eq!(
            WalletKind::from_columns("managed", Some("brale"), Some("w_1")),
            None
        );
        assert_eq!(
            serde_json::to_string(&WalletKind::External).unwrap(),
            r#"{"type":"external"}"#
        );
    }
}
