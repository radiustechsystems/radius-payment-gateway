//! Prices in micro-units: millionths of one token (1 = 0.000001). Precision is fixed at six
//! decimal places because the stablecoins we accept use six; tokens with more decimals are scaled
//! up only when a price is converted to the token's atomic units ([`micros_to_atomic`]).

use std::fmt;
use std::str::FromStr;

use alloy_primitives::U256;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Decimal places a price may have.
pub const MICROS_DECIMALS: u8 = 6;
const MICROS_PER_UNIT: u64 = 1_000_000;

/// A positive price in micro-units. Prices are stored in Postgres `bigint`, so the largest
/// is `i64::MAX` micros.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Micros(u64);

/// Why a price didn't parse. `Display` is a message for the person who typed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MicrosError {
    Empty,
    Malformed,
    TooPrecise,
    Zero,
    TooLarge,
}

impl fmt::Display for MicrosError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "Enter a price",
            Self::Malformed => "Enter a number like 0.001",
            Self::TooPrecise => "Use at most 6 decimal places",
            Self::Zero => "Enter a price above 0",
            Self::TooLarge => "Enter a smaller price",
        })
    }
}

impl std::error::Error for MicrosError {}

impl Micros {
    /// The largest price: what fits in a Postgres `bigint`.
    pub const MAX: Self = Self(i64::MAX as u64);

    /// `micros` micro-units, if it's a valid price (above 0 and at most [`Self::MAX`]).
    pub fn new(micros: u64) -> Result<Self, MicrosError> {
        match micros {
            0 => Err(MicrosError::Zero),
            m if m > Self::MAX.0 => Err(MicrosError::TooLarge),
            m => Ok(Self(m)),
        }
    }

    /// Parses a decimal amount like `0.001`, `2` or `12.5`: digits, then optionally `.` and 1 to
    /// 6 more digits. Leading zeros are allowed. Signs, exponents, separators and a bare `.5` are
    /// not.
    pub fn parse(text: &str) -> Result<Self, MicrosError> {
        let text = text.trim();
        if text.is_empty() {
            return Err(MicrosError::Empty);
        }
        let (whole, fraction) = match text.split_once('.') {
            Some((whole, fraction)) => (whole, Some(fraction)),
            None => (text, None),
        };
        let is_digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        if !is_digits(whole) || fraction.is_some_and(|f| !is_digits(f)) {
            return Err(MicrosError::Malformed);
        }
        let fraction = fraction.unwrap_or("");
        if fraction.len() > usize::from(MICROS_DECIMALS) {
            return Err(MicrosError::TooPrecise);
        }

        let whole = whole.trim_start_matches('0');
        let whole: u64 = if whole.is_empty() {
            0
        } else {
            whole.parse().map_err(|_| MicrosError::TooLarge)?
        };
        // Pad to six digits: "5" is 500000 micros.
        let fraction: u64 = format!("{fraction:0<6}")
            .parse()
            .map_err(|_| MicrosError::Malformed)?;
        let micros = whole
            .checked_mul(MICROS_PER_UNIT)
            .and_then(|m| m.checked_add(fraction))
            .ok_or(MicrosError::TooLarge)?;
        Self::new(micros)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// The shortest decimal form: `0.001`, `2.5`, `12`.
impl fmt::Display for Micros {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (whole, fraction) = (self.0 / MICROS_PER_UNIT, self.0 % MICROS_PER_UNIT);
        if fraction == 0 {
            return write!(f, "{whole}");
        }
        let fraction = format!("{fraction:06}");
        write!(f, "{whole}.{}", fraction.trim_end_matches('0'))
    }
}

impl FromStr for Micros {
    type Err = MicrosError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

/// Serialized as the decimal string, e.g. `"0.001"`, so JSON never carries a float.
impl Serialize for Micros {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Micros {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// `micros` in the smallest unit of a token with `token_decimals` decimals: the same number at
/// 6 decimals, times 10^12 at 18. The catalog only lists tokens with at least 6 decimals.
///
/// # Panics
///
/// If `token_decimals` is below 6. Catalog entries are checked at compile time
/// (`catalog::ASSETS`), so this only happens with a token that isn't in the catalog.
pub fn micros_to_atomic(micros: Micros, token_decimals: u8) -> U256 {
    let extra = token_decimals
        .checked_sub(MICROS_DECIMALS)
        .unwrap_or_else(|| {
            panic!("token has {token_decimals} decimals; prices need at least {MICROS_DECIMALS}")
        });
    U256::from(micros.0) * U256::from(10u8).pow(U256::from(extra))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<u64, MicrosError> {
        Micros::parse(text).map(Micros::get)
    }

    #[test]
    fn parses_up_to_six_decimal_places() {
        assert_eq!(parse("0.001"), Ok(1_000));
        assert_eq!(parse("0.000001"), Ok(1));
        assert_eq!(parse("2"), Ok(2_000_000));
        assert_eq!(parse("2.5"), Ok(2_500_000));
        assert_eq!(parse(" 1.25 "), Ok(1_250_000));
        assert_eq!(parse("0.0000001"), Err(MicrosError::TooPrecise));
        assert_eq!(parse("1.1234567"), Err(MicrosError::TooPrecise));
    }

    #[test]
    fn allows_leading_zeros() {
        assert_eq!(parse("007.5"), Ok(7_500_000));
        assert_eq!(parse("00.001"), Ok(1_000));
    }

    #[test]
    fn rejects_zero_empty_negative_and_malformed() {
        assert_eq!(parse("0"), Err(MicrosError::Zero));
        assert_eq!(parse("0.000000"), Err(MicrosError::Zero));
        assert_eq!(parse(""), Err(MicrosError::Empty));
        assert_eq!(parse("   "), Err(MicrosError::Empty));
        assert_eq!(parse("-1"), Err(MicrosError::Malformed));
        assert_eq!(parse("+1"), Err(MicrosError::Malformed));
        assert_eq!(parse(".5"), Err(MicrosError::Malformed));
        assert_eq!(parse("5."), Err(MicrosError::Malformed));
        assert_eq!(parse("1e3"), Err(MicrosError::Malformed));
        assert_eq!(parse("1,000"), Err(MicrosError::Malformed));
        assert_eq!(parse("$1"), Err(MicrosError::Malformed));
        assert_eq!(parse("1.2.3"), Err(MicrosError::Malformed));
    }

    #[test]
    fn rejects_overflow() {
        // i64::MAX micros is 9223372036854.775807.
        assert_eq!(parse("9223372036854.775807"), Ok(i64::MAX as u64));
        assert_eq!(parse("9223372036854.775808"), Err(MicrosError::TooLarge));
        assert_eq!(parse("18446744073709551616"), Err(MicrosError::TooLarge));
        assert_eq!(parse("99999999999999999999.5"), Err(MicrosError::TooLarge));
    }

    #[test]
    fn displays_the_shortest_form() {
        for (micros, text) in [
            (1, "0.000001"),
            (1_000, "0.001"),
            (2_500_000, "2.5"),
            (12_000_000, "12"),
        ] {
            assert_eq!(Micros::new(micros).unwrap().to_string(), text);
            assert_eq!(Micros::parse(text).unwrap().get(), micros);
        }
    }

    #[test]
    fn serializes_as_a_decimal_string() {
        let price = Micros::parse("0.001").unwrap();
        assert_eq!(serde_json::to_string(&price).unwrap(), r#""0.001""#);
        assert_eq!(serde_json::from_str::<Micros>(r#""0.001""#).unwrap(), price);
        assert!(serde_json::from_str::<Micros>("0.001").is_err());
        assert!(serde_json::from_str::<Micros>(r#""0""#).is_err());
    }

    #[test]
    fn converts_to_atomic_units() {
        let price = Micros::parse("0.001").unwrap();
        assert_eq!(micros_to_atomic(price, 6), U256::from(1_000u64));
        assert_eq!(
            micros_to_atomic(price, 18),
            U256::from(1_000_000_000_000_000u64)
        );
        assert_eq!(
            micros_to_atomic(Micros::MAX, 18),
            U256::from(i64::MAX as u64) * U256::from(10u64).pow(U256::from(12u8))
        );
    }

    #[test]
    #[should_panic(expected = "prices need at least 6")]
    fn refuses_tokens_with_fewer_than_six_decimals() {
        micros_to_atomic(Micros::parse("1").unwrap(), 2);
    }
}
