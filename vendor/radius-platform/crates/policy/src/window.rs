//! Limit windows: a whole number and a unit, like `30s`, `5m`, `1h` or `1d`.

/// The longest window: 30 days.
pub const MAX_SECONDS: u64 = 30 * 86_400;

const UNITS: [(char, u64); 4] = [('s', 1), ('m', 60), ('h', 3_600), ('d', 86_400)];

/// The window's length in seconds, from 1s to 30d.
pub fn parse(text: &str) -> Result<u64, String> {
    let text = text.trim();
    let invalid =
        || format!("{text:?} isn't a window. Use a whole number and s, m, h or d, like 5m");
    let mut chars = text.chars();
    let unit = chars.next_back().ok_or_else(invalid)?;
    let digits = chars.as_str();
    let (_, scale) = UNITS
        .iter()
        .find(|(name, _)| *name == unit)
        .ok_or_else(invalid)?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    match digits
        .parse::<u64>()
        .ok()
        .and_then(|count| count.checked_mul(*scale))
    {
        Some(0) => Err("Use a window of at least 1s".to_owned()),
        Some(seconds) if seconds <= MAX_SECONDS => Ok(seconds),
        _ => Err("Use a window of at most 30d".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_windows() {
        for (text, seconds) in [
            ("1s", 1),
            ("5m", 300),
            ("1h", 3_600),
            ("1d", 86_400),
            ("30d", 2_592_000),
            // Surrounding whitespace is ignored.
            (" 5m ", 300),
        ] {
            assert_eq!(parse(text), Ok(seconds), "{text}");
        }
        assert_eq!(parse("0s").unwrap_err(), "Use a window of at least 1s");
        assert_eq!(parse("31d").unwrap_err(), "Use a window of at most 30d");
        assert_eq!(
            parse("99999999999999999999d").unwrap_err(),
            "Use a window of at most 30d"
        );
        for text in ["", "m", "5", "1w", "-1m", "1.5h", "5 m", "5M"] {
            assert!(
                parse(text).unwrap_err().contains("isn't a window"),
                "{text}"
            );
        }
    }
}
