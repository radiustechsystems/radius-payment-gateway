//! Validation errors keyed by the path of the field they belong to, e.g.
//! `pricing.price.amount`, so clients can show each message next to its input.

use std::collections::BTreeMap;
use std::fmt;

/// Messages keyed by field path. Paths use `.` between object keys, matching the request body.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FieldErrors(BTreeMap<String, String>);

impl FieldErrors {
    pub fn new() -> Self {
        Self::default()
    }

    /// One error for `field`.
    pub fn single(field: impl Into<String>, message: impl Into<String>) -> Self {
        let mut errors = Self::new();
        errors.add(field, message);
        errors
    }

    /// Records `message` for `field`. The first message for a field wins, so the most basic
    /// problem is the one reported.
    pub fn add(&mut self, field: impl Into<String>, message: impl Into<String>) {
        self.0.entry(field.into()).or_insert_with(|| message.into());
    }

    /// Records the error of `result`, if any, and returns its value.
    pub fn check<T>(&mut self, field: &str, result: Result<T, String>) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            Err(message) => {
                self.add(field, message);
                None
            }
        }
    }

    /// Moves `other`'s errors in under `prefix`, e.g. `price` + `amount` becomes `price.amount`.
    pub fn merge_under(&mut self, prefix: &str, other: FieldErrors) {
        for (field, message) in other.0 {
            self.add(format!("{prefix}.{field}"), message);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn get(&self, field: &str) -> Option<&str> {
        self.0.get(field).map(String::as_str)
    }

    /// `Ok(value)` when there are no errors.
    pub fn into_result<T>(self, value: impl FnOnce() -> T) -> Result<T, FieldErrors> {
        if self.is_empty() {
            Ok(value())
        } else {
            Err(self)
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0
            .iter()
            .map(|(field, message)| (field.as_str(), message.as_str()))
    }

    pub fn into_map(self) -> BTreeMap<String, String> {
        self.0
    }
}

/// The first message, in field order: a one-line summary for clients that ignore `fields`.
impl fmt::Display for FieldErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.values().next() {
            Some(message) => f.write_str(message),
            None => f.write_str("invalid request"),
        }
    }
}

impl std::error::Error for FieldErrors {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_first_message_per_field() {
        let mut errors = FieldErrors::new();
        errors.add("name", "enter a name");
        errors.add("name", "too long");
        assert_eq!(errors.get("name"), Some("enter a name"));
        assert_eq!(errors.to_string(), "enter a name");
    }

    #[test]
    fn merges_under_a_prefix() {
        let mut errors = FieldErrors::new();
        errors.merge_under(
            "pricing",
            FieldErrors::single("price.amount", "too precise"),
        );
        assert_eq!(errors.get("pricing.price.amount"), Some("too precise"));
    }

    #[test]
    fn into_result_is_ok_only_without_errors() {
        assert_eq!(FieldErrors::new().into_result(|| 1), Ok(1));
        assert!(FieldErrors::single("a", "b").into_result(|| 1).is_err());
    }
}
