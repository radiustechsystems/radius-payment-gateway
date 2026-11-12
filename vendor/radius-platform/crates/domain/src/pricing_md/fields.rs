//! What pricing.md says, as data: each line is a [`Field`] with a label and a function that reads
//! its value, or leaves the line out by returning `None`. Adding a line is one entry here, not a
//! change to the renderer.

use super::escape::{code_span, escape};
use super::{BaseUrlLine, Catalog, Limit, Listing, PaymentOption, QuotaKey, format_usd};
use crate::matching::route_label;
use crate::pricing::catalog::Mode;

/// A field's value. Seller text can only be [`Text::Escaped`], [`Text::Code`] or a [`Text::Url`]
/// checked when it was set, so it can't skip escaping; [`Text::Literal`] is for our own fixed
/// strings, such as the `[Base URL]` placeholder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Text {
    /// Escaped with [`escape`] when rendered.
    Escaped(String),
    /// Rendered as an inline code span.
    Code(String),
    /// Rendered exactly as written.
    Literal(&'static str),
    /// A [`super::BaseUrl`], rendered as it is: it can't contain Markdown.
    Url(super::BaseUrl),
}

impl Text {
    pub(super) fn render(&self) -> String {
        match self {
            Self::Escaped(text) => escape(text),
            Self::Code(text) => code_span(text),
            Self::Literal(text) => (*text).to_owned(),
            Self::Url(url) => url.to_string(),
        }
    }
}

/// One `- <label>: <value>` line.
pub struct Field<T> {
    pub label: &'static str,
    pub value: fn(&T) -> Option<Text>,
}

/// The lines at the top of each catalog's section, about the whole catalog.
pub const CATALOG_FIELDS: &[Field<Catalog>] = &[
    Field {
        label: "Base URL",
        value: |catalog| match &catalog.base_url {
            BaseUrlLine::Known(url) => Some(Text::Url(url.clone())),
            // Rendered as `super::PLACEHOLDER`.
            BaseUrlLine::Placeholder => Some(Text::Literal("[Base URL]")),
            BaseUrlLine::Unknown => None,
        },
    },
    Field {
        label: "Payment",
        value: |catalog| payment(&catalog.payment),
    },
    Field {
        label: "Mode",
        value: |catalog| match catalog.mode {
            Mode::Test => Some(Text::Literal("test (no real money)")),
            Mode::Production => None,
        },
    },
];

/// The lines of each endpoint's section.
pub const LISTING_FIELDS: &[Field<Listing>] = &[
    Field {
        label: "Request",
        value: |listing| Some(Text::Code(request(listing))),
    },
    Field {
        label: "Price",
        value: |listing| {
            Some(Text::Escaped(format!(
                "{} / request",
                format_usd(listing.price)
            )))
        },
    },
    Field {
        label: "Who pays",
        value: |listing| listing.agents.clone().map(Text::Escaped),
    },
    Field {
        label: "Free",
        value: |listing| {
            listing
                .free_quota
                .map(|quota| Text::Escaped(limit(quota, &listing.shared_with)))
        },
    },
    Field {
        label: "Rate limit",
        // Beyond it requests are refused with `429`, paid or not; the file's intro says so.
        value: |listing| {
            listing
                .rate_limit
                .map(|rate| Text::Escaped(limit(rate, &listing.shared_with)))
        },
    },
    Field {
        label: "Payment",
        // Empty where it's the catalog's (see `Catalog::new`).
        value: |listing| payment(&listing.payment),
    },
];

/// `GET /v1/forecast/:city`, `GET, POST /tx/:hash` or `ANY /price/*`.
fn request(listing: &Listing) -> String {
    route_label(&listing.methods, &listing.path)
}

/// `x402, SBC on Radius`, or `x402, SBC on Radius or USDC on Base`.
fn payment(options: &[PaymentOption]) -> Option<Text> {
    if options.is_empty() {
        return None;
    }
    let options: Vec<String> = options
        .iter()
        .map(|option| format!("{} on {}", option.token, option.network))
        .collect();
    Some(Text::Escaped(format!("x402, {}", options.join(" or "))))
}

/// Most other endpoints a shared free quota names; more are counted instead.
const MAX_SHARED_NAMES: usize = 3;

/// `20 requests per 5 minutes per IP`, and who else's requests count against it when the limit
/// is shared: `…, shared with Historical data and Severe weather alerts`, or `…, shared across 6
/// endpoints`.
fn limit(quota: Limit, shared_with: &[String]) -> String {
    let requests = if quota.quota == 1 {
        "1 request".to_owned()
    } else {
        format!("{} requests", group_thousands(quota.quota))
    };
    let window = window(quota.window_s);
    let per = match quota.per {
        QuotaKey::Ip => " per IP",
        QuotaKey::Caller => " per caller",
        QuotaKey::Global => " in total",
        QuotaKey::Agent => " per agent",
    };
    let shared = match shared_with {
        [] => String::new(),
        names if names.len() > MAX_SHARED_NAMES => {
            format!(", shared across {} endpoints", names.len() + 1)
        }
        [only] => format!(", shared with {only}"),
        [rest @ .., last] => format!(", shared with {} and {last}", rest.join(", ")),
    };
    format!("{requests} per {window}{per}{shared}")
}

/// `minute`, `5 minutes`, `day`, `90 seconds`: the largest unit that divides the window.
fn window(seconds: u64) -> String {
    let (count, unit) = [(86_400, "day"), (3_600, "hour"), (60, "minute")]
        .into_iter()
        .find(|(size, _)| seconds >= *size && seconds.is_multiple_of(*size))
        .map_or((seconds, "second"), |(size, unit)| (seconds / size, unit));
    if count == 1 {
        unit.to_owned()
    } else {
        format!("{} {unit}s", group_thousands(count))
    }
}

/// `1234567` as `1,234,567`.
pub(super) fn group_thousands(number: u64) -> String {
    let digits = number.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_use_the_largest_whole_unit() {
        assert_eq!(window(1), "second");
        assert_eq!(window(90), "90 seconds");
        assert_eq!(window(60), "minute");
        assert_eq!(window(300), "5 minutes");
        assert_eq!(window(3_600), "hour");
        assert_eq!(window(5_400), "90 minutes");
        assert_eq!(window(86_400), "day");
        assert_eq!(window(30 * 86_400), "30 days");
    }

    #[test]
    fn free_quotas_name_who_they_count() {
        let quota = |quota, window_s, per| {
            limit(
                Limit {
                    quota,
                    window_s,
                    per,
                },
                &[],
            )
        };
        assert_eq!(
            quota(20, 300, QuotaKey::Ip),
            "20 requests per 5 minutes per IP"
        );
        assert_eq!(
            quota(1, 86_400, QuotaKey::Caller),
            "1 request per day per caller"
        );
        assert_eq!(
            quota(10_000, 3_600, QuotaKey::Global),
            "10,000 requests per hour in total"
        );
    }

    #[test]
    fn shared_free_quotas_name_the_others_or_count_them() {
        let quota = Limit {
            quota: 20,
            window_s: 300,
            per: QuotaKey::Ip,
        };
        let names = |names: &[&str]| names.iter().map(|&n| n.to_owned()).collect::<Vec<_>>();
        assert_eq!(
            limit(quota, &names(&["History"])),
            "20 requests per 5 minutes per IP, shared with History"
        );
        assert_eq!(
            limit(quota, &names(&["A", "B", "C"])),
            "20 requests per 5 minutes per IP, shared with A, B and C"
        );
        assert_eq!(
            limit(quota, &names(&["A", "B", "C", "D"])),
            "20 requests per 5 minutes per IP, shared across 5 endpoints"
        );
    }

    #[test]
    fn groups_thousands() {
        assert_eq!(group_thousands(0), "0");
        assert_eq!(group_thousands(999), "999");
        assert_eq!(group_thousands(1_000), "1,000");
        assert_eq!(group_thousands(1_234_567), "1,234,567");
    }
}
