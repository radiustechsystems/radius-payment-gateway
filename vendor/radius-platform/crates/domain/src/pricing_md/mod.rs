//! pricing.md: an organization's published catalogs (each project's paid endpoints) and their
//! prices, as one Markdown file for agents.
//!
//! [`render`] turns a [`PricingDocument`] into the file: a `# <Org> pricing` title, then a
//! `## <Catalog>` section per catalog with its own base URL, payment line and mode, then a
//! `### <Endpoint>` entry per paid endpoint. What goes in each section is data
//! ([`fields::CATALOG_FIELDS`] and [`fields::LISTING_FIELDS`]), every seller-written value is
//! escaped ([`escape`]), and the output is deterministic: catalogs sorted by name, endpoints by
//! name then slug, `\n` line endings, one trailing newline, and nothing that changes without a
//! price changing (no timestamps, policy versions or rule IDs). The `policy` crate builds each
//! catalog's listings from its project's compiled policy (`policy::offers`), so the file says
//! what the gateway charges.

pub mod base_url;
pub mod escape;
pub mod fields;

pub use base_url::BaseUrl;

use crate::matching::{MethodMatch, PathPattern};
use crate::pricing::catalog::Mode;
use crate::pricing::micros::Micros;

use fields::{CATALOG_FIELDS, LISTING_FIELDS};

/// Everything one organization's file says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PricingDocument {
    pub organization_name: String,
    /// Sorted by name, then key; each lists at least one endpoint.
    pub catalogs: Vec<Catalog>,
}

/// One project's paid endpoints, named after the project.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Catalog {
    /// Tells catalogs with the same name apart when sorting (the project's ID); never shown.
    pub key: String,
    pub name: String,
    /// Where agents send its requests; [`BaseUrlLine::Unknown`] from [`Catalog::new`].
    pub base_url: BaseUrlLine,
    /// Test mode says so, so agents know it's not real money.
    pub mode: Mode,
    /// How the listed endpoints are paid: every way any of them accepts, in first-seen order.
    pub payment: Vec<PaymentOption>,
    /// Sorted by name, then slug.
    pub listings: Vec<Listing>,
}

/// What a catalog's `- Base URL:` line says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BaseUrlLine {
    /// The project's base URL, as the seller set it.
    Known(BaseUrl),
    /// [`PLACEHOLDER`], for a copy of the file that the server serving it fills in with its own
    /// origin (`@radiustech/platform-sdk` does).
    Placeholder,
    /// Not set: the line is left out, rather than showing agents a placeholder they can't use.
    Unknown,
}

/// The line [`BaseUrlLine::Placeholder`] renders. Seller text escapes `[`, and a [`BaseUrl`] can't
/// contain it, so no other line matches. `@radiustech/platform-sdk` replaces it
/// (`BASE_URL_PLACEHOLDER`): change it only together with the SDK.
pub const PLACEHOLDER: &str = "- Base URL: [Base URL]";

/// One paid endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listing {
    /// The endpoint's slug: a tiebreak for sorting, never shown.
    pub slug: String,
    pub name: String,
    pub methods: MethodMatch,
    pub path: PathPattern,
    /// USD per request.
    pub price: Micros,
    /// Requests allowed free before the price applies.
    pub free_quota: Option<Limit>,
    /// Requests allowed at all, paid or free: beyond it the gateway refuses them with `429`.
    pub rate_limit: Option<Limit>,
    /// The rule whose free quota and rate limit apply, by its stable ID, when it has either: the
    /// gateway counts both per rule, so listings with the same one share them. Never shown.
    pub limits_rule: Option<String>,
    /// The other listings of the catalog that share this one's free quota and rate limit, sorted
    /// by name; set by [`Catalog::new`].
    pub shared_with: Vec<String>,
    /// How this endpoint is paid, when that differs from its catalog's [`Catalog::payment`];
    /// empty when it's the same.
    pub payment: Vec<PaymentOption>,
    /// Who pays, when only some verified agents do: `Agents signed by chatgpt.com`. `None` when
    /// every caller pays.
    pub agents: Option<String>,
}

/// A number of requests per window: a free quota or a rate limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limit {
    pub quota: u64,
    pub window_s: u64,
    pub per: QuotaKey,
}

/// Who a limit counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuotaKey {
    /// Each client IP address.
    Ip,
    /// Each caller the seller identifies, else each IP address.
    Caller,
    /// Everyone together.
    Global,
    /// Each verified agent (operator or category), else each IP address.
    Agent,
}

/// One token on one network, by their display names: `SBC` on `Radius`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentOption {
    pub token: String,
    pub network: String,
}

impl Catalog {
    /// A catalog of `listings`, in any order. They're sorted by name then slug; the catalog's
    /// payment is every option the listings accept, in that order, and each listing keeps its
    /// own only where it differs from the catalog's. Listings whose limits come from the same rule
    /// name each other in [`Listing::shared_with`].
    pub fn new(
        key: impl Into<String>,
        name: impl Into<String>,
        mode: Mode,
        mut listings: Vec<Listing>,
    ) -> Self {
        listings.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.slug.cmp(&b.slug)));
        let mut payment: Vec<PaymentOption> = Vec::new();
        for option in listings.iter().flat_map(|listing| &listing.payment) {
            if !payment.contains(option) {
                payment.push(option.clone());
            }
        }
        for listing in &mut listings {
            if listing.payment == payment {
                listing.payment.clear();
            }
        }
        let rules: Vec<(Option<String>, String)> = listings
            .iter()
            .map(|listing| (listing.limits_rule.clone(), listing.name.clone()))
            .collect();
        for (index, listing) in listings.iter_mut().enumerate() {
            let limited = listing.free_quota.is_some() || listing.rate_limit.is_some();
            listing.shared_with = match &listing.limits_rule {
                Some(rule) if limited => rules
                    .iter()
                    .enumerate()
                    .filter(|(other, (other_rule, _))| {
                        *other != index && other_rule.as_ref() == Some(rule)
                    })
                    .map(|(_, (_, name))| name.clone())
                    .collect(),
                _ => Vec::new(),
            };
        }
        Self {
            key: key.into(),
            name: name.into(),
            base_url: BaseUrlLine::Unknown,
            mode,
            payment,
            listings,
        }
    }

    /// The catalog, saying `base_url` on its `- Base URL:` line.
    #[must_use]
    pub fn with_base_url(mut self, base_url: BaseUrlLine) -> Self {
        self.base_url = base_url;
        self
    }
}

impl PricingDocument {
    /// A document of `catalogs`, in any order. Catalogs with nothing to list are left out, and
    /// the rest are sorted by name, then key.
    pub fn new(organization_name: impl Into<String>, mut catalogs: Vec<Catalog>) -> Self {
        catalogs.retain(|catalog| !catalog.listings.is_empty());
        catalogs.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.key.cmp(&b.key)));
        Self {
            organization_name: organization_name.into(),
            catalogs,
        }
    }

    /// Whether there's nothing to list: no catalog with a paid endpoint. The file isn't served
    /// then.
    pub fn is_empty(&self) -> bool {
        self.catalogs.is_empty()
    }
}

/// How the gateway answers a request it doesn't serve, said once under the title: agents plan
/// from the file, so what a refusal looks like is part of the price list.
pub const DENIALS: &str = "A request without payment is answered `402 Payment Required` with x402 payment requirements; send it again with payment. A request beyond a rate limit is refused with `429 Too Many Requests`, whether or not it pays; wait for the window to reset (the `Retry-After` header, when sent, says how long). Every request counts against its endpoint's rate limit and free quota.";

/// The file.
pub fn render(document: &PricingDocument) -> String {
    let organization = escape::escape(&document.organization_name);
    let mut lines = vec![
        format!("# {organization} pricing"),
        String::new(),
        format!(
            "Machine-readable pricing for {organization}'s paid endpoints, by catalog. Prices are per request, in US dollars."
        ),
        String::new(),
        DENIALS.to_owned(),
    ];
    for catalog in &document.catalogs {
        lines.push(String::new());
        lines.push(format!("## {}", escape::escape(&catalog.name)));
        lines.push(String::new());
        lines.extend(field_lines(CATALOG_FIELDS, catalog));
        for listing in &catalog.listings {
            lines.push(String::new());
            lines.push(format!("### {}", escape::escape(&listing.name)));
            lines.push(String::new());
            lines.extend(field_lines(LISTING_FIELDS, listing));
        }
    }
    let mut file = lines.join("\n");
    file.push('\n');
    file
}

fn field_lines<'a, T>(
    fields: &'a [fields::Field<T>],
    value: &'a T,
) -> impl Iterator<Item = String> + 'a {
    fields.iter().filter_map(move |field| {
        (field.value)(value).map(|text| format!("- {}: {}", field.label, text.render()))
    })
}

/// A price in US dollars, with at least two decimal places and up to six: `$0.001`, `$0.05`,
/// `$2.50`, `$1,284.52`.
pub fn format_usd(price: Micros) -> String {
    let micros = price.get();
    let whole = fields::group_thousands(micros / 1_000_000);
    let fraction = format!("{:06}", micros % 1_000_000);
    let fraction = fraction.trim_end_matches('0');
    let fraction = format!("{fraction:0<2}");
    format!("${whole}.{fraction}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matching::HttpMethod;

    fn price(text: &str) -> Micros {
        Micros::parse(text).unwrap()
    }

    fn sbc(network: &str) -> PaymentOption {
        PaymentOption {
            token: "SBC".to_owned(),
            network: network.to_owned(),
        }
    }

    fn listing(slug: &str, name: &str, method: HttpMethod, path: &str, usd: &str) -> Listing {
        Listing {
            slug: slug.to_owned(),
            name: name.to_owned(),
            methods: MethodMatch::only([method]).unwrap(),
            path: PathPattern::parse(path).unwrap(),
            price: price(usd),
            free_quota: None,
            rate_limit: None,
            limits_rule: None,
            shared_with: Vec::new(),
            payment: vec![sbc("Radius")],
            agents: None,
        }
    }

    fn on(network: &str, mut listings: Vec<Listing>) -> Vec<Listing> {
        for listing in &mut listings {
            listing.payment = vec![sbc(network)];
        }
        listings
    }

    /// The design's Weather API, in production.
    fn weather() -> Catalog {
        let mut forecast = listing(
            "get-v1-forecast-city",
            "Forecast",
            HttpMethod::Get,
            "/v1/forecast/:city",
            "0.001",
        );
        forecast.free_quota = Some(Limit {
            quota: 20,
            window_s: 300,
            per: QuotaKey::Ip,
        });
        let mut export = listing(
            "post-v1-export",
            "Bulk export",
            HttpMethod::Post,
            "/v1/export",
            "0.05",
        );
        export.rate_limit = Some(Limit {
            quota: 10,
            window_s: 1,
            per: QuotaKey::Caller,
        });
        let listings = vec![
            listing(
                "post-v1-alerts",
                "Severe weather alerts",
                HttpMethod::Post,
                "/v1/alerts",
                "0.002",
            ),
            forecast,
            listing(
                "get-v1-history-city",
                "Historical data",
                HttpMethod::Get,
                "/v1/history/:city",
                "0.005",
            ),
            export,
        ];
        Catalog::new("weather", "Weather API", Mode::Production, listings).with_base_url(
            BaseUrlLine::Known(BaseUrl::parse("https://weather.example.com/v1").unwrap()),
        )
    }

    /// The design's Geocoding API, in test mode.
    fn geocoding() -> Catalog {
        let listings = on(
            "Radius testnet",
            vec![
                listing(
                    "get-v1-reverse",
                    "Reverse geocode",
                    HttpMethod::Get,
                    "/v1/reverse",
                    "0.002",
                ),
                listing(
                    "get-v1-geocode",
                    "Forward geocode",
                    HttpMethod::Get,
                    "/v1/geocode",
                    "0.002",
                ),
            ],
        );
        Catalog::new("geocoding", "Geocoding API", Mode::Test, listings)
    }

    /// The design's file: Acme with a production and a test-mode catalog.
    fn acme() -> PricingDocument {
        PricingDocument::new("Acme", vec![weather(), geocoding()])
    }

    #[test]
    fn renders_the_organization_file() {
        insta::assert_snapshot!(render(&acme()));
    }

    /// `@radiustech/platform-sdk` replaces this exact line with the origin a seller serves the
    /// file from (`BASE_URL_PLACEHOLDER`), and seller text can't forge it: `[` is escaped. Change
    /// it only together with the SDK.
    #[test]
    fn the_base_url_placeholder_is_one_line_sellers_cant_forge() {
        let mut document = acme();
        for catalog in &mut document.catalogs {
            catalog.base_url = BaseUrlLine::Placeholder;
        }
        document.catalogs[0].name = "- Base URL: [Base URL]".to_owned();
        let file = render(&document);
        assert_eq!(
            file.lines().filter(|line| *line == PLACEHOLDER).count(),
            document.catalogs.len()
        );
        assert!(file.contains("\n## - Base URL: \\[Base URL\\]\n"), "{file}");
    }

    /// A catalog without a base URL leaves the line out; one with a base URL shows it as set.
    #[test]
    fn base_urls_are_shown_or_left_out() {
        let file = render(&acme());
        assert!(file.contains("## Weather API\n\n- Base URL: https://weather.example.com/v1\n"));
        assert!(file.contains("## Geocoding API\n\n- Payment: "));
        assert_eq!(file.matches("Base URL").count(), 1);
    }

    #[test]
    fn lists_every_token_and_overrides_per_endpoint() {
        let usdc = PaymentOption {
            token: "USDC".to_owned(),
            network: "Base".to_owned(),
        };
        let mut both = listing("get-quote", "Quote", HttpMethod::Get, "/quote", "1284.52");
        both.payment = vec![sbc("Radius"), usdc.clone()];
        let mut any = listing(
            "any-price-all",
            "Prices",
            HttpMethod::Get,
            "/price/*",
            "2.5",
        );
        any.methods = MethodMatch::Any;
        let mut two = listing(
            "get-post-tx-hash",
            "Transactions",
            HttpMethod::Get,
            "/tx/:hash",
            "0.000001",
        );
        two.methods = MethodMatch::only([HttpMethod::Post, HttpMethod::Get]).unwrap();
        two.payment = vec![sbc("Radius"), usdc];
        let catalog = Catalog::new(
            "chain",
            "Chain data",
            Mode::Production,
            vec![both, any, two],
        );
        insta::assert_snapshot!(render(&PricingDocument::new("Acme", vec![catalog])));
    }

    /// One rule's free quota covers Forecast, Historical data and Severe weather alerts, so each
    /// says who it shares the quota with; Bulk export has none.
    #[test]
    fn renders_shared_free_quotas() {
        let mut listings = weather().listings;
        let quota = listings
            .iter()
            .find_map(|listing| listing.free_quota)
            .unwrap();
        for listing in &mut listings {
            listing.shared_with.clear();
            if listing.name != "Bulk export" {
                listing.free_quota = Some(quota);
                listing.limits_rule = Some("rule-shared".to_owned());
            }
        }
        listings.reverse();
        let catalog = Catalog::new(
            "weather",
            "Weather API",
            Mode::Production,
            on("Radius", listings),
        );
        let forecast = &catalog.listings[1];
        assert_eq!(forecast.name, "Forecast");
        assert_eq!(
            forecast.shared_with,
            ["Historical data", "Severe weather alerts"]
        );
        assert!(catalog.listings[0].shared_with.is_empty());
        insta::assert_snapshot!(render(&PricingDocument::new("Acme", vec![catalog])));
    }

    #[test]
    fn a_charge_for_some_agents_says_who_pays() {
        let mut lookup = listing("tx", "Lookup", HttpMethod::Get, "/tx/:hash", "0.001");
        lookup.agents = Some("Agents signed by chatgpt.com".to_owned());
        let catalog = Catalog::new(
            "chain".to_owned(),
            "Chain data".to_owned(),
            Mode::Production,
            vec![lookup],
        );
        let rendered = render(&PricingDocument::new("Acme", vec![catalog]));
        assert!(
            rendered.contains("- Who pays: Agents signed by chatgpt.com\n"),
            "{rendered}"
        );
    }

    #[test]
    fn a_quota_of_its_own_is_not_shared() {
        let mut listings = weather().listings;
        for (index, listing) in listings.iter_mut().enumerate() {
            listing.limits_rule = Some(format!("rule-{index}"));
        }
        let catalog = Catalog::new("weather", "Weather API", Mode::Production, listings);
        assert!(catalog.listings.iter().all(|l| l.shared_with.is_empty()));
        assert!(!render(&PricingDocument::new("Acme", vec![catalog])).contains("shared"));
    }

    /// A rate limit is listed beside the price, and a rule's rate limit is shared like its free
    /// quota: the gateway counts both per rule.
    #[test]
    fn rate_limits_are_listed_and_shared_like_free_quotas() {
        let rate = Limit {
            quota: 1_000,
            window_s: 3_600,
            per: QuotaKey::Global,
        };
        let mut analytics = listing(
            "get-a",
            "Analytics",
            HttpMethod::Get,
            "/analytics/*",
            "0.01",
        );
        let mut reports = listing("get-r", "Reports", HttpMethod::Get, "/reports", "0.02");
        for listing in [&mut analytics, &mut reports] {
            listing.rate_limit = Some(rate);
            listing.limits_rule = Some("rule-rate".to_owned());
        }
        let catalog = Catalog::new("p", "Data", Mode::Production, vec![reports, analytics]);
        assert_eq!(catalog.listings[0].shared_with, ["Reports"]);
        let file = render(&PricingDocument::new("Acme", vec![catalog]));
        assert!(
            file.contains(
                "\n- Rate limit: 1,000 requests per hour in total, shared with Reports\n"
            )
        );
        assert!(!file.contains("- Free:"));
        // The intro says what a refusal looks like.
        assert!(
            file.contains("`402 Payment Required`") && file.contains("`429 Too Many Requests`")
        );
    }

    #[test]
    fn input_order_does_not_change_the_file() {
        let forward = acme();
        let mut reversed_listings = weather().listings;
        reversed_listings.reverse();
        let weather_reversed = Catalog::new(
            "weather",
            "Weather API",
            Mode::Production,
            on("Radius", reversed_listings),
        )
        .with_base_url(weather().base_url);
        let reversed = PricingDocument::new("Acme", vec![geocoding(), weather_reversed]);
        assert_eq!(render(&forward), render(&reversed));
        // Catalogs by name, endpoints by name.
        let file = render(&forward);
        let at = |text: &str| file.find(text).unwrap();
        assert!(at("## Geocoding API") < at("## Weather API"));
        assert!(at("### Bulk export") < at("### Forecast"));

        // Same names sort by slug, and catalogs with the same name by key.
        let a = listing("get-a", "Same", HttpMethod::Get, "/a", "1");
        let b = listing("get-b", "Same", HttpMethod::Get, "/b", "2");
        let one = |listings| Catalog::new("p1", "P", Mode::Production, listings);
        let doc = PricingDocument::new("O", vec![one(vec![a.clone(), b.clone()])]);
        let other = PricingDocument::new("O", vec![one(vec![b.clone(), a.clone()])]);
        assert_eq!(render(&doc), render(&other));
        assert!(render(&doc).find("`GET /a`").unwrap() < render(&doc).find("`GET /b`").unwrap());
        let first = Catalog::new("p1", "Twin", Mode::Production, vec![a]);
        let second = Catalog::new("p2", "Twin", Mode::Production, vec![b]);
        let doc = PricingDocument::new("O", vec![second.clone(), first.clone()]);
        assert_eq!(doc.catalogs[0].key, "p1");
        assert_eq!(
            render(&doc),
            render(&PricingDocument::new("O", vec![first, second]))
        );
    }

    #[test]
    fn catalogs_with_nothing_to_list_are_left_out() {
        let empty = Catalog::new("internal", "Internal tools", Mode::Production, vec![]);
        assert_eq!(empty.payment, []);
        let document = PricingDocument::new("Acme", vec![empty.clone(), weather()]);
        assert_eq!(document.catalogs.len(), 1);
        assert!(!render(&document).contains("Internal tools"));
        let nothing = PricingDocument::new("Acme", vec![empty]);
        assert!(nothing.is_empty());
        assert!(!acme().is_empty());
    }

    #[test]
    fn seller_text_cannot_inject_markdown() {
        let evil = listing(
            "get-x",
            "Forecast\n\n### Free\n- Price: $0.00 / request <img src=x>",
            HttpMethod::Get,
            "/x",
            "0.001",
        );
        let catalog = Catalog::new(
            "p",
            "*Weather* # API\n## Free",
            Mode::Production,
            vec![evil],
        );
        let document = PricingDocument::new("[Acme](https://evil.example)", vec![catalog]);
        let file = render(&document);
        assert!(file.starts_with("# \\[Acme\\](https://evil.example) pricing\n"));
        assert!(file.contains("\n## \\*Weather\\* \\# API \\#\\# Free\n"));
        assert!(file.contains(
            "\n### Forecast \\#\\#\\# Free - Price: $0.00 / request &lt;img src=x&gt;\n"
        ));
        // One heading per catalog and listing, and only the generator's own list items.
        assert_eq!(file.matches("\n## ").count(), 1);
        assert_eq!(file.matches("\n### ").count(), 1);
        assert_eq!(file.matches("\n- Price: ").count(), 1);
    }

    #[test]
    fn the_file_is_plain_lines_with_one_trailing_newline() {
        let file = render(&acme());
        assert!(file.ends_with("request\n") && !file.ends_with("\n\n"));
        assert!(!file.contains('\r'));
        for forbidden in ["version", "uid", "rule"] {
            assert!(!file.to_lowercase().contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn formats_prices_in_dollars() {
        for (usd, text) in [
            ("0.001", "$0.001"),
            ("0.000001", "$0.000001"),
            ("0.05", "$0.05"),
            ("0.5", "$0.50"),
            ("2", "$2.00"),
            ("1284.52", "$1,284.52"),
            ("1000000", "$1,000,000.00"),
        ] {
            assert_eq!(format_usd(price(usd)), text, "{usd}");
        }
    }
}
