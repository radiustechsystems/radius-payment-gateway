//! URL slugs for organizations: the `acme` in `app.radiustech.xyz/acme/pricing.md`.
//!
//! A slug is made once, from the name at the time, and kept when the name changes, so links keep
//! working. Collisions get `-2`, `-3`… (see the platform API's `pricing_md::queries`).

/// The longest base a name turns into, before any `-2` suffix.
pub const MAX_BASE_CHARS: usize = 60;

/// Organization slugs are the first segment of a web app path, so they mustn't be one of the web
/// app's own routes (or a route it may get), or `/settings/pricing.md` would be ambiguous.
pub const RESERVED_ORGANIZATION_SLUGS: &[&str] = &[
    "account",
    "admin",
    "api",
    "app",
    "assets",
    "auth",
    "billing",
    "callback",
    "catalogs",
    "config",
    "dashboard",
    "docs",
    "endpoints",
    "health",
    "help",
    "invite",
    "join",
    "login",
    "logout",
    "mcp",
    "new",
    "onboarding",
    "organizations",
    "policy",
    "pricing",
    "pricing-md",
    "projects",
    "settings",
    "sign-in",
    "sign-up",
    "signup",
    "slack",
    "static",
    "status",
    "support",
    "wallets",
    "well-known",
    "www",
];

/// `name` as a slug: lowercase ASCII letters and digits, with every run of anything else turned
/// into one `-`, no `-` at either end, at most [`MAX_BASE_CHARS`] long. A name with no letters or
/// digits (`日本`, `!!!`) becomes `fallback`.
pub fn slugify(name: &str, fallback: &str) -> String {
    let mut slug = String::with_capacity(name.len());
    for c in name.chars() {
        let c = c.to_ascii_lowercase();
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            slug.push(c);
        } else if !slug.is_empty() && !slug.ends_with('-') {
            slug.push('-');
        }
    }
    // ASCII only by now, so byte and char lengths agree.
    slug.truncate(MAX_BASE_CHARS);
    let slug = slug.trim_matches('-');
    if slug.is_empty() {
        fallback.to_owned()
    } else {
        slug.to_owned()
    }
}

/// Whether `slug` is one the web app's routes keep for themselves.
pub fn is_reserved_organization_slug(slug: &str) -> bool {
    RESERVED_ORGANIZATION_SLUGS.contains(&slug)
}

/// Whether `text` is shaped like a slug: `[a-z0-9]` words joined by single dashes, at most 64
/// characters (a 60-character base and a suffix). The tables check the same.
pub fn is_slug(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text.split('-').all(|word| {
            !word.is_empty()
                && word
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowercases_and_joins_words_with_dashes() {
        assert_eq!(slugify("Weather API", "org"), "weather-api");
        assert_eq!(slugify("  Acme, Inc.  ", "org"), "acme-inc");
        assert_eq!(slugify("v2 -- Beta__Feed", "project"), "v2-beta-feed");
        assert_eq!(slugify("Café Münster", "project"), "caf-m-nster");
    }

    #[test]
    fn falls_back_when_nothing_is_left() {
        assert_eq!(slugify("日本", "project"), "project");
        assert_eq!(slugify("!!!", "org"), "org");
        assert_eq!(slugify("", "org"), "org");
    }

    #[test]
    fn caps_the_length_without_a_trailing_dash() {
        let name = format!("{} tail", "a".repeat(59));
        let slug = slugify(&name, "project");
        assert_eq!(slug, "a".repeat(59));
        assert!(slugify(&"word ".repeat(40), "project").len() <= MAX_BASE_CHARS);
    }

    #[test]
    fn every_slug_it_makes_is_a_slug() {
        for name in ["Weather API", "日本", "x", "-a-", &"z".repeat(200)] {
            assert!(is_slug(&slugify(name, "project")), "{name}");
        }
        assert!(is_slug("weather-api-2"));
        for text in ["", "-a", "a-", "a--b", "A", "a_b", &"a".repeat(65)] {
            assert!(!is_slug(text), "{text}");
        }
    }

    #[test]
    fn reserves_the_web_app_routes() {
        for slug in [
            "endpoints",
            "wallets",
            "settings",
            "login",
            "callback",
            "api",
            "docs",
            "well-known",
            "projects",
            "organizations",
            "sign-in",
            "sign-up",
            "catalogs",
        ] {
            assert!(is_reserved_organization_slug(slug), "{slug}");
            assert!(is_slug(slug), "{slug}");
        }
        assert!(!is_reserved_organization_slug("acme"));
    }
}
