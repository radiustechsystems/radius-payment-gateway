//! A catalog's base URL: where agents send the requests its endpoints list. Sellers set it per
//! project, and pricing.md shows it as written, so it's checked here to be a plain `https` URL that
//! can't add Markdown to the file.

use std::fmt;

/// The longest base URL accepted, in bytes.
pub const MAX_LEN: usize = 2048;

/// An `https` URL with a host, and no credentials, query or fragment, normalized: lowercase
/// scheme and host, no default port, and no trailing `/`. Its path uses only unreserved
/// characters, `/` and percent escapes, so it's safe in a Markdown line as it is.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BaseUrl(String);

impl BaseUrl {
    /// `text` as a base URL, or why it isn't one, as a sentence for the person who typed it.
    pub fn parse(text: &str) -> Result<Self, &'static str> {
        let text = text.trim();
        if text.is_empty() {
            return Err("Enter a base URL, like https://api.example.com");
        }
        if text.len() > MAX_LEN {
            return Err("Use a base URL of at most 2,048 characters");
        }
        let url =
            url::Url::parse(text).map_err(|_| "Enter a full URL, like https://api.example.com")?;
        if url.scheme() != "https" {
            return Err("Use an https:// URL");
        }
        match url.host() {
            Some(url::Host::Domain(domain)) if public_domain(domain) => {}
            Some(url::Host::Domain(_) | url::Host::Ipv4(_) | url::Host::Ipv6(_)) => {
                return Err("Use a public domain name, like https://api.example.com");
            }
            None => return Err("Enter a full URL, like https://api.example.com"),
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err("Leave the user name and password out of the base URL");
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err("Leave the query (?) and fragment (#) out of the base URL");
        }
        let path = url.path().trim_end_matches('/');
        if !path.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/' | b'%')
        }) {
            return Err("Use only letters, digits, -, ., _, ~ and / in the base URL's path");
        }
        let origin = url.origin().ascii_serialization();
        Ok(Self(format!("{origin}{path}")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Top-level domains that never resolve on the public internet (RFC 2606, RFC 6761, RFC 6762 and
/// ICANN's `.internal`), so agents could never reach a base URL under one.
const PRIVATE_TLDS: &[&str] = &["internal", "invalid", "local", "localhost", "test"];

/// Whether `domain` (as `url` serializes it: lowercase ASCII, punycode for other scripts) looks
/// like a name agents can reach: at least two labels of letters, digits and inner hyphens, at most
/// 63 characters each, under a top-level domain of letters (or punycode) that isn't private.
fn public_domain(domain: &str) -> bool {
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    let labels: Vec<&str> = domain.split('.').collect();
    let [_, .., tld] = labels.as_slice() else {
        return false;
    };
    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }) && (tld.starts_with("xn--")
        || (tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic())))
        && !PRIVATE_TLDS.contains(tld)
}

impl fmt::Display for BaseUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(text: &str) -> String {
        BaseUrl::parse(text).unwrap().to_string()
    }

    #[test]
    fn normalizes_urls() {
        assert_eq!(ok("https://api.example.com"), "https://api.example.com");
        assert_eq!(ok(" HTTPS://API.Example.com/ "), "https://api.example.com");
        assert_eq!(
            ok("https://api.example.com:443/v1/"),
            "https://api.example.com/v1"
        );
        assert_eq!(
            ok("https://api.example.com:8443/v1"),
            "https://api.example.com:8443/v1"
        );
        assert_eq!(
            ok("https://docs.radiustech.xyz"),
            "https://docs.radiustech.xyz"
        );
        assert_eq!(
            ok("https://bücher.example/a_b~c"),
            "https://xn--bcher-kva.example/a_b~c"
        );
        assert_eq!(ok("https://shop.xn--p1ai"), "https://shop.xn--p1ai");
        assert_eq!(ok("https://a-b.co.uk/v1"), "https://a-b.co.uk/v1");
        assert_eq!(
            BaseUrl::parse("https://hehehe").unwrap_err(),
            "Use a public domain name, like https://api.example.com"
        );
    }

    #[test]
    fn refuses_what_isnt_a_plain_https_url() {
        for text in [
            "",
            "   ",
            "api.example.com",
            "/v1",
            "http://api.example.com",
            "ftp://api.example.com",
            "https://user:pass@api.example.com",
            "https://api.example.com/?a=1",
            "https://api.example.com/#top",
            "https://api.example.com/[Base URL]",
            "https://api.example.com/a*b",
            "https://api.example.com/a(b)",
            "https://hehehe",
            "https://localhost",
            "https://api.localhost",
            "https://printer.local",
            "https://db.internal",
            "https://a.test",
            "https://127.0.0.1",
            "https://10.0.0.1:8443/v1",
            "https://[::1]",
            "https://api.example.123",
            "https://-api.example.com",
            "https://api_x.example.com",
            "https://api..example.com",
        ] {
            assert!(BaseUrl::parse(text).is_err(), "{text}");
        }
        let long = format!("https://api.example.com/{}", "a".repeat(MAX_LEN));
        assert!(BaseUrl::parse(&long).is_err());
    }
}
