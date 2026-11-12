//! Which requests an endpoint applies to: its HTTP methods and a path pattern. The pair becomes the
//! `match` of the endpoint in the policy.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The methods an endpoint can be limited to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl HttpMethod {
    pub const ALL: [HttpMethod; 5] = [Self::Get, Self::Post, Self::Put, Self::Patch, Self::Delete];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }

    /// Accepts upper or lower case.
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|method| method.as_str().eq_ignore_ascii_case(text.trim()))
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The methods an endpoint matches: every method, or a non-empty set kept sorted and free of
/// duplicates. Stored as an array where the empty array means any method, as in the policy, where
/// a rule without `method` matches every method.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MethodMatch {
    Any,
    /// Never empty: build it with [`MethodMatch::only`], which refuses an empty set.
    Only(BTreeSet<HttpMethod>),
}

impl MethodMatch {
    /// `None` for an empty set: "no methods" isn't a valid endpoint.
    pub fn only(methods: impl IntoIterator<Item = HttpMethod>) -> Option<Self> {
        let methods: BTreeSet<_> = methods.into_iter().collect();
        (!methods.is_empty()).then_some(Self::Only(methods))
    }

    /// From the stored array: empty is [`MethodMatch::Any`].
    pub fn from_list(methods: impl IntoIterator<Item = HttpMethod>) -> Self {
        Self::only(methods).unwrap_or(Self::Any)
    }

    /// The stored array: empty for [`MethodMatch::Any`].
    pub fn to_list(&self) -> Vec<HttpMethod> {
        match self {
            Self::Any => Vec::new(),
            Self::Only(methods) => methods.iter().copied().collect(),
        }
    }

    pub fn intersects(&self, other: &MethodMatch) -> bool {
        match (self, other) {
            (Self::Any, _) | (_, Self::Any) => true,
            (Self::Only(a), Self::Only(b)) => !a.is_disjoint(b),
        }
    }

    /// The methods both match, or `None` when they have none in common.
    pub fn intersection(&self, other: &MethodMatch) -> Option<MethodMatch> {
        match (self, other) {
            (Self::Any, other) | (other, Self::Any) => Some(other.clone()),
            (Self::Only(a), Self::Only(b)) => Self::only(a.intersection(b).copied()),
        }
    }
}

/// How people read a route: `GET /v1/forecast/:city`, `GET, POST /tx/:hash` or `ANY /price/*`.
pub fn route_label(methods: &MethodMatch, path: &PathPattern) -> String {
    let methods = match methods {
        MethodMatch::Any => "ANY".to_owned(),
        MethodMatch::Only(methods) => methods
            .iter()
            .map(|method| method.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    };
    format!("{methods} {path}")
}

impl Serialize for MethodMatch {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_list().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MethodMatch {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Vec::<HttpMethod>::deserialize(deserializer).map(Self::from_list)
    }
}

/// One `/`-separated part of a [`PathPattern`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Segment {
    /// Matches itself exactly.
    Literal(String),
    /// `:name`: matches any one segment.
    Param(String),
    /// A trailing `*`: matches everything below.
    Wildcard,
}

/// A request path pattern such as `/tx/:hash` or `/price/*`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathPattern {
    segments: Vec<Segment>,
}

const MAX_PATH_CHARS: usize = 512;

fn is_literal_char(c: char) -> bool {
    // RFC 3986 unreserved characters, plus a few sub-delims common in API paths.
    c.is_ascii_alphanumeric() || "-._~@!$&'()+,;=".contains(c)
}

fn is_param_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

impl PathPattern {
    /// Parses a pattern. It starts with `/`; segments are literal text, `:name` (one segment), or
    /// a final `*` (everything below). `/` alone is the root.
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        if text.is_empty() {
            return Err("Enter a path, like /tx/:hash".to_owned());
        }
        if !text.starts_with('/') {
            return Err("Start the path with /".to_owned());
        }
        if text.chars().count() > MAX_PATH_CHARS {
            return Err(format!("Use at most {MAX_PATH_CHARS} characters"));
        }
        if text == "/" {
            return Ok(Self {
                segments: Vec::new(),
            });
        }
        let parts: Vec<&str> = text[1..].split('/').collect();
        let mut segments = Vec::with_capacity(parts.len());
        let mut params = BTreeSet::new();
        for (index, part) in parts.iter().enumerate() {
            let last = index + 1 == parts.len();
            let segment = if part.is_empty() {
                return Err(if last {
                    "Remove the trailing /".to_owned()
                } else {
                    "Remove the empty segment (//)".to_owned()
                });
            } else if *part == "*" {
                if !last {
                    return Err("Use * only at the end of the path".to_owned());
                }
                Segment::Wildcard
            } else if let Some(name) = part.strip_prefix(':') {
                if !is_param_name(name) {
                    return Err(format!(
                        "Name the parameter :{name} with letters, digits and _, starting with a letter"
                    ));
                }
                if !params.insert(name) {
                    return Err(format!("Use the parameter :{name} only once"));
                }
                Segment::Param(name.to_owned())
            } else if part.contains('*') {
                return Err("Use * as a whole segment at the end, like /price/*".to_owned());
            } else if let Some(bad) = part.chars().find(|c| !is_literal_char(*c)) {
                return Err(format!("Remove the character {bad:?} from the path"));
            } else {
                Segment::Literal((*part).to_owned())
            };
            segments.push(segment);
        }
        Ok(Self { segments })
    }

    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Whether a request path matches, as x402 matches routes: literal segments exactly, `:name`
    /// any one non-empty segment, and a trailing `*` the path above it and everything below. A
    /// query string and one trailing `/` are ignored.
    pub fn matches(&self, path: &str) -> bool {
        let path = path.split(['?', '#']).next().unwrap_or_default();
        let Some(path) = path.strip_prefix('/') else {
            return false;
        };
        let path = path.strip_suffix('/').unwrap_or(path);
        let parts: Vec<&str> = if path.is_empty() {
            Vec::new()
        } else {
            path.split('/').collect()
        };
        for (index, segment) in self.segments.iter().enumerate() {
            match (segment, parts.get(index)) {
                (Segment::Wildcard, _) => return true,
                (Segment::Literal(text), Some(part)) if part == text => {}
                (Segment::Param(_), Some(part)) if !part.is_empty() => {}
                _ => return false,
            }
        }
        parts.len() == self.segments.len()
    }

    /// The pattern with parameter names dropped, so `/tx/:hash` and `/tx/:id`, which match the
    /// same requests, compare equal.
    pub fn match_key(&self) -> String {
        if self.segments.is_empty() {
            return "/".to_owned();
        }
        self.segments
            .iter()
            .map(|segment| match segment {
                Segment::Literal(text) => format!("/{text}"),
                Segment::Param(_) => "/:".to_owned(),
                Segment::Wildcard => "/*".to_owned(),
            })
            .collect()
    }
}

impl fmt::Display for PathPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.segments.is_empty() {
            return f.write_str("/");
        }
        for segment in &self.segments {
            match segment {
                Segment::Literal(text) => write!(f, "/{text}")?,
                Segment::Param(name) => write!(f, "/:{name}")?,
                Segment::Wildcard => f.write_str("/*")?,
            }
        }
        Ok(())
    }
}

impl Serialize for PathPattern {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for PathPattern {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

/// Whether two endpoints would answer the same request: the same path (ignoring parameter names)
/// and at least one method in common, where any method intersects everything. Such endpoints are
/// refused. Different patterns that match some of the same requests (`/tx/*` and `/tx/:hash`) are
/// allowed: [`cmp_specificity`] decides which one governs those requests.
pub fn overlaps(
    (methods_a, path_a): (&MethodMatch, &PathPattern),
    (methods_b, path_b): (&MethodMatch, &PathPattern),
) -> bool {
    path_a.match_key() == path_b.match_key() && methods_a.intersects(methods_b)
}

/// Whether some request matches both patterns: literal segments agree where both have one, a
/// `:name` meets any one segment, and a trailing `*` meets the rest of the other pattern
/// (`/price/*` and `/price` both match `/price`).
pub fn paths_intersect(a: &PathPattern, b: &PathPattern) -> bool {
    let mut a = a.segments().iter();
    let mut b = b.segments().iter();
    loop {
        match (a.next(), b.next()) {
            (Some(Segment::Wildcard), _) | (_, Some(Segment::Wildcard)) | (None, None) => {
                return true;
            }
            (None, Some(_)) | (Some(_), None) => return false,
            (Some(Segment::Literal(x)), Some(Segment::Literal(y))) if x != y => return false,
            _ => {}
        }
    }
}

/// Whether some request matches both endpoints: a method in common and paths that intersect.
pub fn routes_intersect(
    (methods_a, path_a): (&MethodMatch, &PathPattern),
    (methods_b, path_b): (&MethodMatch, &PathPattern),
) -> bool {
    methods_a.intersects(methods_b) && paths_intersect(path_a, path_b)
}

/// How specific a route is, for choosing the one endpoint that governs a request several match.
/// [`Ordering::Less`] means `a` is more specific and wins.
///
/// Paths compare first, segment by segment from the left: a literal segment beats a `:name`, a
/// `:name` beats a trailing `*`, and a path that has ended beats a `*` (`/price` beats `/price/*`
/// for `/price`). So `/forecast/list` beats `/forecast/:region`, and `/files/:id/*` beats
/// `/files/*`. Only then do methods count: for the same path, a list of methods beats any method.
/// Endpoints with the same path and a method in common can't be created, so that tie never has to
/// break between two endpoints one request matches; it's there so the order is total.
///
/// Routes no request matches together still get an order (by literal text, then method names),
/// so sorting by it is deterministic; callers break the remaining ties by slug.
pub fn cmp_specificity(
    (methods_a, path_a): (&MethodMatch, &PathPattern),
    (methods_b, path_b): (&MethodMatch, &PathPattern),
) -> Ordering {
    specificity_key(path_a)
        .cmp(&specificity_key(path_b))
        .then_with(|| match (methods_a, methods_b) {
            (MethodMatch::Only(a), MethodMatch::Only(b)) => a.cmp(b),
            (MethodMatch::Only(_), MethodMatch::Any) => Ordering::Less,
            (MethodMatch::Any, MethodMatch::Only(_)) => Ordering::Greater,
            (MethodMatch::Any, MethodMatch::Any) => Ordering::Equal,
        })
}

/// Each segment's rank (literal 0, `:name` 1, the end of the path 2, `*` 3) with its literal
/// text, ending with the end of the path unless the pattern ends in `*`. Compared
/// lexicographically.
fn specificity_key(path: &PathPattern) -> Vec<(u8, &str)> {
    let mut key: Vec<(u8, &str)> = path
        .segments()
        .iter()
        .map(|segment| match segment {
            Segment::Literal(text) => (0, text.as_str()),
            Segment::Param(_) => (1, ""),
            Segment::Wildcard => (3, ""),
        })
        .collect();
    if !matches!(path.segments().last(), Some(Segment::Wildcard)) {
        key.push((2, ""));
    }
    key
}

/// A readable ID from the methods and path, e.g. `get-tx-hash`, `get-post-tx-hash` or
/// `any-price-all`. It becomes the policy's endpoint ID, so it's generated once and kept; callers add a
/// suffix to keep it unique in the project ([`unique_slug`]).
pub fn slug(methods: &MethodMatch, path: &PathPattern) -> String {
    let mut words: Vec<String> = match methods {
        MethodMatch::Any => vec!["any".to_owned()],
        MethodMatch::Only(methods) => methods
            .iter()
            .map(|method| method.as_str().to_ascii_lowercase())
            .collect(),
    };
    if path.segments.is_empty() {
        words.push("root".to_owned());
    }
    for segment in &path.segments {
        words.push(match segment {
            Segment::Literal(text) | Segment::Param(text) => text.to_ascii_lowercase(),
            Segment::Wildcard => "all".to_owned(),
        });
    }
    let joined = words.join("-");
    // Keep [a-z0-9-] only, without repeated or edge dashes.
    let mut slug = String::with_capacity(joined.len());
    for c in joined.chars() {
        let c = if c.is_ascii_alphanumeric() { c } else { '-' };
        if c != '-' || !slug.ends_with('-') {
            slug.push(c);
        }
    }
    slug.trim_matches('-').to_owned()
}

/// `base`, or `base-2`, `base-3`… if that's already taken.
pub fn unique_slug(base: &str, taken: impl Fn(&str) -> bool) -> String {
    if !taken(base) {
        return base.to_owned();
    }
    (2..)
        .map(|n| format!("{base}-{n}"))
        .find(|candidate| !taken(candidate))
        .expect("an unused suffix exists")
}

#[cfg(test)]
mod tests {
    use super::*;
    use HttpMethod::*;

    fn path(text: &str) -> PathPattern {
        PathPattern::parse(text).unwrap()
    }

    fn only(methods: &[HttpMethod]) -> MethodMatch {
        MethodMatch::only(methods.iter().copied()).unwrap()
    }

    #[test]
    fn method_sets_are_sorted_and_deduplicated() {
        assert_eq!(only(&[Post, Get, Post]).to_list(), [Get, Post]);
        assert_eq!(MethodMatch::only([]), None);
        assert_eq!(MethodMatch::from_list([]), MethodMatch::Any);
        assert_eq!(MethodMatch::Any.to_list(), []);
    }

    #[test]
    fn method_sets_serialize_as_arrays_with_empty_meaning_any() {
        assert_eq!(
            serde_json::to_string(&only(&[Post, Get])).unwrap(),
            r#"["GET","POST"]"#
        );
        assert_eq!(serde_json::to_string(&MethodMatch::Any).unwrap(), "[]");
        assert_eq!(
            serde_json::from_str::<MethodMatch>("[]").unwrap(),
            MethodMatch::Any
        );
        assert!(serde_json::from_str::<MethodMatch>(r#"["TRACE"]"#).is_err());
    }

    #[test]
    fn parses_methods_in_any_case() {
        assert_eq!(HttpMethod::parse("get"), Some(Get));
        assert_eq!(HttpMethod::parse("DELETE"), Some(Delete));
        assert_eq!(HttpMethod::parse("HEAD"), None);
    }

    #[test]
    fn parses_path_patterns() {
        assert_eq!(path("/tx/:hash").to_string(), "/tx/:hash");
        assert_eq!(path("/price/*").to_string(), "/price/*");
        assert_eq!(path("/").to_string(), "/");
        assert_eq!(path("/*").to_string(), "/*");
        assert_eq!(path(" /v1/quote ").to_string(), "/v1/quote");
        assert_eq!(
            path("/a/:b/*").segments(),
            [
                Segment::Literal("a".into()),
                Segment::Param("b".into()),
                Segment::Wildcard
            ]
        );
    }

    #[test]
    fn rejects_bad_path_patterns() {
        for (text, error) in [
            ("", "Enter a path, like /tx/:hash"),
            ("tx/:hash", "Start the path with /"),
            ("/tx/", "Remove the trailing /"),
            ("/tx//hash", "Remove the empty segment (//)"),
            ("/*/tx", "Use * only at the end of the path"),
            (
                "/price*",
                "Use * as a whole segment at the end, like /price/*",
            ),
            (
                "/tx/:",
                "Name the parameter : with letters, digits and _, starting with a letter",
            ),
            (
                "/tx/:1d",
                "Name the parameter :1d with letters, digits and _, starting with a letter",
            ),
            ("/a/:id/b/:id", "Use the parameter :id only once"),
            ("/tx?x=1", "Remove the character '?' from the path"),
            ("/a b", "Remove the character ' ' from the path"),
        ] {
            assert_eq!(PathPattern::parse(text).unwrap_err(), error, "{text}");
        }
        assert!(PathPattern::parse(&format!("/{}", "a".repeat(512))).is_err());
    }

    #[test]
    fn same_path_with_shared_methods_overlaps() {
        let tx = path("/tx/:hash");
        assert!(overlaps((&only(&[Get]), &tx), (&only(&[Get, Post]), &tx)));
        assert!(!overlaps((&only(&[Get]), &tx), (&only(&[Post]), &tx)));
        // Any intersects everything, both ways.
        assert!(overlaps((&MethodMatch::Any, &tx), (&only(&[Delete]), &tx)));
        assert!(overlaps((&only(&[Delete]), &tx), (&MethodMatch::Any, &tx)));
        // Parameter names don't matter.
        assert!(overlaps(
            (&only(&[Get]), &tx),
            (&only(&[Get]), &path("/tx/:id"))
        ));
        // Different paths don't overlap here; wildcard shadowing comes later.
        assert!(!overlaps(
            (&MethodMatch::Any, &tx),
            (&MethodMatch::Any, &path("/tx/*"))
        ));
        assert!(!overlaps(
            (&MethodMatch::Any, &tx),
            (&MethodMatch::Any, &path("/tx/latest"))
        ));
    }

    #[test]
    fn slugs_name_methods_and_path() {
        assert_eq!(slug(&only(&[Get]), &path("/tx/:hash")), "get-tx-hash");
        assert_eq!(
            slug(&only(&[Post, Get]), &path("/tx/:hash")),
            "get-post-tx-hash"
        );
        assert_eq!(slug(&MethodMatch::Any, &path("/tx/:hash")), "any-tx-hash");
        assert_eq!(slug(&MethodMatch::Any, &path("/price/*")), "any-price-all");
        assert_eq!(slug(&only(&[Get]), &path("/")), "get-root");
        assert_eq!(
            slug(&only(&[Get]), &path("/V1/Weather_Now/~me")),
            "get-v1-weather-now-me"
        );
    }

    #[test]
    fn unique_slugs_get_a_suffix() {
        let taken = ["get-tx", "get-tx-2"];
        assert_eq!(unique_slug("get-tx", |s| taken.contains(&s)), "get-tx-3");
        assert_eq!(
            unique_slug("get-quote", |s| taken.contains(&s)),
            "get-quote"
        );
    }

    #[test]
    fn paths_intersect_when_a_request_matches_both() {
        for (a, b, expected) in [
            ("/forecast/list", "/forecast/:region", true),
            ("/forecast/list", "/forecast/lists", false),
            ("/forecast/:region", "/forecast/:id", true),
            ("/forecast/:region", "/forecast", false),
            ("/forecast/:region", "/forecast/:region/hourly", false),
            ("/price/*", "/price", true),
            ("/price/*", "/price/btc/usd", true),
            ("/price/*", "/prices", false),
            ("/*", "/anything/:at/all", true),
            ("/", "/", true),
            ("/", "/a", false),
            ("/a/:b/c", "/a/x/:d", true),
        ] {
            assert_eq!(paths_intersect(&path(a), &path(b)), expected, "{a} and {b}");
            assert_eq!(paths_intersect(&path(b), &path(a)), expected, "{b} and {a}");
        }
        assert!(routes_intersect(
            (&only(&[Get]), &path("/a/list")),
            (&MethodMatch::Any, &path("/a/:id"))
        ));
        assert!(!routes_intersect(
            (&only(&[Get]), &path("/a/list")),
            (&only(&[Post]), &path("/a/:id"))
        ));
    }

    #[test]
    fn more_specific_routes_sort_first() {
        let get = only(&[Get]);
        let any = MethodMatch::Any;
        // Each pair is (more specific, less specific).
        for ((ma, a), (mb, b)) in [
            ((&get, "/forecast/list"), (&get, "/forecast/:region")),
            ((&any, "/forecast/list"), (&get, "/forecast/:region")),
            ((&get, "/forecast/:region"), (&get, "/forecast/*")),
            ((&get, "/price"), (&get, "/price/*")),
            ((&get, "/files/:id/*"), (&get, "/files/*")),
            ((&get, "/a/b/c/*"), (&get, "/a/*")),
            ((&get, "/a/:b/c"), (&get, "/a/:b/:c")),
            ((&get, "/a/b/:c"), (&get, "/a/:b/c")),
            ((&get, "/"), (&get, "/*")),
            ((&get, "/tx/:hash"), (&any, "/tx/:hash")),
        ] {
            let (a, b) = (path(a), path(b));
            assert_eq!(
                cmp_specificity((ma, &a), (mb, &b)),
                Ordering::Less,
                "{a} before {b}"
            );
            assert_eq!(
                cmp_specificity((mb, &b), (ma, &a)),
                Ordering::Greater,
                "{b} after {a}"
            );
        }
        // Parameter names don't count.
        assert_eq!(
            cmp_specificity((&get, &path("/tx/:hash")), (&get, &path("/tx/:id"))),
            Ordering::Equal
        );
    }

    #[test]
    fn matches_request_paths() {
        let cases = [
            ("/tx/:hash", "/tx/0xabc", true),
            ("/tx/:hash", "/tx/0xabc/", true),
            ("/tx/:hash", "/tx/0xabc?full=1", true),
            ("/tx/:hash", "/tx", false),
            ("/tx/:hash", "/tx/a/b", false),
            ("/tx/:hash", "/tx//", false),
            ("/price/*", "/price", true),
            ("/price/*", "/price/btc/usd", true),
            ("/price/*", "/prices", false),
            ("/", "/", true),
            ("/", "/a", false),
            ("/*", "/anything/at/all", true),
            ("/Quote", "/quote", false),
            ("/tx", "tx", false),
        ];
        for (pattern, path, expected) in cases {
            assert_eq!(
                PathPattern::parse(pattern).unwrap().matches(path),
                expected,
                "{pattern} against {path}"
            );
        }
    }
}
