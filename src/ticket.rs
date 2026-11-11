//! Tickets: how a browser that paid from the payment page gets the purchase delivered on the
//! reload that follows. A ticket is single-use, short-lived, and bound to the exact method and
//! URL that was paid for. It travels in a cookie the gateway sets on the paid response and
//! strips from the reload before anything reaches the upstream.

use std::time::Duration;

use http::Method;
use http::header::{COOKIE, HeaderMap, HeaderValue};

pub const COOKIE_NAME: &str = "radius_ticket";

/// A fresh ticket id: 16 random bytes as hex.
pub fn new_id() -> String {
    let bytes: [u8; 16] = rand::random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// HEAD is delivered as GET was paid for.
pub fn normalized_method(method: &Method) -> &'static str {
    if *method == Method::HEAD || *method == Method::GET {
        "GET"
    } else {
        "OTHER"
    }
}

/// The cookie's `Path`: the request path when a cookie can carry it, else `/`. The binding to
/// the exact URL is in the store either way; the path only keeps the cookie off other routes.
pub fn cookie_path(request_path: &str) -> &str {
    let carriable = request_path.starts_with('/')
        && request_path
            .bytes()
            .all(|b| b > 0x20 && b < 0x7f && b != b';' && b != b',');
    if carriable { request_path } else { "/" }
}

pub fn set_cookie(id: &str, path: &str, ttl: Duration, secure: bool) -> HeaderValue {
    let value = format!(
        "{COOKIE_NAME}={id}; Path={path}; Max-Age={}; HttpOnly; SameSite=Strict{}",
        ttl.as_secs().max(1),
        if secure { "; Secure" } else { "" }
    );
    HeaderValue::from_str(&value).expect("a cookie-safe value")
}

pub fn clear_cookie(path: &str, secure: bool) -> HeaderValue {
    let value = format!(
        "{COOKIE_NAME}=; Path={path}; Max-Age=0; HttpOnly; SameSite=Strict{}",
        if secure { "; Secure" } else { "" }
    );
    HeaderValue::from_str(&value).expect("a cookie-safe value")
}

/// The ticket id in the request's cookies, if any, removed from them so it never reaches the
/// upstream. Other cookies are kept as they were.
pub fn take_from_request(headers: &mut HeaderMap) -> Option<String> {
    let values: Vec<String> = headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_owned)
        .collect();
    if values.is_empty() {
        return None;
    }
    let mut found = None;
    let mut kept = Vec::new();
    for value in &values {
        for pair in value.split(';') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            match pair.split_once('=') {
                Some((name, id)) if name.trim() == COOKIE_NAME => {
                    if found.is_none() {
                        found = Some(id.trim().to_owned());
                    }
                }
                _ => kept.push(pair.to_owned()),
            }
        }
    }
    found.as_ref()?;
    headers.remove(COOKIE);
    if !kept.is_empty()
        && let Ok(value) = HeaderValue::from_str(&kept.join("; "))
    {
        headers.insert(COOKIE, value);
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn takes_the_ticket_and_keeps_other_cookies() {
        let mut headers = HeaderMap::new();
        headers.append(
            COOKIE,
            HeaderValue::from_static("a=1; radius_ticket=abc; b=2"),
        );
        headers.append(COOKIE, HeaderValue::from_static("c=3"));
        assert_eq!(take_from_request(&mut headers).as_deref(), Some("abc"));
        assert_eq!(headers[COOKIE], "a=1; b=2; c=3");

        let mut only = HeaderMap::new();
        only.insert(COOKIE, HeaderValue::from_static("radius_ticket=x"));
        assert_eq!(take_from_request(&mut only).as_deref(), Some("x"));
        assert!(!only.contains_key(COOKIE));

        let mut none = HeaderMap::new();
        none.insert(COOKIE, HeaderValue::from_static("a=1"));
        assert_eq!(take_from_request(&mut none), None);
        assert_eq!(none[COOKIE], "a=1");
    }

    #[test]
    fn cookies_are_well_formed() {
        assert_eq!(
            set_cookie("abc", "/paid/x", Duration::from_secs(60), true),
            "radius_ticket=abc; Path=/paid/x; Max-Age=60; HttpOnly; SameSite=Strict; Secure"
        );
        assert_eq!(
            clear_cookie("/", false),
            "radius_ticket=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"
        );
        assert_eq!(cookie_path("/paid/x"), "/paid/x");
        assert_eq!(cookie_path("/a;b"), "/");
        assert_eq!(cookie_path("/caf\u{e9}"), "/");
        assert_eq!(normalized_method(&Method::HEAD), "GET");
        assert_eq!(normalized_method(&Method::POST), "OTHER");
        assert_eq!(new_id().len(), 32);
        assert_ne!(new_id(), new_id());
    }
}
