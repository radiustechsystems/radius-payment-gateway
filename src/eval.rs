//! From an HTTP request to the evaluator's view of it, and from the evaluator's steps to a
//! decision, counting with the gate's store in between.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use http::Request;
use policy::Compiled;
use policy::eval::{self, Decision, Step};

use crate::counters::CounterStore;

/// What the evaluator sees of the request. HEAD is evaluated as GET: it's GET without the body,
/// and the evaluator only matches GET, POST, PUT, PATCH and DELETE against an endpoint's methods,
/// which would let an unpaid HEAD through. The path is as the client sent it: the gate standard
/// says gates don't normalize.
pub fn describe(request: &Request<Body>, compiled: &Compiled, peer: SocketAddr) -> eval::Request {
    let method = request.method().as_str().to_ascii_uppercase();
    let method = if method == "HEAD" {
        "GET".to_owned()
    } else {
        method
    };
    let headers = request.headers();
    let client_ip = eval::client_ip(
        compiled,
        |name| headers.get(name).and_then(|value| value.to_str().ok()),
        Some(peer.ip()),
    );
    eval::Request {
        method,
        path: request.uri().path().to_owned(),
        client_ip,
        caller: None,
        agent: None,
        now: now_unix(),
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// Selects the rule, counts the request against its limits, and decides.
pub async fn evaluate(
    compiled: &Compiled,
    request: &eval::Request,
    counters: &dyn CounterStore,
) -> Decision {
    match eval::select(compiled, request) {
        Step::Done(decision) => decision,
        Step::Count(counted) => {
            let mut counts = Vec::with_capacity(counted.counters.len());
            for counter in &counted.counters {
                let ttl = std::time::Duration::from_secs(counter.reset_s);
                counts.push(counters.increment(&counter.key, ttl).await);
            }
            eval::decide(compiled, &counted, &counts)
        }
    }
}

/// The id of the rule `select` would apply, or none for an unmatched request.
fn selected_rule(compiled: &Compiled, request: &eval::Request) -> Option<String> {
    match eval::select(compiled, request) {
        Step::Done(decision) => decision.rule,
        Step::Count(counted) => Some(counted.rule.id.clone()),
    }
}

/// Whether percent-decoding the path, as the upstream's router may, would route the request to a
/// different rule than the raw path selects. Such a request is refused rather than forwarded: its
/// handler would run under a rule that doesn't apply to it (`GET /hell%6F` for a paid `/hello`).
/// An encoded parameter value that stays on its rule (`/files/caf%C3%A9`) is unaffected.
pub fn ambiguous_path(compiled: &Compiled, request: &eval::Request) -> bool {
    if !request.path.contains('%') {
        return false;
    }
    let decoded = decode_path(&request.path);
    if decoded == request.path {
        return false;
    }
    let routed = eval::Request {
        path: decoded,
        ..request.clone()
    };
    selected_rule(compiled, request) != selected_rule(compiled, &routed)
}

/// Characters `decodeURI` leaves encoded: the reserved set, `#`, and `%` itself.
const KEPT_ENCODED: &[u8] = b";/?:@&=+$,#%";

/// The path as a router that decodes it would see it: each run of `%XX` sequences is decoded
/// when it's valid UTF-8 and spells no reserved character; otherwise it's left as it is.
fn decode_path(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut out = String::with_capacity(path.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            // Advance one char.
            let ch = path[i..].chars().next().expect("in bounds");
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        // A run of %XX sequences.
        let start = i;
        let mut decoded = Vec::new();
        while i + 2 < bytes.len() && bytes[i] == b'%' {
            let Some(byte) = hex_pair(bytes.get(i + 1).copied(), bytes.get(i + 2).copied()) else {
                break;
            };
            decoded.push(byte);
            i += 3;
        }
        let run = &path[start..i];
        if run.is_empty() {
            // A lone `%` without two hex digits: keep it.
            out.push('%');
            i += 1;
            continue;
        }
        match std::str::from_utf8(&decoded) {
            Ok(text) if !text.bytes().any(|b| KEPT_ENCODED.contains(&b)) => out.push_str(text),
            _ => out.push_str(run),
        }
    }
    out
}

fn hex_pair(a: Option<u8>, b: Option<u8>) -> Option<u8> {
    let hi = (a? as char).to_digit(16)?;
    let lo = (b? as char).to_digit(16)?;
    Some((hi * 16 + lo) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_like_a_router_would() {
        assert_eq!(decode_path("/hell%6F"), "/hello");
        assert_eq!(decode_path("/files/caf%C3%A9"), "/files/café");
        assert_eq!(decode_path("/a%2Fb"), "/a%2Fb");
        assert_eq!(decode_path("/a%25b"), "/a%25b");
        assert_eq!(decode_path("/bad%ZZ"), "/bad%ZZ");
        assert_eq!(decode_path("/trailing%"), "/trailing%");
        assert_eq!(decode_path("/x%C3"), "/x%C3");
        assert_eq!(decode_path("/plain"), "/plain");
    }
}
