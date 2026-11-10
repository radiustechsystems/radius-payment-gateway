//! Error responses: `{ "code": "...", "message": "..." }` as JSON, the shape the gate standard
//! gives denials (section 5).

use axum::Json;
use axum::response::{IntoResponse, Response};
use http::StatusCode;
use http::header::CACHE_CONTROL;
use serde::Serialize;

#[derive(Serialize)]
struct Body<'a> {
    code: &'a str,
    message: &'a str,
}

/// A JSON error response.
pub fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    (status, Json(Body { code, message })).into_response()
}

/// A JSON error response that caches must not keep.
pub fn uncacheable_error(status: StatusCode, code: &str, message: &str) -> Response {
    let mut response = error_response(status, code, message);
    response.headers_mut().insert(
        CACHE_CONTROL,
        "no-store".parse().expect("valid header value"),
    );
    response
}
