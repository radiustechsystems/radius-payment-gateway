//! Whether a client wants the HTML page or the JSON body on a 402, from its `Accept` header.

/// HTML for a client that asks for `text/html` (or `text/*`) at least as much as for
/// `application/json` (or `application/*`). `*/*` counts for neither, so curl, agents, SDKs and
/// radius-cli keep the JSON they parse today; browsers, which send `text/html,…,*/*;q=0.8`,
/// get the page.
pub fn prefers_html(accept: Option<&str>) -> bool {
    let Some(accept) = accept else {
        return false;
    };
    let mut html: f32 = 0.0;
    let mut json: f32 = 0.0;
    for element in accept.split(',') {
        let mut parts = element.split(';');
        let media = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
        let mut q: f32 = 1.0;
        for parameter in parts {
            let parameter = parameter.trim();
            if let Some(value) = parameter
                .strip_prefix("q=")
                .or_else(|| parameter.strip_prefix("Q="))
            {
                q = value.trim().parse().unwrap_or(1.0);
            }
        }
        let q = q.clamp(0.0, 1.0);
        match media.as_str() {
            "text/html" | "text/*" => html = html.max(q),
            "application/json" | "application/*" => json = json.max(q),
            _ => {}
        }
    }
    html > 0.0 && html >= json
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browsers_get_html_and_everyone_else_json() {
        for (accept, html) in [
            (
                Some("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
                true,
            ),
            (Some("text/*"), true),
            (Some("TEXT/HTML; q=0.9, application/json; q=0.5"), true),
            (Some("text/html;q=0.5, application/json"), false),
            (Some("text/html;q=0"), false),
            (Some("*/*"), false),
            (Some("application/json"), false),
            (Some(""), false),
            (None, false),
        ] {
            assert_eq!(prefers_html(accept), html, "{accept:?}");
        }
    }
}
