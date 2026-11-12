//! Making user text safe in pricing.md. Names come from sellers and the file goes to agents, so
//! a name must never add a heading, a list item, a link or HTML. Every value follows a fixed
//! prefix (`# `, `## `, `- Request: `), so escaping the characters below is enough.

/// Characters that start Markdown syntax anywhere in a line, backslash-escaped.
const MARKDOWN: &[char] = &['\\', '`', '*', '_', '[', ']', '|', '~', '#'];

/// `text` for a Markdown line: whitespace runs (newlines included) collapsed to one space and
/// trimmed, control characters dropped, `<`, `>` and `&` as entities, and the characters in
/// [`MARKDOWN`] backslash-escaped.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut space = false;
    for c in text.chars() {
        if c.is_whitespace() {
            space = !out.is_empty();
            continue;
        }
        if c.is_control() {
            continue;
        }
        if space {
            out.push(' ');
            space = false;
        }
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            c if MARKDOWN.contains(&c) => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out
}

/// `text` as an inline code span, fenced with one more backtick than its longest run of them,
/// and padded with a space when it starts or ends with one. Whitespace is collapsed and control
/// characters dropped as in [`escape`]; nothing else needs escaping inside a code span.
pub fn code_span(text: &str) -> String {
    let text: String = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    let longest = text.split(|c| c != '`').map(str::len).max().unwrap_or(0);
    let fence = "`".repeat(longest + 1);
    let pad = if text.starts_with('`') || text.ends_with('`') {
        " "
    } else {
        ""
    };
    format!("{fence}{pad}{text}{pad}{fence}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_passes_through() {
        assert_eq!(escape("Weather API"), "Weather API");
        assert_eq!(
            escape("Acme's forecast, v2.1 (beta)"),
            "Acme's forecast, v2.1 (beta)"
        );
    }

    #[test]
    fn markdown_syntax_is_escaped() {
        assert_eq!(escape("*bold* _it_"), r"\*bold\* \_it\_");
        assert_eq!(
            escape("[link](https://evil.example)"),
            r"\[link\](https://evil.example)"
        );
        assert_eq!(escape("a | b ~ c"), r"a \| b \~ c");
        assert_eq!(escape("C# and `code`"), r"C\# and \`code\`");
        assert_eq!(escape(r"back\slash"), r"back\\slash");
    }

    #[test]
    fn html_becomes_entities() {
        assert_eq!(
            escape("<script>alert(1)</script> & co"),
            "&lt;script&gt;alert(1)&lt;/script&gt; &amp; co"
        );
    }

    #[test]
    fn names_cannot_start_new_lines_or_blocks() {
        assert_eq!(
            escape("Forecast\n## Free stuff\n- Price: $0"),
            r"Forecast \#\# Free stuff - Price: $0"
        );
        assert_eq!(escape("  spaced \t out  "), "spaced out");
        assert_eq!(escape("bell\u{7}\u{0}x"), "bellx");
        assert_eq!(escape("\r\n\r\n"), "");
    }

    #[test]
    fn code_spans_fence_past_any_backticks() {
        assert_eq!(
            code_span("GET /v1/forecast/:city"),
            "`GET /v1/forecast/:city`"
        );
        assert_eq!(code_span("a`b"), "``a`b``");
        assert_eq!(code_span("a``b`c"), "```a``b`c```");
        assert_eq!(code_span("`edge"), "`` `edge ``");
        assert_eq!(code_span("two\nlines"), "`two lines`");
    }
}
