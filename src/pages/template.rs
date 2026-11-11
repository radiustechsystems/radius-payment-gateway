//! `{{name}}` substitution for the pages. A text value is HTML-escaped on the way in; a raw value
//! is inserted as given, for markup the gateway built itself or a JSON block already made safe
//! for a `<script>` element. Unknown placeholders render empty.

use std::collections::HashMap;

pub enum Value {
    Text(String),
    Raw(String),
}

pub type Vars<'a> = HashMap<&'a str, Value>;

/// Escapes text for an HTML element or a double-quoted attribute.
pub fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Makes JSON safe inside `<script type="application/json">`: the only sequences that can end
/// or alter the script element are `</` and `<!--`, and JSON parses them back unchanged.
pub fn escape_json_script(json: &str) -> String {
    json.replace("</", "<\\/").replace("<!--", "<\\!--")
}

pub fn render(template: &str, vars: &Vars<'_>) -> String {
    let mut out = String::with_capacity(template.len() + 256);
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            out.push_str(&rest[start..]);
            return out;
        };
        let name = after[..end].trim();
        match vars.get(name) {
            Some(Value::Text(text)) => out.push_str(&escape_html(text)),
            Some(Value::Raw(raw)) => out.push_str(raw),
            None => {}
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out
}

/// The placeholder names a template uses.
pub fn placeholders(template: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else { break };
        let name = after[..end].trim().to_owned();
        if !names.contains(&name) {
            names.push(name);
        }
        rest = &after[end + 2..];
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitutes_escaping_text_and_passing_raw() {
        let mut vars = Vars::new();
        vars.insert("name", Value::Text("<b>&\"'".into()));
        vars.insert("html", Value::Raw("<p>ok</p>".into()));
        assert_eq!(
            render("a {{name}} b {{ html }} c {{missing}} d {{broken", &vars),
            "a &lt;b&gt;&amp;&quot;&#39; b <p>ok</p> c  d {{broken"
        );
        assert_eq!(placeholders("{{a}} {{ b }} {{a}}"), ["a", "b"]);
    }

    #[test]
    fn json_cant_close_the_script() {
        assert_eq!(
            escape_json_script(r#"{"d":"</script><!-- x"}"#),
            r#"{"d":"<\/script><\!-- x"}"#
        );
    }
}
