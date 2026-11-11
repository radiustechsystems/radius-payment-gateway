//! The pages the gateway serves itself: the payment page a browser gets on a 402, and its
//! assets. The built-in files ship inside the binary; a directory of files (`--pages-dir`)
//! overrides them one by one, and `--export-pages` writes the built-in ones out to start from.

pub mod negotiate;
pub mod template;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Context;
use bytes::Bytes;
use http::HeaderValue;
use sha2::{Digest, Sha256};

use template::{Value, Vars, escape_html};

/// Where the page's assets are served, before the policy sees the request. Reserved: an
/// upstream route under it can't be reached through the gateway.
pub const ASSETS_PREFIX: &str = "/_radius/assets";

const TEMPLATE: &str = "402.html";

/// The built-in files, by their path in a pages directory.
const DEFAULTS: &[(&str, &[u8])] = &[
    (TEMPLATE, include_bytes!("../../pages/402.html")),
    (
        "assets/style.css",
        include_bytes!("../../pages/assets/style.css"),
    ),
    ("assets/pay.js", include_bytes!("../../pages/assets/pay.js")),
];

/// The placeholders `402.html` may use.
pub const PLACEHOLDERS: &[&str] = &[
    "brand",
    "brand_url",
    "brand_html",
    "price",
    "amount",
    "asset_symbol",
    "description",
    "resource_url",
    "network_name",
    "pay_to",
    "error",
    "cli_command",
    "challenge_json",
    "options_html",
    "page_json",
    "assets_base",
];

/// One way to pay, as the page lists it.
#[derive(Debug, Clone)]
pub struct PageOption {
    /// Its index in the challenge's `accepts`.
    pub index: usize,
    pub amount: String,
    pub symbol: String,
    pub network_name: String,
    pub pay_to: String,
    /// Whether the page's script can pay it (EIP-3009 on an EVM network).
    pub payable: bool,
}

pub struct Asset {
    pub body: Bytes,
    pub content_type: &'static str,
    pub etag: HeaderValue,
}

/// What the payment page shows. Everything is escaped on render; `challenge_json` is the
/// challenge as JSON, made safe for its script block here.
#[derive(Debug, Clone)]
pub struct PageVars {
    pub brand: Option<String>,
    pub brand_url: Option<String>,
    pub price: String,
    pub amount: String,
    pub asset_symbol: String,
    pub description: String,
    pub resource_url: String,
    pub network_name: String,
    pub pay_to: String,
    pub error: String,
    pub cli_command: String,
    pub challenge_json: String,
    /// Every way to pay, in the challenge's order.
    pub options: Vec<PageOption>,
    /// What the page's script needs beyond the challenge (networks, balances to read), as JSON.
    pub page_json: String,
}

pub struct Pages {
    template: String,
    assets: HashMap<String, Asset>,
    assets_base: String,
}

impl Pages {
    /// The built-in files, with those under `dir` (if any) replacing them by relative path.
    /// `public_url` is where the gateway is reached, so the page can address its assets under
    /// a path prefix a proxy in front strips.
    pub fn load(dir: Option<&Path>, public_url: Option<&str>) -> anyhow::Result<Self> {
        let mut files: HashMap<String, Vec<u8>> = DEFAULTS
            .iter()
            .map(|(name, body)| ((*name).to_owned(), body.to_vec()))
            .collect();
        if let Some(dir) = dir {
            if !dir.is_dir() {
                anyhow::bail!("--pages-dir {}: not a directory", dir.display());
            }
            let mut found = Vec::new();
            walk(dir, dir, &mut found)?;
            for (relative, path) in found {
                if relative != TEMPLATE && !relative.starts_with("assets/") {
                    tracing::warn!(
                        file = relative,
                        "pages dir: ignored (not 402.html or under assets/)"
                    );
                    continue;
                }
                let body =
                    std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
                files.insert(relative, body);
            }
        }
        let template = String::from_utf8(files.remove(TEMPLATE).expect("the default exists"))
            .context("402.html isn't UTF-8")?;
        for name in template::placeholders(&template) {
            if !PLACEHOLDERS.contains(&name.as_str()) {
                tracing::warn!(
                    placeholder = name,
                    "402.html uses a placeholder the gateway doesn't fill"
                );
            }
        }
        let assets = files
            .into_iter()
            .map(|(name, body)| {
                let asset = Asset {
                    content_type: content_type(&name),
                    etag: etag(&body),
                    body: Bytes::from(body),
                };
                (name, asset)
            })
            .collect();
        let assets_base = match public_url {
            Some(base) => format!("{}{ASSETS_PREFIX}", base.trim_end_matches('/')),
            None => ASSETS_PREFIX.to_owned(),
        };
        Ok(Self {
            template,
            assets,
            assets_base,
        })
    }

    /// Writes the built-in files under `dir`, creating it; refuses to overwrite a file.
    pub fn export(dir: &Path) -> anyhow::Result<usize> {
        for (name, _) in DEFAULTS {
            let path = dir.join(name);
            if path.exists() {
                anyhow::bail!("{} exists; not overwriting", path.display());
            }
        }
        for (name, body) in DEFAULTS {
            let path = dir.join(name);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            std::fs::write(&path, body).with_context(|| format!("writing {}", path.display()))?;
        }
        Ok(DEFAULTS.len())
    }

    /// The absolute or root-relative base the page addresses its assets at.
    pub fn assets_base(&self) -> &str {
        &self.assets_base
    }

    pub fn render_402(&self, vars: &PageVars) -> String {
        let brand_html = match (&vars.brand, &vars.brand_url) {
            (Some(brand), Some(url)) => format!(
                r#"<p class="brand"><a href="{}" rel="noopener">{}</a></p>"#,
                escape_html(url),
                escape_html(brand)
            ),
            (Some(brand), None) => format!(r#"<p class="brand">{}</p>"#, escape_html(brand)),
            (None, _) => String::new(),
        };
        let text = |value: &str| Value::Text(value.to_owned());
        let mut map = Vars::new();
        map.insert("brand", text(vars.brand.as_deref().unwrap_or_default()));
        map.insert(
            "brand_url",
            text(vars.brand_url.as_deref().unwrap_or_default()),
        );
        map.insert("brand_html", Value::Raw(brand_html));
        map.insert("price", text(&vars.price));
        map.insert("amount", text(&vars.amount));
        map.insert("asset_symbol", text(&vars.asset_symbol));
        map.insert("description", text(&vars.description));
        map.insert("resource_url", text(&vars.resource_url));
        map.insert("network_name", text(&vars.network_name));
        map.insert("pay_to", text(&vars.pay_to));
        map.insert("error", text(&vars.error));
        map.insert("cli_command", text(&vars.cli_command));
        map.insert(
            "challenge_json",
            Value::Raw(template::escape_json_script(&vars.challenge_json)),
        );
        map.insert("options_html", Value::Raw(options_html(&vars.options)));
        map.insert(
            "page_json",
            Value::Raw(template::escape_json_script(&vars.page_json)),
        );
        map.insert("assets_base", text(&self.assets_base));
        template::render(&self.template, &map)
    }

    /// An asset by its path under `assets/`, e.g. `style.css`.
    pub fn asset(&self, relative: &str) -> Option<&Asset> {
        self.assets.get(&format!("assets/{relative}"))
    }
}

/// The ways to pay as a radio group: the first the script can pay is selected, the others it
/// can't are listed but disabled. The script fills in balances once a wallet is connected.
fn options_html(options: &[PageOption]) -> String {
    let first_payable = options.iter().position(|option| option.payable);
    let mut html =
        String::from(r#"<div class="options" role="radiogroup" aria-label="Ways to pay">"#);
    for (position, option) in options.iter().enumerate() {
        let checked = first_payable == Some(position);
        let short = if option.pay_to.len() > 12 {
            format!(
                "{}…{}",
                &option.pay_to[..6],
                &option.pay_to[option.pay_to.len() - 4..]
            )
        } else {
            option.pay_to.clone()
        };
        html.push_str(&format!(
            concat!(
                r#"<label class="option-card{disabled}" data-index="{index}">"#,
                r#"<input type="radio" name="option" value="{index}"{checked}{disabled_attr}>"#,
                r#"<span class="option-main"><span class="option-amount">{amount} {symbol}</span>"#,
                r#"<span class="option-network">on {network}</span></span>"#,
                r#"<span class="option-side"><span class="balance" data-index="{index}"></span>"#,
                r#"<span class="option-note">{note}</span></span>"#,
                r#"<span class="option-to">to <code title="{pay_to}">{short}</code></span>"#,
                "</label>"
            ),
            index = option.index,
            disabled = if option.payable { "" } else { " disabled" },
            disabled_attr = if option.payable { "" } else { " disabled" },
            checked = if checked { " checked" } else { "" },
            amount = escape_html(&option.amount),
            symbol = escape_html(&option.symbol),
            network = escape_html(&option.network_name),
            note = if option.payable { "" } else { "terminal only" },
            pay_to = escape_html(&option.pay_to),
            short = escape_html(&short),
        ));
    }
    html.push_str("</div>");
    html
}

/// Every regular file under `root`, as (relative path with `/`, path).
fn walk(root: &Path, dir: &Path, found: &mut Vec<(String, PathBuf)>) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            walk(root, &path, found)?;
        } else if path.is_file() {
            let relative = path
                .strip_prefix(root)
                .expect("under root")
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            found.push((relative, path));
        }
    }
    Ok(())
}

fn content_type(name: &str) -> &'static str {
    match name.rsplit('.').next().unwrap_or_default() {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn etag(body: &[u8]) -> HeaderValue {
    let digest = Sha256::digest(body);
    let hex: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    HeaderValue::from_str(&format!("\"{hex}\"")).expect("hex is a valid header value")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars() -> PageVars {
        PageVars {
            brand: Some("Acme <API>".into()),
            brand_url: Some("https://acme.example/?a=1&b=2".into()),
            price: "0.01 SBC".into(),
            amount: "0.01".into(),
            asset_symbol: "SBC".into(),
            description: "Reports <b>per call</b>".into(),
            resource_url: "https://api.example.com/paid/x?q=\"1\"".into(),
            network_name: "Radius Testnet".into(),
            pay_to: "0x4373dD700774F8C3f649AC58B7EDCC112785Fe6e".into(),
            error: String::new(),
            cli_command:
                "radius-cli wallet pay get 'https://api.example.com/paid/x' --threshold 0.01 -y"
                    .into(),
            challenge_json: r#"{"resource":{"description":"</script>"}}"#.into(),
            options: vec![
                PageOption {
                    index: 0,
                    amount: "0.01".into(),
                    symbol: "SBC".into(),
                    network_name: "Radius Testnet".into(),
                    pay_to: "0x4373dD700774F8C3f649AC58B7EDCC112785Fe6e".into(),
                    payable: true,
                },
                PageOption {
                    index: 1,
                    amount: "0.01".into(),
                    symbol: "USDC".into(),
                    network_name: "Base <Sepolia>".into(),
                    pay_to: "0x4373dD700774F8C3f649AC58B7EDCC112785Fe6e".into(),
                    payable: false,
                },
            ],
            page_json: r#"{"options":[]}"#.into(),
        }
    }

    #[test]
    fn renders_the_default_page_escaped() {
        let pages = Pages::load(None, Some("https://example.com/api/")).unwrap();
        let html = pages.render_402(&vars());
        assert!(html.contains(
            r#"<a href="https://acme.example/?a=1&amp;b=2" rel="noopener">Acme &lt;API&gt;</a>"#
        ));
        assert!(html.contains("Reports &lt;b&gt;per call&lt;/b&gt;"));
        assert!(html.contains("https://api.example.com/paid/x?q=&quot;1&quot;"));
        assert!(html.contains(r#"{"resource":{"description":"<\/script>"}}"#));
        assert!(html.contains("https://example.com/api/_radius/assets/style.css"));
        assert!(html.contains(r#"<input type="radio" name="option" value="0" checked>"#));
        assert!(html.contains(r#"<input type="radio" name="option" value="1" disabled>"#));
        assert!(html.contains("on Base &lt;Sepolia&gt;"));
        assert!(html.contains("terminal only"));
        assert!(html.contains(
            r#"<code title="0x4373dD700774F8C3f649AC58B7EDCC112785Fe6e">0x4373…Fe6e</code>"#
        ));
        assert!(html.contains(r#"id="x402-page">{"options":[]}</script>"#));
        assert!(!html.contains("{{"));
        assert!(pages.asset("style.css").is_some());
        assert!(pages.asset("pay.js").is_some());
        assert!(pages.asset("../402.html").is_none());
    }

    #[test]
    fn brand_is_optional() {
        let pages = Pages::load(None, None).unwrap();
        let html = pages.render_402(&PageVars {
            brand: None,
            brand_url: None,
            ..vars()
        });
        assert!(!html.contains("class=\"brand\""));
        assert!(html.contains("href=\"/_radius/assets/style.css\""));
    }

    #[test]
    fn content_types_and_etags() {
        assert_eq!(content_type("assets/style.css"), "text/css; charset=utf-8");
        assert_eq!(content_type("assets/logo.svg"), "image/svg+xml");
        assert_eq!(content_type("assets/x.bin"), "application/octet-stream");
        assert_eq!(etag(b"a"), etag(b"a"));
        assert_ne!(etag(b"a"), etag(b"b"));
    }
}
