//! Stamps the binary with the git commit it was built from, so a running gateway can say which
//! code it is (`--version`, the startup log, the admin `/policy` answer, the payment page).
//! `RADIUS_GATEWAY_COMMIT` in the environment wins, for builds without a checkout.

use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=RADIUS_GATEWAY_COMMIT");
    let commit = std::env::var("RADIUS_GATEWAY_COMMIT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| git_commit().unwrap_or_else(|| "unknown".to_owned()));
    println!("cargo:rustc-env=RADIUS_GATEWAY_COMMIT={commit}");
}

/// `<short hash>`, with `-dirty` when the tree has uncommitted changes.
fn git_commit() -> Option<String> {
    // Rebuild when the branch moves.
    if let Ok(head) = std::fs::read_to_string(".git/HEAD") {
        println!("cargo:rerun-if-changed=.git/HEAD");
        if let Some(reference) = head.trim().strip_prefix("ref: ") {
            let path = Path::new(".git").join(reference);
            if path.exists() {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }
    let output = Command::new("git")
        .args(["rev-parse", "--short=9", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let hash = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    if hash.is_empty() {
        return None;
    }
    let dirty = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .ok()
        .is_some_and(|status| !status.stdout.is_empty());
    Some(if dirty { format!("{hash}-dirty") } else { hash })
}
