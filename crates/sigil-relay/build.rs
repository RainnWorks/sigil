// Bakes the current git commit into the binary for GET /version (ops
// convenience only; nothing security-load-bearing rests on it). Best-effort: if
// git is unavailable, /version reports "unknown".

use std::process::Command;

fn main() {
    let commit = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=GIT_COMMIT={commit}");
    // Re-run if HEAD moves.
    println!("cargo:rerun-if-changed=../../.git/HEAD");
}
