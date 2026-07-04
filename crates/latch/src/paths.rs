//! Filesystem discovery: the real `op`, the shim install location, and where
//! the shim sits relative to `op` on `PATH`.

use std::path::{Path, PathBuf};

/// `~/.latch/bin`, where `latch shim install` drops the `op` symlink.
pub fn shim_bin_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".latch").join("bin"))
}

/// True if `p` is a regular file with any execute bit set.
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(p) {
        Ok(m) => m.is_file() && (m.permissions().mode() & 0o111 != 0),
        Err(_) => false,
    }
}

/// The canonical path of this running binary, if resolvable.
fn own_binary() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
}

/// Locate the real `op`: the first `op` on `PATH` that is not our own shim.
///
/// The shim symlink canonicalises to this binary, so we skip any candidate
/// whose real path equals ours. This is what both the shim's exec fallback and
/// the daemon use to find the tool to run.
pub fn find_real_op() -> Option<PathBuf> {
    let own = own_binary();
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let cand = dir.join("op");
        if !is_executable(&cand) {
            continue;
        }
        if let (Some(own), Some(canon)) = (&own, cand.canonicalize().ok()) {
            if &canon == own {
                continue; // our own shim
            }
        }
        return Some(cand);
    }
    None
}

/// Where on `PATH` the shim and the real `op` first appear, as indices.
pub struct PathOrder {
    pub shim: Option<usize>,
    pub real_op: Option<usize>,
}

/// Walk `PATH` once, recording the first index that resolves to our shim and
/// the first that resolves to a real `op`.
pub fn path_order() -> PathOrder {
    let own = own_binary();
    let mut order = PathOrder {
        shim: None,
        real_op: None,
    };
    let path = match std::env::var_os("PATH") {
        Some(p) => p,
        None => return order,
    };
    for (i, dir) in std::env::split_paths(&path).enumerate() {
        let cand = dir.join("op");
        if !is_executable(&cand) {
            continue;
        }
        let is_shim = matches!(
            (&own, cand.canonicalize().ok()),
            (Some(own), Some(canon)) if &canon == own
        );
        if is_shim {
            order.shim.get_or_insert(i);
        } else {
            order.real_op.get_or_insert(i);
        }
    }
    order
}
