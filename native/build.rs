//! The image's clock floor (spec 13, *Hosted and Native*, N6).
//!
//! A Native node keeps no audit log across boots, so it has no audited event
//! to anchor its clock to. The next best floor is when its source was
//! committed: a board clock earlier than that is wrong (a dead RTC battery, or
//! a clock set back to revive expired tokens). The floor is
//! `SOURCE_DATE_EPOCH` if set (reproducible builds), otherwise the commit time
//! of `HEAD`, minus one day of tolerance for a committer's skewed clock. It
//! never comes from the build machine's clock, so the image stays reproducible.

use std::process::Command;

const TOLERANCE_S: u64 = 24 * 60 * 60;

fn git(dir: &str, args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).current_dir(dir).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    // a new commit moves the floor; a stale floor is still a valid (older) one
    for path in ["HEAD", "logs/HEAD"].iter().filter_map(|p| git(&dir, &["rev-parse", "--git-path", p])) {
        println!("cargo:rerun-if-changed={}", std::path::Path::new(&dir).join(path).display());
    }

    let committed = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .or_else(|| git(&dir, &["log", "-1", "--format=%ct"]).and_then(|s| s.parse::<u64>().ok()));
    let floor_ms = match committed {
        Some(s) => s.saturating_sub(TOLERANCE_S) * 1000,
        None => {
            println!("cargo:warning=no SOURCE_DATE_EPOCH and no git history: the image has no clock floor");
            0
        }
    };
    println!("cargo:rustc-env=CHITALA_CLOCK_FLOOR_MS={floor_ms}");
}
