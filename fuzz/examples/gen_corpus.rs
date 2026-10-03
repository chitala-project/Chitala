//! Write the deterministic seed corpus to `fuzz/corpus/<target>/`.
//!
//!   cargo run --manifest-path fuzz/Cargo.toml --example gen_corpus

use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("corpus");
    for target in chitala_fuzz::TARGETS {
        let dir = root.join(target);
        std::fs::create_dir_all(&dir)?;
        for (i, seed) in chitala_fuzz::seeds(target).iter().enumerate() {
            std::fs::write(dir.join(format!("seed-{i:02}")), seed)?;
        }
        println!("{target}: {} seeds", chitala_fuzz::seeds(target).len());
    }
    Ok(())
}
