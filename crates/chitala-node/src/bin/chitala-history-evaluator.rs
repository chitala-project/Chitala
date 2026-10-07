//! `chitala-history-evaluator`: the history evaluator, in its own process
//! (spec 32). Outside the Trusted Core, but a safety-relevant trusted
//! dependency for the history rules it evaluates.
//!
//! Started by the node with exactly this environment, nothing inherited:
//!
//! - `CHITALA_HISTORY_KEYS`: the domain directory whose key store holds its
//!   signing key;
//! - `CHITALA_HISTORY_LOG`: the history log, read only;
//! - `CHITALA_HISTORY_ID`: its principal.
//!
//! It reads the log and nothing else, writes nothing, and answers one
//! request per line (`chitala_node::history_eval`).

#![forbid(unsafe_code)]

use std::io::{BufRead, Write};
use std::path::Path;
use std::sync::Arc;

use chitala_history::eval::{EvalRequest, Evaluator};
use chitala_identity::Keypair;
use chitala_model::EntityId;
use chitala_platform::{SecureKeyStore, SoftwareKeyStore, StoragePath};
use chitala_platform_host::{FsStorage, OsEntropy};
use serde_json::json;

fn setup() -> Result<(Evaluator, FsStorage, StoragePath), String> {
    let var = |k: &str| std::env::var(k).map_err(|_| format!("{k} is not set"));
    let id = EntityId::parse(&var("CHITALA_HISTORY_ID")?).map_err(|e| e.to_string())?;
    let keys_root = FsStorage::new(Path::new(&var("CHITALA_HISTORY_KEYS")?)).map_err(|e| e.to_string())?;
    let keys = SoftwareKeyStore::new(
        Arc::new(keys_root),
        Arc::new(OsEntropy),
        StoragePath::new(chitala_platform_host::KEYS_DIR).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let key_ref = chitala_node::config::key_ref(&id).map_err(|e| e.to_string())?;
    let seed = keys.export_seed(&key_ref).map_err(|e| format!("{id}'s key: {e}"))?;
    let log = var("CHITALA_HISTORY_LOG")?;
    let log = Path::new(&log);
    let dir = log.parent().ok_or("the log has no directory")?;
    let name = log.file_name().and_then(|n| n.to_str()).ok_or("the log has no name")?;
    let storage = FsStorage::new(dir).map_err(|e| e.to_string())?;
    let path = StoragePath::new(name).map_err(|e| e.to_string())?;
    Ok((Evaluator::new(id, env!("CARGO_PKG_VERSION"), Keypair::from_seed(&seed)), storage, path))
}

fn main() -> std::process::ExitCode {
    let (evaluator, storage, path) = match setup() {
        Ok(s) => s,
        Err(why) => {
            eprintln!("chitala-history-evaluator: {why}");
            return std::process::ExitCode::from(2);
        }
    };
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let hello = json!({"hello": {"protocol": chitala_node::history_eval::EVAL_PROTOCOL, "evaluator": evaluator.id.to_string()}});
    if writeln!(out, "{hello}").and_then(|()| out.flush()).is_err() {
        return std::process::ExitCode::from(1);
    }
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        let answer = match serde_json::from_str::<EvalRequest>(&line) {
            Ok(req) => match chitala_history::log::read_chained(&storage, &path) {
                Ok(log) => json!({"ok": evaluator.evaluate(&req, &log)}),
                Err(why) => json!({"error": format!("the history log: {why}")}),
            },
            Err(e) => json!({"error": format!("not a request: {e}")}),
        };
        if writeln!(out, "{answer}").and_then(|()| out.flush()).is_err() {
            break;
        }
    }
    std::process::ExitCode::SUCCESS
}
