//! `chitala-mcp` — MCP stdio server acting as the Action Broker of one AI principal.
//!
//! ```text
//! chitala-mcp --config ./home/chitala.json --as ai:assistant
//! ```
//!
//! The token is read from `tokens/<kind>-<local>.token` next to the config (or
//! `--token`), on every call. Logs go to stderr; stdout is the MCP channel.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use chitala_mcp::{run_stdio, Broker, TokenSource};
use chitala_model::{EntityId, EntityKind};
use chitala_node::config::read_key;
use chitala_node::{now_ms, LoadedConfig, Requester};
use clap::Parser;

#[derive(Parser)]
#[command(name = "chitala-mcp", version, about = "Chitala AI Action Broker (MCP over stdio)")]
struct Args {
    /// Node config file.
    #[arg(long, env = "CHITALA_CONFIG", default_value = "chitala.json")]
    config: PathBuf,
    /// AI principal this broker acts for.
    #[arg(long = "as", default_value = "ai:assistant")]
    actor: String,
    /// Token file (base64). Defaults to tokens/<kind>-<local>.token.
    #[arg(long)]
    token: Option<PathBuf>,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let run = || -> Result<(), String> {
        let loaded = LoadedConfig::load(&args.config).map_err(|e| e.to_string())?;
        let actor = EntityId::parse(&args.actor).map_err(|e| e.to_string())?;
        if actor.kind() != EntityKind::Ai {
            return Err(format!("{actor} is not an AI principal; chitala-mcp only brokers for ai:* identities"));
        }
        let key = read_key(&loaded.key_file(&actor)).map_err(|e| e.to_string())?;
        let token = args.token.clone().unwrap_or_else(|| {
            loaded.base_dir.join("tokens").join(format!("{}-{}.token", actor.kind(), actor.local()))
        });
        let authority = loaded.authority_public_key().map_err(|e| e.to_string())?;
        let requester = Requester::new(actor.clone(), key, EntityId::parse("service:mcp-broker").expect("valid id"));
        let mut broker = Broker::new(
            loaded.client().map_err(|e| e.to_string())?,
            loaded.config.domain.clone(),
            requester,
            TokenSource::File(token.clone()),
            &authority,
            Box::new(now_ms),
        );
        eprintln!("chitala-mcp: broker for {actor}, token file {}", token.display());
        run_stdio(&mut broker).map_err(|e| e.to_string())
    };
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("chitala-mcp: {e}");
            ExitCode::FAILURE
        }
    }
}
