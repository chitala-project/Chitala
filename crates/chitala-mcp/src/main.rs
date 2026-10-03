//! `chitala-mcp` — MCP stdio server acting as the Action Broker of one AI principal.
//!
//! ```text
//! chitala-mcp --config ./home/chitala.json --as ai:assistant [--for person:alice]
//! ```
//!
//! The person the AI acts for defaults to the first one its enrollment
//! declares (`serves` in the config); the node checks it on every intent.
//!
//! The token is read from `tokens/<kind>-<local>.token` next to the config (or
//! `--token`), on every call. Logs go to stderr; stdout is the MCP channel.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use chitala_mcp::{run_stdio, Agent, Broker, TokenSource};
use chitala_model::{EntityId, EntityKind};
use chitala_node::hosted::now_ms;
use chitala_node::LoadedConfig;
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
    /// Person the AI acts for. Defaults to the first person it serves.
    #[arg(long = "for")]
    on_behalf_of: Option<String>,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let run = || -> Result<(), String> {
        let loaded = LoadedConfig::load(&args.config).map_err(|e| e.to_string())?;
        let actor = EntityId::parse(&args.actor).map_err(|e| e.to_string())?;
        if actor.kind() != EntityKind::Ai {
            return Err(format!("{actor} is not an AI principal; chitala-mcp only brokers for ai:* identities"));
        }
        let key = loaded.keypair(&actor).map_err(|e| e.to_string())?;
        let token = args.token.clone().unwrap_or_else(|| loaded.token_file(&actor));
        let authority = loaded.authority_public_key().map_err(|e| e.to_string())?;
        let declared = loaded.config.principals.iter().find(|p| p.id == actor).map(|p| p.serves.clone());
        let on_behalf_of = match &args.on_behalf_of {
            Some(p) => EntityId::parse(p).map_err(|e| e.to_string())?,
            None => declared.and_then(|s| s.into_iter().next()).ok_or_else(|| {
                format!("{actor} serves nobody in this domain; add `serves` to its principal entry or pass --for")
            })?,
        };
        let agent = Agent::new(actor.clone(), key, on_behalf_of.clone());
        let mut broker = Broker::new(
            loaded.client().map_err(|e| e.to_string())?,
            loaded.config.domain.clone(),
            agent,
            TokenSource::File(token.clone()),
            &authority,
            Box::new(now_ms),
        );
        eprintln!("chitala-mcp: broker for {actor} acting for {on_behalf_of}, token file {}", token.display());
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
