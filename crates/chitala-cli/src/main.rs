//! `chitala` — command-line tool for a Chitala domain.
//!
//! ```text
//! chitala demo                                   # milestone 0.0.1/0.0.2 in memory
//! chitala init ./home                            # sample domain with virtual devices
//! chitala --config ./home/chitala.json node      # run the Home Node (Unix socket)
//! chitala --config ./home/chitala.json invoke --as person:alice device:living-room-light light.turn_on
//! chitala --config ./home/chitala.json delegate --as person:alice --to ai:assistant device:living-room-light light.turn_on --ttl 600
//! ```
//!
//! Exit codes: 0 allowed and executed, 1 allowed but execution failed,
//! 2 denied by the Reference Monitor, 3 usage/connection error.

#![forbid(unsafe_code)]

mod demo;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use chitala_audit::verify_file;
use chitala_model::{payload, CapabilityId, CapabilityRegistry, EntityId, ParamValue, Payload};
use chitala_node::config::{key_file_name, read_key};
use chitala_node::{node_from_config, now_ms, LoadedConfig, Requester, Response, Submit};
use chitala_token::{bytes_from_base64, TokenVerifier};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "chitala", version, about = "Chitala OS — trusted core v0.0.x")]
struct Cli {
    /// Node config file.
    #[arg(long, global = true, env = "CHITALA_CONFIG", default_value = "chitala.json")]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the milestone 0.0.1/0.0.2 scenario in memory and explain each step.
    Demo,
    /// Create a sample domain (keys, config, four virtual devices) in DIR.
    Init { dir: PathBuf },
    /// Run the Home Node on the configured Unix socket.
    Node,
    /// Show what the node announces before authentication.
    Hello,
    /// List the core capability registry.
    Registry,
    /// Request a capability: PARAMS are name=value (true/false, integers, text).
    Invoke {
        #[arg(long = "as")]
        actor: String,
        target: String,
        capability: String,
        params: Vec<String>,
        /// Capability token file (base64).
        #[arg(long)]
        token: Option<PathBuf>,
    },
    /// Read a device's twin state (device.read_state).
    State {
        #[arg(long = "as")]
        actor: String,
        target: String,
        #[arg(long)]
        token: Option<PathBuf>,
    },
    /// List the domain's devices (domain.list_devices).
    Devices {
        #[arg(long = "as")]
        actor: String,
    },
    /// Delegate one capability on one target to another principal.
    Delegate {
        #[arg(long = "as")]
        actor: String,
        #[arg(long)]
        to: String,
        target: String,
        capability: String,
        /// Lifetime in seconds.
        #[arg(long, default_value_t = 600)]
        ttl: i64,
        /// Re-delegate from a token you hold (base64 file).
        #[arg(long)]
        parent: Option<PathBuf>,
        /// Where to write the token; defaults to tokens/<holder>.token.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Revoke a token (and every token delegated from it).
    Revoke {
        #[arg(long = "as")]
        actor: String,
        revocation_id: String,
    },
    /// Move a principal in the security state machine.
    SetState {
        #[arg(long = "as")]
        actor: String,
        principal: String,
        state: String,
    },
    /// Capability token tools.
    Token {
        #[command(subcommand)]
        cmd: TokenCmd,
    },
    /// Audit log tools.
    Audit {
        #[command(subcommand)]
        cmd: AuditCmd,
    },
}

#[derive(Subcommand)]
enum TokenCmd {
    /// Verify a token against the domain authority key and print it.
    Inspect { file: PathBuf },
}

#[derive(Subcommand)]
enum AuditCmd {
    /// Verify the hash chain and signed checkpoints.
    Verify { file: Option<PathBuf> },
}

struct Failure(u8, String);

impl<E: std::fmt::Display> From<E> for Failure {
    fn from(e: E) -> Self {
        Failure(3, e.to_string())
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => ExitCode::from(code),
        Err(Failure(code, msg)) => {
            eprintln!("chitala: {msg}");
            ExitCode::from(code)
        }
    }
}

fn parse_id(s: &str) -> Result<EntityId, Failure> {
    EntityId::parse(s).map_err(|e| Failure(3, e.to_string()))
}

fn parse_cap(s: &str) -> Result<CapabilityId, Failure> {
    CapabilityId::parse(s).map_err(|e| Failure(3, e.to_string()))
}

fn parse_params(items: &[String]) -> Result<Payload, Failure> {
    let mut p = Payload::new();
    for item in items {
        let (k, v) =
            item.split_once('=').ok_or_else(|| Failure(3, format!("parameter {item:?} must be name=value")))?;
        let value = match v {
            "true" => ParamValue::Bool(true),
            "false" => ParamValue::Bool(false),
            _ => v.parse::<i64>().map(ParamValue::Int).unwrap_or_else(|_| ParamValue::Text(v.to_string())),
        };
        p.insert(k.to_string(), value);
    }
    Ok(p)
}

fn read_token(path: &Path) -> Result<Vec<u8>, Failure> {
    let text = std::fs::read_to_string(path).map_err(|e| Failure(3, format!("{}: {e}", path.display())))?;
    bytes_from_base64(&text).map_err(|e| Failure(3, e.to_string()))
}

struct Ctx {
    loaded: LoadedConfig,
    registry: CapabilityRegistry,
}

impl Ctx {
    fn load(path: &Path) -> Result<Self, Failure> {
        Ok(Self { loaded: LoadedConfig::load(path)?, registry: CapabilityRegistry::core_v0_1() })
    }

    fn requester(&self, actor: &str, token: Option<&Path>) -> Result<Requester, Failure> {
        let actor = parse_id(actor)?;
        let key = read_key(&self.loaded.key_file(&actor))
            .map_err(|e| Failure(3, format!("{e} (keys of {actor} are not on this machine)")))?;
        let token = token.map(read_token).transpose()?;
        Ok(Requester::new(actor, key, parse_id("service:cli")?).with_token(token))
    }

    fn send(&self, r: &Requester, target: &EntityId, cap: &CapabilityId, pl: Payload) -> Result<Response, Failure> {
        let bytes = r.sign(&self.registry, target, cap, pl, now_ms());
        self.loaded.client()?.submit(&bytes).map_err(|e| Failure(3, e))
    }

    fn domain(&self) -> EntityId {
        self.loaded.config.domain.clone()
    }
}

fn report(r: &Response) -> u8 {
    println!("{}", r.summary());
    if let Some(res) = &r.result {
        println!("{}", serde_json::to_string_pretty(res).unwrap_or_default());
    }
    if let Some(seq) = r.audit_seq {
        println!("(audit #{seq})");
    }
    match (r.is_allow(), r.error.is_some()) {
        (true, false) => 0,
        (true, true) => 1,
        (false, _) => 2,
    }
}

fn run(cli: Cli) -> Result<u8, Failure> {
    match cli.cmd {
        Cmd::Demo => {
            demo::run().map_err(|e| Failure(3, e))?;
            Ok(0)
        }
        Cmd::Init { dir } => {
            let s = chitala_node::setup::init_domain(&dir)?;
            println!("Đã tạo domain mẫu: {}", s.config_path.display());
            for (id, roles) in &s.principals {
                println!("  principal {id:<20} roles {roles:?}");
            }
            for d in &s.devices {
                println!("  device    {d}");
            }
            println!("\nChạy node:   chitala --config {} node", s.config_path.display());
            println!(
                "Bật đèn:     chitala --config {} invoke --as person:alice device:living-room-light light.turn_on",
                s.config_path.display()
            );
            Ok(0)
        }
        Cmd::Node => {
            let loaded = LoadedConfig::load(&cli.config)?;
            let node = node_from_config(&loaded)?;
            let socket = loaded.socket()?;
            eprintln!(
                "chitala node: domain {} · {} devices · listening on {}",
                node.domain(),
                loaded.config.devices.len(),
                socket.display()
            );
            chitala_node::ipc::serve(Arc::new(Mutex::new(node)), &socket)?;
            Ok(0)
        }
        Cmd::Hello => {
            let ctx = Ctx::load(&cli.config)?;
            let v = ctx.loaded.client()?.hello().map_err(|e| Failure(3, e))?;
            println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            println!("(chữ ký node khớp node_public_key trong config)");
            Ok(0)
        }
        Cmd::Registry => {
            let reg = CapabilityRegistry::core_v0_1();
            println!("{} {}", reg.name(), reg.version());
            for d in reg.iter() {
                let params: Vec<String> = d.params.iter().map(|p| p.name.clone()).collect();
                println!(
                    "  {:<32} v{} {:<6} {:<8} {:?} {}",
                    d.id.as_str(),
                    d.version,
                    format!("{:?}", d.target).to_lowercase(),
                    d.risk.label(),
                    params,
                    d.description
                );
            }
            Ok(0)
        }
        Cmd::Invoke { actor, target, capability, params, token } => {
            let ctx = Ctx::load(&cli.config)?;
            let r = ctx.requester(&actor, token.as_deref())?;
            let resp = ctx.send(&r, &parse_id(&target)?, &parse_cap(&capability)?, parse_params(&params)?)?;
            Ok(report(&resp))
        }
        Cmd::State { actor, target, token } => {
            let ctx = Ctx::load(&cli.config)?;
            let r = ctx.requester(&actor, token.as_deref())?;
            let resp = ctx.send(&r, &parse_id(&target)?, &parse_cap("device.read_state")?, Payload::new())?;
            Ok(report(&resp))
        }
        Cmd::Devices { actor } => {
            let ctx = Ctx::load(&cli.config)?;
            let r = ctx.requester(&actor, None)?;
            let resp = ctx.send(&r, &ctx.domain(), &parse_cap("domain.list_devices")?, Payload::new())?;
            Ok(report(&resp))
        }
        Cmd::Delegate { actor, to, target, capability, ttl, parent, out } => {
            let ctx = Ctx::load(&cli.config)?;
            let r = ctx.requester(&actor, None)?;
            let holder = parse_id(&to)?;
            let mut pl = payload([
                ("holder", ParamValue::Text(holder.to_string())),
                ("target", ParamValue::Text(parse_id(&target)?.to_string())),
                ("capability", ParamValue::Text(parse_cap(&capability)?.to_string())),
                ("ttl_s", ParamValue::Int(ttl)),
            ]);
            if let Some(p) = parent {
                let text = std::fs::read_to_string(&p).map_err(|e| Failure(3, format!("{}: {e}", p.display())))?;
                pl.insert("parent_token".into(), ParamValue::Text(text.trim().to_string()));
            }
            let resp = ctx.send(&r, &ctx.domain(), &parse_cap("domain.delegate")?, pl)?;
            let code = report(&resp);
            if let Some(token) = resp.result.as_ref().and_then(|v| v["token"].as_str()) {
                let path = out.unwrap_or_else(|| {
                    ctx.loaded.base_dir.join("tokens").join(key_file_name(&holder).replace(".key", ".token"))
                });
                write_private(&path, &format!("{token}\n"))?;
                println!("token → {}", path.display());
            }
            Ok(code)
        }
        Cmd::Revoke { actor, revocation_id } => {
            let ctx = Ctx::load(&cli.config)?;
            let r = ctx.requester(&actor, None)?;
            let pl = payload([("revocation_id", ParamValue::Text(revocation_id))]);
            Ok(report(&ctx.send(&r, &ctx.domain(), &parse_cap("domain.revoke_token")?, pl)?))
        }
        Cmd::SetState { actor, principal, state } => {
            let ctx = Ctx::load(&cli.config)?;
            let r = ctx.requester(&actor, None)?;
            let pl = payload([("principal", ParamValue::Text(principal)), ("state", ParamValue::Text(state))]);
            Ok(report(&ctx.send(&r, &ctx.domain(), &parse_cap("domain.set_principal_state")?, pl)?))
        }
        Cmd::Token { cmd: TokenCmd::Inspect { file } } => {
            let ctx = Ctx::load(&cli.config)?;
            let bytes = read_token(&file)?;
            let v = TokenVerifier::new(&ctx.loaded.authority_public_key()?)
                .verify(&bytes)
                .map_err(|e| Failure(2, e.to_string()))?;
            let left = v.expires_at_ms.saturating_sub(now_ms()) / 1000;
            println!("holder        {}", v.holder);
            println!("issuer        {}", v.issuer);
            println!("depth         {}", v.depth);
            println!("expires_at_ms {} ({}s left)", v.expires_at_ms, left);
            println!("revocation_id {}", v.revocation_id);
            for r in &v.rights {
                println!("right         {r}");
            }
            println!("\n{}", v.print());
            Ok(0)
        }
        Cmd::Audit { cmd: AuditCmd::Verify { file } } => {
            let ctx = Ctx::load(&cli.config)?;
            let path = file.unwrap_or_else(|| ctx.loaded.path(&ctx.loaded.config.audit_log));
            // the verifier needs only the node's *public* key from the config:
            // it stays independent of the node being investigated (v16 §7)
            let node_pk = ctx.loaded.node_public_key()?;
            let trusted = HashMap::from([(chitala_identity::key_id_of(&node_pk), node_pk)]);
            let r = verify_file(&path, &trusted).map_err(|e| Failure(2, e.to_string()))?;
            println!("OK  {} records · {} checkpoints · head {}", r.records, r.checkpoints, &r.head[..16]);
            match r.last_signed_seq {
                Some(s) => println!(
                    "    signed up to #{s}; {} newer records not yet covered by a checkpoint",
                    r.unsigned_tail()
                ),
                None => println!("    no trusted checkpoint yet"),
            }
            Ok(0)
        }
    }
}

fn write_private(path: &Path, contents: &str) -> Result<(), Failure> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    use std::io::Write;
    opts.open(path)?.write_all(contents.as_bytes())?;
    Ok(())
}
