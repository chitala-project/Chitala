//! `chitala` — command-line tool for a Chitala domain.
//!
//! ```text
//! chitala demo                                   # milestone 0.0.1/0.0.2 in memory
//! chitala init ./home                            # sample domain with virtual devices
//! chitala --config ./home/chitala.json node      # run the Home Node (hosted: Unix socket)
//! chitala --config ./home/chitala.json invoke --as person:alice device:living-room-light light.turn_on
//! chitala --config ./home/chitala.json delegate --as person:alice --to ai:assistant resource:front-door lock.unlock --ttl 600
//! chitala --config ./home/chitala.json revoke-all --as person:alice ai:assistant   # lost phone: every token it holds
//! chitala --config ./home/chitala.json intent --as ai:assistant resource:front-door lock.unlock --purpose "plumber"
//! chitala --config ./home/chitala.json approvals --as person:alice
//! chitala --config ./home/chitala.json approve --as person:alice <intent-id>
//! ```
//!
//! Exit codes: 0 allowed and executed, 1 allowed but execution failed,
//! 2 denied, 3 usage/connection error, 4 escalated (waiting for a human).

#![forbid(unsafe_code)]

mod demo;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use chitala_intent::{new_intent_id, parse_id_hex, Approval, Intent, Verdict};
use chitala_model::{payload, CapabilityId, CapabilityRegistry, EntityId, ParamValue, Payload};
use chitala_node::hosted::now_ms;
use chitala_node::{LoadedConfig, Requester, Response, Submit};
use chitala_platform_host::OsEntropy;
use chitala_resource::ResourceId;
use chitala_token::{bytes_from_base64, TokenVerifier, VerifiedToken};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "chitala", version, about = "Chitala OS — trusted core")]
struct Cli {
    /// Node config file.
    #[arg(long, global = true, env = "CHITALA_CONFIG", default_value = "chitala.json")]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the Physical Authority Slice v0.1 in memory and explain each step.
    Demo,
    /// Create a sample domain (keys, config, four virtual devices) in DIR.
    Init { dir: PathBuf },
    /// List the lights, plugs and locks a Home Assistant has that the Home
    /// profile can drive, to help write the config. It changes nothing.
    HaDiscover {
        /// e.g. https://homeassistant.local:8123
        #[arg(long)]
        url: String,
        /// The environment variable that holds a long-lived access token.
        #[arg(long)]
        token_env: String,
        /// Allow plain http:// to a non-loopback host.
        #[arg(long)]
        allow_insecure_http: bool,
    },
    /// Run the Home Node on the configured endpoint (a Unix socket).
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
        /// Lifetime in seconds (from the start).
        #[arg(long, default_value_t = 600)]
        ttl: i64,
        /// Valid only from this many seconds from now.
        #[arg(long, default_value_t = 0)]
        start: i64,
        /// How many more times the holder may hand the right on (0: non-transferable).
        #[arg(long, default_value_t = 0)]
        redelegate: i64,
        /// For an AI holder: the person it may use the right for (default: you,
        /// if it serves you, else the one person it serves).
        #[arg(long = "for")]
        for_person: Option<String>,
        /// Re-delegate from a token you hold (base64 file).
        #[arg(long)]
        parent: Option<PathBuf>,
        /// Where to write the token; defaults to tokens/<holder>.token.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Submit an intent (what an AI does): ACTION on RESOURCE; PARAMS are name=value.
    Intent {
        #[arg(long = "as")]
        actor: String,
        /// The person it is for: yourself if you are a person, else the first person the AI serves.
        #[arg(long = "for")]
        on_behalf_of: Option<String>,
        resource: String,
        action: String,
        params: Vec<String>,
        /// Why (recorded for humans and audit; grants nothing).
        #[arg(long)]
        purpose: Option<String>,
        /// Token file, one base64 token per line; defaults to tokens/<actor>.token.
        #[arg(long)]
        token: Option<PathBuf>,
    },
    /// List the intents waiting for your decision.
    Approvals {
        #[arg(long = "as")]
        actor: String,
    },
    /// Answer an escalated intent (approve, or --reject).
    Approve {
        #[arg(long = "as")]
        actor: String,
        intent: String,
        #[arg(long)]
        reject: bool,
        #[arg(long)]
        note: Option<String>,
    },
    /// Revoke a token (and every token delegated from it).
    Revoke {
        #[arg(long = "as")]
        actor: String,
        revocation_id: String,
    },
    /// Revoke every token issued so far that PRINCIPAL holds, issued or passed
    /// on — or, without one, every token of the domain (owners and admins).
    RevokeAll {
        #[arg(long = "as")]
        actor: String,
        principal: Option<String>,
    },
    /// Put a safety hold on a resource (and everything in it): no action there
    /// until it is released, including orders already in flight.
    Hold {
        #[arg(long = "as")]
        actor: String,
        resource: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Release a resource: lift its safety hold and end its recovery.
    Release {
        #[arg(long = "as")]
        actor: String,
        resource: String,
    },
    /// List the plans you may see (all of them for owners and admins).
    Plans {
        #[arg(long = "as")]
        actor: String,
    },
    /// Cancel a running plan: no further step starts, its order in flight is stopped.
    PlanCancel {
        #[arg(long = "as")]
        actor: String,
        plan: String,
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
        let key = self
            .loaded
            .keypair(&actor)
            .map_err(|e| Failure(3, format!("{e} (keys of {actor} are not on this machine)")))?;
        let token = token.map(read_token).transpose()?;
        Ok(Requester::new(actor, key, parse_id("service:cli")?, Arc::new(OsEntropy)).with_token(token))
    }

    fn send(&self, r: &Requester, target: &EntityId, cap: &CapabilityId, pl: Payload) -> Result<Response, Failure> {
        let bytes = r.sign(&self.registry, target, cap, pl, now_ms());
        self.loaded.client()?.submit(&bytes).map_err(|e| Failure(3, e))
    }

    fn domain(&self) -> EntityId {
        self.loaded.config.domain.clone()
    }

    fn submit(&self, bytes: &[u8]) -> Result<Response, Failure> {
        self.loaded.client()?.submit(bytes).map_err(|e| Failure(3, e))
    }

    fn token_file(&self, holder: &EntityId) -> PathBuf {
        self.loaded.token_file(holder)
    }

    /// The held token to attach for `action` on `resource` ([`pick_token`]).
    fn token_for(&self, file: &Path, resource: &ResourceId, action: &CapabilityId) -> Result<Option<Vec<u8>>, Failure> {
        let Ok(text) = std::fs::read_to_string(file) else { return Ok(None) };
        let verifier = TokenVerifier::new(&self.loaded.authority_public_key()?);
        let mut held = Vec::new();
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let bytes = bytes_from_base64(line).map_err(|e| Failure(3, e.to_string()))?;
            if let Ok(v) = verifier.verify(&bytes) {
                held.push((bytes, v));
            }
        }
        Ok(pick_token(&held, resource, action, now_ms()))
    }
}

/// Of the held tokens that name `action`: valid now on this exact resource,
/// then valid now on some scope (the node decides whether it contains the
/// resource), then the same two expired or not yet valid, so the node can say
/// so. A right delegated again after its token expired is therefore used, and
/// an expired token never hides a live one (v0.3 step ③A, finding F3).
fn pick_token(
    held: &[(Vec<u8>, VerifiedToken)],
    resource: &ResourceId,
    action: &CapabilityId,
    now: u64,
) -> Option<Vec<u8>> {
    held.iter()
        .filter_map(|(bytes, v)| {
            let names = |exact: bool| {
                v.rights.iter().any(|r| &r.capability == action && (!exact || &r.target == resource.as_entity()))
            };
            let live = v.not_before_ms <= now && now < v.expires_at_ms;
            let rank = match (names(true), names(false), live) {
                (true, _, true) => 0,
                (_, true, true) => 1,
                (true, _, false) => 2,
                (_, true, false) => 3,
                _ => return None,
            };
            Some((rank, bytes))
        })
        .min_by_key(|(rank, _)| *rank)
        .map(|(_, bytes)| bytes.clone())
}

fn report(r: &Response) -> u8 {
    println!("{}", r.summary());
    if r.is_escalated() {
        if let Some(reason) = &r.reason {
            println!("{reason}");
        }
        println!("(audit #{})", r.audit_seq.unwrap_or_default());
        return 4;
    }
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
        Cmd::HaDiscover { url, token_env, allow_insecure_http } => {
            use chitala_adapters::home_assistant::HomeAssistantAdapter;
            let ha = HomeAssistantAdapter::with_link(&url, &token_env, Default::default(), allow_insecure_http, None)
                .map_err(|e| Failure(3, e.to_string()))?;
            let found = ha.discover().map_err(|e| Failure(3, e.to_string()))?;
            let json = serde_json::to_string_pretty(&found).map_err(|e| Failure(3, e.to_string()))?;
            println!("{json}");
            eprintln!(
                "{} entities the Home profile can drive. Map the ones Chitala should govern in the config's \
                 home_assistant.entities; discovery grants nothing.",
                found.len()
            );
            Ok(0)
        }
        Cmd::Init { dir } => {
            let (config_path, s) = chitala_node::hosted::init_domain(&dir)?;
            println!("Created a sample domain: {}", config_path.display());
            for (id, roles) in &s.principals {
                println!("  principal {id:<20} roles {roles:?}");
            }
            for d in &s.devices {
                println!("  device    {d}");
            }
            println!("\nRun the node:    chitala --config {} node", config_path.display());
            let cfg = config_path.display();
            println!(
                "Light on:        chitala --config {cfg} invoke --as person:alice device:living-room-light light.turn_on"
            );
            println!(
                "Delegate:        chitala --config {cfg} delegate --as person:alice --to ai:assistant resource:front-door lock.unlock"
            );
            println!(
                "AI asks:         chitala --config {cfg} intent --as ai:assistant resource:front-door lock.unlock"
            );
            println!("Owner decides:   chitala --config {cfg} approvals --as person:alice   (then: approve <intent>)");
            Ok(0)
        }
        Cmd::Node => {
            let loaded = LoadedConfig::load(&cli.config)?;
            let domain = loaded.domain()?;
            let node = chitala_node::start_node(&domain, &loaded.node_env()?)?;
            let ipc = &domain.platform.ipc;
            eprintln!(
                "chitala node: domain {} · {} devices · {} platform · listening on {}",
                node.domain(),
                domain.config.devices.len(),
                domain.platform.name,
                ipc.describe(&domain.endpoint)
            );
            chitala_node::ipc::serve(Arc::new(Mutex::new(node)), ipc.as_ref(), &domain.endpoint)?;
            Ok(0)
        }
        Cmd::Hello => {
            let ctx = Ctx::load(&cli.config)?;
            let v = ctx.loaded.client()?.hello().map_err(|e| Failure(3, e))?;
            println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
            println!("(the node's signature matches node_public_key in the config)");
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
        Cmd::Delegate { actor, to, target, capability, ttl, start, redelegate, for_person, parent, out } => {
            let ctx = Ctx::load(&cli.config)?;
            let r = ctx.requester(&actor, None)?;
            let holder = parse_id(&to)?;
            let mut pl = payload([
                ("holder", ParamValue::Text(holder.to_string())),
                ("target", ParamValue::Text(parse_id(&target)?.to_string())),
                ("capability", ParamValue::Text(parse_cap(&capability)?.to_string())),
                ("ttl_s", ParamValue::Int(ttl)),
            ]);
            if start > 0 {
                pl.insert("start_s".into(), ParamValue::Int(start));
            }
            if redelegate > 0 {
                pl.insert("redelegate".into(), ParamValue::Int(redelegate));
            }
            if let Some(f) = for_person {
                pl.insert("for_person".into(), ParamValue::Text(parse_id(&f)?.to_string()));
            }
            if let Some(p) = parent {
                let text = std::fs::read_to_string(&p).map_err(|e| Failure(3, format!("{}: {e}", p.display())))?;
                pl.insert("parent_token".into(), ParamValue::Text(text.trim().to_string()));
            }
            let resp = ctx.send(&r, &ctx.domain(), &parse_cap("domain.delegate")?, pl)?;
            let code = report(&resp);
            if let Some(token) = resp.result.as_ref().and_then(|v| v["token"].as_str()) {
                // a holder may keep several tokens: one per line
                let path = out.unwrap_or_else(|| ctx.token_file(&holder));
                let mut held = std::fs::read_to_string(&path).unwrap_or_default();
                if !held.is_empty() && !held.ends_with('\n') {
                    held.push('\n');
                }
                held.push_str(&format!("{token}\n"));
                write_private(&path, &held)?;
                println!("token → {}", path.display());
            }
            Ok(code)
        }
        Cmd::Intent { actor, on_behalf_of, resource, action, params, purpose, token } => {
            let ctx = Ctx::load(&cli.config)?;
            let actor_id = parse_id(&actor)?;
            let key = ctx
                .loaded
                .keypair(&actor_id)
                .map_err(|e| Failure(3, format!("{e} (keys of {actor_id} are not on this machine)")))?;
            let on_behalf_of = match on_behalf_of {
                Some(p) => parse_id(&p)?,
                None if actor_id.kind() == chitala_model::EntityKind::Person => actor_id.clone(),
                None => ctx
                    .loaded
                    .config
                    .principals
                    .iter()
                    .find(|p| p.id == actor_id)
                    .and_then(|p| p.serves.first().cloned())
                    .ok_or_else(|| Failure(3, format!("{actor_id} serves nobody; pass --for")))?,
            };
            let resource = ResourceId::parse(&resource).map_err(|e| Failure(3, e.to_string()))?;
            let action = parse_cap(&action)?;
            let mut i = Intent::new(
                new_intent_id(&OsEntropy),
                actor_id.clone(),
                on_behalf_of,
                action.clone(),
                resource.clone(),
                now_ms(),
                300_000,
            );
            i.params = parse_params(&params)?;
            i.context.purpose = purpose;
            if actor_id.kind() != chitala_model::EntityKind::Person {
                let file = token.unwrap_or_else(|| ctx.token_file(&actor_id));
                i.authority = ctx.token_for(&file, &resource, &action)?;
            }
            Ok(report(&ctx.submit(&i.sign(&key))?))
        }
        Cmd::Approvals { actor } => {
            let ctx = Ctx::load(&cli.config)?;
            let r = ctx.requester(&actor, None)?;
            let resp = ctx.send(&r, &ctx.domain(), &parse_cap("domain.list_approvals")?, Payload::new())?;
            Ok(report(&resp))
        }
        Cmd::Approve { actor, intent, reject, note } => {
            let ctx = Ctx::load(&cli.config)?;
            let r = ctx.requester(&actor, None)?;
            let list = ctx.send(&r, &ctx.domain(), &parse_cap("domain.list_approvals")?, Payload::new())?;
            let entries = list.result.as_ref().and_then(|v| v["approvals"].as_array().cloned()).unwrap_or_default();
            let Some(entry) = entries.iter().find(|e| e["intent"] == intent.as_str()) else {
                return Err(Failure(2, format!("intent {intent} is not waiting for {actor}")));
            };
            println!(
                "{} wants {} on {} for {} — \"{}\" (risk {})",
                entry["actor"].as_str().unwrap_or("?"),
                entry["capability"].as_str().unwrap_or("?"),
                entry["resource"].as_str().unwrap_or("?"),
                entry["on_behalf_of"].as_str().unwrap_or("?"),
                entry["purpose"].as_str().unwrap_or(""),
                entry["risk"].as_str().unwrap_or("?"),
            );
            // a lease request: the approval covers exactly these terms (spec 21)
            if let Some(lease) = entry["lease"].as_object() {
                let envelope = lease.get("envelope").and_then(|e| e.as_object()).map_or_else(String::new, |e| {
                    let ranges: Vec<String> = e.iter().map(|(k, r)| format!("{k} {}..{}", r[0], r[1])).collect();
                    format!(", choosing {}", ranges.join(", "))
                });
                println!(
                    "  as a LEASE: up to {} times within {} minutes{envelope}",
                    lease.get("max_uses").and_then(|v| v.as_u64()).unwrap_or(0),
                    lease.get("duration_ms").and_then(|v| v.as_u64()).unwrap_or(0) / 60_000,
                );
            }
            let digest: [u8; 32] = hex::decode(entry["digest"].as_str().unwrap_or_default())
                .ok()
                .and_then(|d| d.try_into().ok())
                .ok_or_else(|| Failure(3, "node sent a malformed digest".into()))?;
            let now = now_ms();
            let answer = Approval {
                intent: parse_id_hex(&intent).ok_or_else(|| Failure(3, "intent id must be 32 hex digits".into()))?,
                intent_digest: digest,
                approver: r.actor.clone(),
                verdict: if reject { Verdict::Reject } else { Verdict::Approve },
                issued_at_ms: now,
                expires_at_ms: now + 60_000,
                note,
            };
            Ok(report(&ctx.submit(&answer.sign(&r.key))?))
        }
        Cmd::Revoke { actor, revocation_id } => {
            let ctx = Ctx::load(&cli.config)?;
            let r = ctx.requester(&actor, None)?;
            let pl = payload([("revocation_id", ParamValue::Text(revocation_id))]);
            Ok(report(&ctx.send(&r, &ctx.domain(), &parse_cap("domain.revoke_token")?, pl)?))
        }
        Cmd::RevokeAll { actor, principal } => {
            let ctx = Ctx::load(&cli.config)?;
            let r = ctx.requester(&actor, None)?;
            let mut pl = Payload::new();
            if let Some(p) = principal {
                pl.insert("principal".into(), ParamValue::Text(parse_id(&p)?.to_string()));
            }
            Ok(report(&ctx.send(&r, &ctx.domain(), &parse_cap("domain.revoke_all")?, pl)?))
        }
        Cmd::Hold { actor, resource, reason } => {
            let ctx = Ctx::load(&cli.config)?;
            let r = ctx.requester(&actor, None)?;
            let resource = ResourceId::parse(&resource).map_err(|e| Failure(3, e.to_string()))?;
            let mut pl = payload([("resource", ParamValue::Text(resource.to_string()))]);
            if let Some(why) = reason {
                pl.insert("reason".into(), ParamValue::Text(why));
            }
            Ok(report(&ctx.send(&r, &ctx.domain(), &parse_cap("domain.safety_hold")?, pl)?))
        }
        Cmd::Release { actor, resource } => {
            let ctx = Ctx::load(&cli.config)?;
            let r = ctx.requester(&actor, None)?;
            let resource = ResourceId::parse(&resource).map_err(|e| Failure(3, e.to_string()))?;
            let pl = payload([("resource", ParamValue::Text(resource.to_string()))]);
            Ok(report(&ctx.send(&r, &ctx.domain(), &parse_cap("domain.safety_release")?, pl)?))
        }
        Cmd::Plans { actor } => {
            let ctx = Ctx::load(&cli.config)?;
            let r = ctx.requester(&actor, None)?;
            Ok(report(&ctx.send(&r, &ctx.domain(), &parse_cap("domain.list_plans")?, Payload::new())?))
        }
        Cmd::PlanCancel { actor, plan } => {
            let ctx = Ctx::load(&cli.config)?;
            let r = ctx.requester(&actor, None)?;
            let pl = payload([("plan", ParamValue::Text(plan))]);
            Ok(report(&ctx.send(&r, &ctx.domain(), &parse_cap("domain.plan_cancel")?, pl)?))
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
            let r = chitala_node::hosted::verify_audit_file(&path, &trusted).map_err(|e| Failure(2, e.to_string()))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use chitala_identity::{key_id_of, test_seed, Keypair};
    use chitala_token::{Grant, Right, TokenAuthority};

    const NOW: u64 = 1_790_000_000_000;

    fn id(s: &str) -> EntityId {
        EntityId::parse(s).unwrap()
    }

    /// A token for `ai:assistant` to turn on the lights of `target`, valid in [from, until).
    fn held(auth: &TokenAuthority, target: &str, from: u64, until: u64) -> (Vec<u8>, VerifiedToken) {
        let grant = Grant {
            holder: id("ai:assistant"),
            holder_key: key_id_of(&Keypair::from_seed(&test_seed("ai:assistant")).public_key()),
            issuer: id("person:alice"),
            rights: vec![Right::new(id(target), CapabilityId::parse("light.turn_on").unwrap())],
            not_before_ms: from,
            not_after_ms: until,
            redelegate: 0,
            for_persons: vec![id("person:alice")],
            issued_epoch: 1,
        };
        let t = auth.issue(&grant, NOW - 10_000_000).unwrap();
        let v = auth.verifier().verify(&t.bytes).unwrap();
        (t.bytes, v)
    }

    /// v0.3 step ③A, finding F3: the CLI attached the first token naming the
    /// right, so a right delegated again after its token expired was refused.
    #[test]
    fn a_live_token_is_picked_before_an_expired_or_early_one() {
        let auth = TokenAuthority::new(
            &Keypair::from_seed(&test_seed("authority")),
            Arc::new(chitala_platform::memory::test_entropy()),
        );
        let light = ResourceId::new("living-room-light").unwrap();
        let on = CapabilityId::parse("light.turn_on").unwrap();
        let expired = held(&auth, "resource:living-room-light", 0, NOW - 1_000);
        let early = held(&auth, "resource:living-room-light", NOW + 3_600_000, NOW + 7_200_000);
        let live = held(&auth, "resource:living-room-light", 0, NOW + 600_000);
        let room = held(&auth, "resource:living-room", 0, NOW + 600_000);
        let pick = |h: &[(Vec<u8>, VerifiedToken)]| pick_token(h, &light, &on, NOW);

        assert_eq!(pick(&[expired.clone(), live.clone()]), Some(live.0.clone()), "the right delegated again");
        assert_eq!(pick(&[live.clone(), expired.clone()]), Some(live.0.clone()));
        assert_eq!(pick(&[expired.clone(), room.clone()]), Some(room.0.clone()), "a live room right");
        assert_eq!(pick(&[early.clone(), room.clone()]), Some(room.0.clone()), "not valid yet");
        assert_eq!(pick(&[room.clone(), live.clone()]), Some(live.0.clone()), "the exact right first");
        // only a dead one: still sent, so the node says why
        assert_eq!(pick(std::slice::from_ref(&expired)), Some(expired.0.clone()));
        assert_eq!(pick(std::slice::from_ref(&early)), Some(early.0.clone()));
        // nothing names the action: nothing is sent
        let off = CapabilityId::parse("light.turn_off").unwrap();
        assert_eq!(pick_token(&[live], &light, &off, NOW), None);
    }
}
