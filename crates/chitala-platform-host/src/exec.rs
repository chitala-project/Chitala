//! Components as OS processes: their own address space, an empty environment
//! plus exactly what the spec grants, a private stdin/stdout channel.

use std::io::ErrorKind;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use chitala_platform::{ComponentHandle, ComponentSpec, ExecutionHost, PlatformError, Result, Spawned};

/// How long a busy program is tried again. The kernel refuses to run a file
/// that is open for writing (`ETXTBSY`), and a child forked by another thread
/// keeps a copy of every open file until it executes its own program: a
/// program just written, and closed, can look busy for a moment (a CI-only
/// failure, 2026-10-07). As with a busy claim ([`crate::fs::CLAIM_WAIT`]),
/// the start is tried again; a program kept open for writing is still refused.
pub const SPAWN_WAIT: Duration = Duration::from_secs(2);

pub struct ProcessHost;

struct ProcessHandle {
    child: Child,
}

impl ComponentHandle for ProcessHandle {
    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
    fn id(&self) -> Option<u32> {
        Some(self.child.id())
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        self.kill();
    }
}

impl ExecutionHost for ProcessHost {
    fn spawn(&self, spec: &ComponentSpec) -> Result<Spawned> {
        let mut command = Command::new(&spec.program);
        command
            .env_clear()
            .envs(spec.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let deadline = Instant::now() + SPAWN_WAIT;
        let mut child = loop {
            match command.spawn() {
                Ok(child) => break child,
                Err(e) if e.kind() == ErrorKind::ExecutableFileBusy && Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20))
                }
                Err(e) => return Err(PlatformError::NotFound(format!("cannot start {}: {e}", spec.program))),
            }
        };
        let (Some(input), Some(output)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            return Err(PlatformError::Io("component has no stdio".into()));
        };
        Ok(Spawned { input: Box::new(input), output: Box::new(output), handle: Box::new(ProcessHandle { child }) })
    }

    fn isolated(&self) -> bool {
        true
    }
}
