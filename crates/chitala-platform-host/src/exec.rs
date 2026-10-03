//! Components as OS processes: their own address space, an empty environment
//! plus exactly what the spec grants, a private stdin/stdout channel.

use std::process::{Child, Command, Stdio};

use chitala_platform::{ComponentHandle, ComponentSpec, ExecutionHost, PlatformError, Result, Spawned};

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
        let mut child = Command::new(&spec.program)
            .env_clear()
            .envs(spec.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| PlatformError::NotFound(format!("cannot start {}: {e}", spec.program)))?;
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
