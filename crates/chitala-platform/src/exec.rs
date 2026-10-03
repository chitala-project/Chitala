//! Execution host (v20 §4: not tied to the Linux process model).
//!
//! Used to run components outside the Trusted Core — today the adapter hosts
//! (spec 10). A component gets a private bidirectional byte channel, exactly
//! the environment it is given (nothing inherited) and, where the backend can
//! provide it, its own address space.

use std::io::{Read, Write};

use crate::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentSpec {
    /// Backend-specific locator: an executable path for the hosted backend, a
    /// registered name for the memory backend.
    pub program: String,
    /// The complete environment of the component.
    pub env: Vec<(String, String)>,
}

pub trait ComponentHandle: Send {
    /// Stop the component now. Idempotent.
    fn kill(&mut self);
    /// Backend identifier (a process id), if any.
    fn id(&self) -> Option<u32>;
}

pub struct Spawned {
    /// The component's input.
    pub input: Box<dyn Write + Send>,
    /// The component's output.
    pub output: Box<dyn Read + Send>,
    pub handle: Box<dyn ComponentHandle>,
}

pub trait ExecutionHost: Send + Sync {
    fn spawn(&self, spec: &ComponentSpec) -> Result<Spawned>;

    /// Whether components get their own address space (a crash or exploit in
    /// one cannot touch the caller's memory).
    fn isolated(&self) -> bool;
}
