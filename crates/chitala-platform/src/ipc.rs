//! Local IPC (v20 §4: not tied to Unix sockets).
//!
//! An [`Endpoint`] is a logical name. The transport is not a trust boundary —
//! everything that crosses it is signed (spec 11) — but a backend must still
//! keep the endpoint private to the platform owner so others cannot squat on
//! it or eavesdrop.

use std::fmt;
use std::io::{Read, Write};
use std::time::Duration;

use crate::{PlatformError, Result};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Endpoint(String);

impl Endpoint {
    pub fn new(name: impl Into<String>) -> Result<Self> {
        let name = name.into();
        let ok = !name.is_empty()
            && name.len() <= 64
            && name.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'));
        if ok {
            Ok(Self(name))
        } else {
            Err(PlatformError::Invalid(format!("endpoint {name:?}")))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

pub trait IpcStream: Read + Write + Send {
    fn try_clone(&self) -> Result<Box<dyn IpcStream>>;
    /// Read/write timeout; `None` blocks forever.
    fn set_timeout(&self, timeout: Option<Duration>) -> Result<()>;
}

pub trait IpcListener: Send {
    fn accept(&self) -> Result<Box<dyn IpcStream>>;
}

pub trait IpcTransport: Send + Sync {
    /// Listen on `endpoint`, private to the platform owner. Fails if another
    /// listener is alive on it; never replaces something that is not an endpoint.
    fn listen(&self, endpoint: &Endpoint) -> Result<Box<dyn IpcListener>>;

    fn connect(&self, endpoint: &Endpoint) -> Result<Box<dyn IpcStream>>;

    /// Human-readable location (a socket path, a pipe name…).
    fn describe(&self, endpoint: &Endpoint) -> String;
}
