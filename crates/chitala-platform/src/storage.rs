//! Storage (v20 §4: no POSIX path semantics in the core).
//!
//! Paths are logical ([`StoragePath`]) and protection is semantic
//! ([`Visibility`]): "only the owner of this platform may read or write" is a
//! security requirement every backend must enforce in its own way (POSIX mode
//! bits, ACLs, an encrypted partition…), not a Unix detail.

use std::fmt;

use crate::{PlatformError, Result};

/// A relative, `/`-separated path inside the platform's storage root.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StoragePath(String);

impl StoragePath {
    pub fn new(path: impl Into<String>) -> Result<Self> {
        let path = path.into();
        let ok = !path.is_empty()
            && path.len() <= 255
            && path.split('/').all(|seg| {
                !seg.is_empty()
                    && seg != "."
                    && seg != ".."
                    && seg.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
            });
        if ok {
            Ok(Self(path))
        } else {
            Err(PlatformError::Invalid(format!("storage path {path:?}")))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn join(&self, segment: &str) -> Result<Self> {
        Self::new(format!("{}/{segment}", self.0))
    }
}

impl fmt::Display for StoragePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    /// Only the platform owner may read or write (keys, audit log, domain state).
    /// Backends refuse to *use* existing private data that others could
    /// read or modify ([`PlatformError::Insecure`]).
    Private,
    /// Readable by others on the same machine (configuration with public keys).
    Shared,
}

/// An append-only record log (the audit log).
pub trait AppendLog: Send {
    /// Append one record; durable when this returns.
    fn append(&mut self, record: &[u8]) -> Result<()>;
}

pub trait Storage: Send + Sync {
    /// `None` if the object does not exist.
    fn read(&self, path: &StoragePath, visibility: Visibility) -> Result<Option<Vec<u8>>>;

    /// Replace the object atomically (readers see the old or the new content).
    fn write_atomic(&self, path: &StoragePath, data: &[u8], visibility: Visibility) -> Result<()>;

    /// Create a new object; `AlreadyExists` if it is there (keys are never overwritten).
    fn create_new(&self, path: &StoragePath, data: &[u8], visibility: Visibility) -> Result<()>;

    /// Open (creating if needed) an append-only log.
    fn open_append(&self, path: &StoragePath, visibility: Visibility) -> Result<Box<dyn AppendLog>>;

    fn exists(&self, path: &StoragePath) -> Result<bool>;

    fn remove(&self, path: &StoragePath) -> Result<()>;

    /// Ensure a directory-like prefix exists with the given protection.
    fn ensure_dir(&self, path: &StoragePath, visibility: Visibility) -> Result<()>;
}
