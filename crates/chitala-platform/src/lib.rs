//! Chitala Platform Abstraction Layer (spec `specs/18-platform.md`, Blueprint v20 §4).
//!
//! The Trusted Core never talks to a host operating system directly. Everything
//! it needs from "the machine" is one of these traits:
//!
//! | trait | instead of |
//! |---|---|
//! | [`TimeSource`] (+ [`TrustedClock`]) | a Unix system clock |
//! | [`Entropy`] | a specific OS RNG |
//! | [`SecureKeyStore`] / [`Signer`] | key files; backends may be TPM, Secure Element, enclave or software |
//! | [`Storage`] | POSIX paths and permission bits |
//! | [`IpcTransport`] | Unix sockets |
//! | [`ExecutionHost`] | the Linux process model |
//! | [`NetworkTransport`] | a specific TCP/HTTP stack |
//! | [`DeviceIo`] | device files, serial ports, GPIO; UART/MMIO on Native — adapters only |
//!
//! This crate holds only the contracts, the trusted clock built on them, an
//! in-memory backend ([`memory`]) for tests and simulation, and a contract test
//! suite ([`contract`]) every backend must pass. The hosted backend (Linux,
//! macOS) lives in `chitala-platform-host`; a native backend will be another
//! crate — the Trusted Core does not change (v20 §2).

#![forbid(unsafe_code)]

pub mod contract;
pub mod device;
pub mod entropy;
pub mod exec;
pub mod ipc;
pub mod keys;
pub mod memory;
pub mod net;
pub mod software;
pub mod storage;
pub mod time;

use std::sync::Arc;

pub use device::{DeviceAddress, DeviceChannel, DeviceInfo, DeviceIo, NoDevices};
pub use entropy::{random_array, Entropy, EntropyRng};
pub use exec::{ComponentHandle, ComponentSpec, ExecutionHost, Spawned};
pub use ipc::{Endpoint, IpcListener, IpcStream, IpcTransport};
pub use keys::{KeyRef, KeyStoreInfo, SecureKeyStore, SeedSigner, Signer};
pub use net::{HttpRequest, HttpResponse, NetworkTransport};
pub use software::SoftwareKeyStore;
pub use storage::{AppendLog, Storage, StoragePath, Visibility};
pub use time::{Clock, TimeSource, TrustedClock};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlatformError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("already exists: {0}")]
    AlreadyExists(String),
    /// The backend cannot do this (e.g. export a hardware key).
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// Existing data is less protected than required (e.g. a private key file
    /// readable by others). Using it anyway would be unsafe.
    #[error("insecure: {0}")]
    Insecure(String),
    #[error("invalid: {0}")]
    Invalid(String),
    #[error("timed out")]
    Timeout,
    #[error("unreachable: {0}")]
    Unreachable(String),
    #[error("I/O: {0}")]
    Io(String),
}

pub type Result<T> = std::result::Result<T, PlatformError>;

impl From<std::io::Error> for PlatformError {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::NotFound => PlatformError::NotFound(e.to_string()),
            std::io::ErrorKind::AlreadyExists => PlatformError::AlreadyExists(e.to_string()),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => PlatformError::Timeout,
            _ => PlatformError::Io(e.to_string()),
        }
    }
}

/// One platform: everything the runtime needs from the machine.
#[derive(Clone)]
pub struct Platform {
    /// Backend name for logs (`hosted-unix`, `memory`, …).
    pub name: &'static str,
    pub time: Arc<dyn TimeSource>,
    pub entropy: Arc<dyn Entropy>,
    pub keys: Arc<dyn SecureKeyStore>,
    pub storage: Arc<dyn Storage>,
    pub ipc: Arc<dyn IpcTransport>,
    pub exec: Arc<dyn ExecutionHost>,
    pub network: Arc<dyn NetworkTransport>,
    pub devices: Arc<dyn DeviceIo>,
}

impl std::fmt::Debug for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Platform").field("name", &self.name).finish_non_exhaustive()
    }
}
