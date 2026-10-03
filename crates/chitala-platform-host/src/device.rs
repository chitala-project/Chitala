//! Device I/O on a hosted system: character devices (serial ports, USB
//! adapters) the operator configured by name. Nothing else can be opened —
//! not `/dev/mem`, not another user's tty, not a path an adapter made up.
//!
//! Reads go through a reader thread so a read can time out without
//! platform-specific `termios`/`fcntl` calls. Line settings (baud rate…) are
//! the operator's job (`stty`, udev) in v0.2.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chitala_platform::{DeviceAddress, DeviceChannel, DeviceInfo, DeviceIo, PlatformError, Result};

pub struct HostDevices {
    configured: BTreeMap<DeviceAddress, (PathBuf, String)>,
    open: Arc<Mutex<BTreeSet<DeviceAddress>>>,
}

impl HostDevices {
    /// `devices`: name → (host path, description), from the node's configuration.
    pub fn new(devices: impl IntoIterator<Item = (DeviceAddress, PathBuf, String)>) -> Self {
        Self {
            configured: devices.into_iter().map(|(a, p, d)| (a, (p, d))).collect(),
            open: Arc::new(Mutex::new(BTreeSet::new())),
        }
    }
}

struct HostChannel {
    address: DeviceAddress,
    file: std::fs::File,
    incoming: Receiver<Vec<u8>>,
    buffered: Vec<u8>,
    timeout: Duration,
    open: Arc<Mutex<BTreeSet<DeviceAddress>>>,
}

impl Drop for HostChannel {
    fn drop(&mut self) {
        self.open.lock().unwrap_or_else(|p| p.into_inner()).remove(&self.address);
    }
}

impl DeviceChannel for HostChannel {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if self.buffered.is_empty() {
            match self.incoming.recv_timeout(self.timeout) {
                Ok(chunk) => self.buffered = chunk,
                Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => return Ok(0),
            }
        }
        let n = buf.len().min(self.buffered.len());
        buf[..n].copy_from_slice(&self.buffered[..n]);
        self.buffered.drain(..n);
        Ok(n)
    }

    fn write(&mut self, data: &[u8]) -> Result<()> {
        self.file.write_all(data)?;
        self.file.flush()?;
        Ok(())
    }

    fn set_timeout(&mut self, timeout: Duration) -> Result<()> {
        self.timeout = timeout;
        Ok(())
    }
}

impl DeviceIo for HostDevices {
    fn devices(&self) -> Vec<DeviceInfo> {
        self.configured.iter().map(|(a, (_, d))| DeviceInfo { address: a.clone(), description: d.clone() }).collect()
    }

    fn open(&self, address: &DeviceAddress) -> Result<Box<dyn DeviceChannel>> {
        let (path, _) =
            self.configured.get(address).ok_or_else(|| PlatformError::NotFound(format!("no device {address}")))?;
        let mut open = self.open.lock().unwrap_or_else(|p| p.into_inner());
        if open.contains(address) {
            return Err(PlatformError::AlreadyExists(format!("{address} is already open")));
        }
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let mut reader = file.try_clone()?;
        let (tx, rx) = mpsc::channel();
        std::thread::Builder::new()
            .name(format!("device {address}"))
            .spawn(move || {
                let mut buf = [0u8; 1024];
                while let Ok(n) = reader.read(&mut buf) {
                    if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            })
            .map_err(|e| PlatformError::Io(e.to_string()))?;
        open.insert(address.clone());
        Ok(Box::new(HostChannel {
            address: address.clone(),
            file,
            incoming: rx,
            buffered: Vec::new(),
            timeout: Duration::from_secs(1),
            open: Arc::clone(&self.open),
        }))
    }
}
