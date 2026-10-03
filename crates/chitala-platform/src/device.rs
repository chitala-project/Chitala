//! Device I/O: the platform's way to reach physical hardware (spec 18).
//!
//! A device channel is a serial line, a GPIO bank, a CAN or USB endpoint on a
//! hosted system, or a UART / MMIO region on Chitala Native. Adapters reach
//! hardware only through this trait; the Trusted Core never does. A backend
//! exposes **only** the devices it was configured with: there is no way to ask
//! for an arbitrary host path.

use std::fmt;
use std::time::Duration;

use crate::{PlatformError, Result};

/// Name of a configured device, `<bus>:<name>` (`serial:front-door`,
/// `gpio:relay-1`, `uart:0`). It is a name, never a host path.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DeviceAddress(String);

impl DeviceAddress {
    pub fn new(address: impl Into<String>) -> Result<Self> {
        let a = address.into();
        let ok_seg = |s: &str| {
            !s.is_empty()
                && s.len() <= 64
                && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.'))
        };
        match a.split_once(':') {
            Some((bus, name)) if ok_seg(bus) && ok_seg(name) && !name.contains("..") => Ok(Self(a)),
            _ => Err(PlatformError::Invalid(format!("device address must be <bus>:<name>, got {a:?}"))),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn bus(&self) -> &str {
        self.0.split_once(':').map(|(b, _)| b).unwrap_or_default()
    }
}

impl fmt::Display for DeviceAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    pub address: DeviceAddress,
    /// Human description from the configuration.
    pub description: String,
}

/// An open, exclusive channel to one device.
pub trait DeviceChannel: Send {
    /// Read what is available, waiting at most the timeout; `Ok(0)` means
    /// nothing arrived in time.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize>;
    fn write(&mut self, data: &[u8]) -> Result<()>;
    fn set_timeout(&mut self, timeout: Duration) -> Result<()>;
}

pub trait DeviceIo: Send + Sync {
    /// The configured devices.
    fn devices(&self) -> Vec<DeviceInfo>;
    /// Open a configured device. Unknown addresses are `NotFound`; a device
    /// that is already open is `AlreadyExists` (channels are exclusive).
    fn open(&self, address: &DeviceAddress) -> Result<Box<dyn DeviceChannel>>;
}

/// No devices at all (simulation, tests, a node without local hardware).
pub struct NoDevices;

impl DeviceIo for NoDevices {
    fn devices(&self) -> Vec<DeviceInfo> {
        Vec::new()
    }
    fn open(&self, address: &DeviceAddress) -> Result<Box<dyn DeviceChannel>> {
        Err(PlatformError::NotFound(format!("no device {address} on this platform")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_names_not_paths() {
        for ok in ["serial:front-door", "gpio:relay-1", "uart:0", "can:bus0.motor"] {
            assert!(DeviceAddress::new(ok).is_ok(), "{ok}");
        }
        for bad in ["/dev/ttyUSB0", "serial:/dev/ttyUSB0", "serial:../x", "Serial:a", "serial:", "noport", "a:b:c"] {
            assert!(DeviceAddress::new(bad).is_err(), "{bad}");
        }
        assert_eq!(DeviceAddress::new("gpio:relay-1").unwrap().bus(), "gpio");
    }
}
