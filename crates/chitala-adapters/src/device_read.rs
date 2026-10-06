//! A read of a device for evidence, in the background (findings F9b and F10,
//! v0.3 step ⑤). An observation for evidence waits a moment for it and goes
//! on; the read goes on too, and a later observation takes its values. One
//! read of a device at a time; a device that did not answer is not read again
//! at once; each read's values are evidence once, as of when the read began.

use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

/// How long an observation for evidence waits for a read before it calls the
/// state unconfirmed.
pub const READ_WAIT: Duration = Duration::from_secs(1);
/// A device that did not answer a read is not read again before this.
pub const READ_RETRY: Duration = Duration::from_secs(5);

/// The reads of one device.
pub(crate) struct DeviceRead<V> {
    /// The read on its way: when it began, and its values to come.
    asking: Option<(Instant, Receiver<Result<V, String>>)>,
    /// Values read and not given as evidence yet, and when their read began.
    fresh: Option<(Instant, V)>,
    /// When the last read failed.
    failed: Option<Instant>,
}

impl<V> Default for DeviceRead<V> {
    fn default() -> Self {
        Self { asking: None, fresh: None, failed: None }
    }
}

impl<V: Send + 'static> DeviceRead<V> {
    /// The values of a read not given yet, and when it began. Otherwise a read
    /// begins with `read` (unless one is on its way, or the last one failed
    /// less than [`READ_RETRY`] ago) and is waited for up to `wait`.
    pub fn take(
        &mut self,
        wait: Duration,
        read: impl FnOnce() -> Result<V, String> + Send + 'static,
    ) -> Option<(Instant, V)> {
        self.poll(Duration::ZERO);
        if self.fresh.is_none() && self.asking.is_none() && self.failed.is_none_or(|f| f.elapsed() >= READ_RETRY) {
            let (tx, answer) = std::sync::mpsc::channel();
            let began = Instant::now();
            std::thread::spawn(move || {
                let _ = tx.send(read());
            });
            self.asking = Some((began, answer));
            self.poll(wait);
        }
        self.fresh.take()
    }

    /// Take the values of the read on its way, waiting up to `wait`.
    fn poll(&mut self, wait: Duration) {
        let Some((began, answer)) = self.asking.take() else { return };
        match answer.recv_timeout(wait) {
            Ok(Ok(values)) => self.fresh = Some((began, values)),
            Err(RecvTimeoutError::Timeout) => self.asking = Some((began, answer)),
            Ok(Err(_)) | Err(RecvTimeoutError::Disconnected) => self.failed = Some(Instant::now()),
        }
    }
}
