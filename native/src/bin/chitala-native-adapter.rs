//! N1.4: the adapter host, alone in a guest of its own (native/spike/README.md).
//!
//! The core's guest reaches it over the channel (`/dev/chitala-channel`, a
//! relay between the two guests). It shakes hands, then runs the adapter
//! host's protocol on the channel, unchanged: it admits only orders the core's
//! trusted execution boundary signed for it (spec 19), drives its virtual
//! devices, and answers with receipts.
//!
//! `--disappear-on-execute N` makes it take the N-th order off the channel and
//! then go silent, without answering: the case the core must classify as
//! of unknown fate, never as not sent (spec 22, R1).
#![forbid(unsafe_code)]

#[cfg(target_os = "hermit")]
use hermit as _;

#[path = "../channel.rs"]
mod channel;

use std::io::{BufReader, Cursor, Read};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chitala_platform::{TimeSource, TrustedClock};

/// The board's clocks, as the kernel reports them.
struct BoardTime {
    origin: Instant,
}

impl TimeSource for BoardTime {
    fn wall_ms(&self) -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
    }

    fn monotonic_ms(&self) -> u64 {
        self.origin.elapsed().as_millis() as u64
    }
}

/// The channel as the adapter host reads it, one line at a time. It counts the
/// orders that pass, and on the N-th it takes the order and goes silent.
struct Tap<R> {
    inner: R,
    line: Vec<u8>,
    at: usize,
    executes: u32,
    disappear_on: Option<u32>,
}

impl<R: Read> Read for Tap<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.at == self.line.len() {
            self.line.clear();
            self.at = 0;
            let mut byte = [0u8; 1];
            loop {
                if self.inner.read(&mut byte)? == 0 {
                    break;
                }
                self.line.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            if self.line.windows(14).any(|w| w == b"\"op\":\"execute\"") {
                self.executes += 1;
                if Some(self.executes) == self.disappear_on {
                    println!(
                        "[adapter]   took order #{} off the channel; disappearing before any answer (N1.4, R1)",
                        self.executes
                    );
                    loop {
                        std::thread::sleep(Duration::from_secs(3600));
                    }
                }
            }
        }
        let n = buf.len().min(self.line.len() - self.at);
        buf[..n].copy_from_slice(&self.line[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

fn main() -> ExitCode {
    println!("Chitala Native spike: the adapter host's guest (N1.4)");
    let args: Vec<String> = std::env::args().collect();
    let disappear_on = args
        .iter()
        .position(|a| a == "--disappear-on-execute")
        .and_then(|i| args.get(i + 1))
        .and_then(|n| n.parse::<u32>().ok());
    if !channel::present() {
        println!("[adapter]   ✗ no channel at {}: this image runs beside the core's guest", channel::PATH);
        return ExitCode::from(2);
    }
    let head = match channel::accept() {
        Ok(head) => head,
        Err(e) => {
            println!("[adapter]   ✗ the channel failed: {e}");
            return ExitCode::from(1);
        }
    };
    println!("[adapter]   channel up: the core's guest is on the other side");
    let (Ok(input), Ok(mut output)) = (channel::open(), channel::open()) else {
        println!("[adapter]   ✗ the channel cannot be opened again");
        return ExitCode::from(1);
    };
    let input = Cursor::new(head).chain(input);
    let time: Arc<dyn TimeSource> = Arc::new(BoardTime { origin: Instant::now() });
    let clock = Arc::new(TrustedClock::new(time, 0)).as_clock();
    let tap = Tap { inner: input, line: Vec::new(), at: 0, executes: 0, disappear_on };
    let status = chitala_adapters::host::run(&mut BufReader::new(tap), &mut output, clock);
    println!("[adapter]   the channel closed (status {status})");
    ExitCode::SUCCESS
}
