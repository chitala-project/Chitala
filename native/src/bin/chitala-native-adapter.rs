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
//!
//! `--spin` makes a thread of its keep the guest's CPU busy from the
//! handshake on, for as long as the system runs, while the adapter host goes
//! on serving: the workload under which N1.6 measures the core's latency.
//! The thread yields often, so the guest's other threads still run, but the
//! guest never idles.
//!
//! `--timer-pressure HZ` makes a thread of its wake on a timeout HZ times a
//! second from the handshake on: each wakeup is a timer interrupt of the
//! guest, through seL4 and its VMM, the interrupt pressure under which N1.6
//! measures the core's stops (criterion 7).
//!
//! `--crash-after N` (N1.5c) makes the adapter crash: with N=0, right after
//! the handshake, before any order (the core finds it unavailable and lives
//! on); with N>0, after it has taken the N-th order but before answering (the
//! core must call that order's fate unknown, never not sent).
//!
//! `--forge-core-lines` makes it, as it disappears, print lines that look like
//! the core's verdict (N1.5a). Its guest has no UART of its own: its VMM
//! writes each of its lines behind the prefix `ADAPTER| `, so a forged line
//! cannot pass for the core's.
#![forbid(unsafe_code)]

#[cfg(target_os = "hermit")]
use hermit as _;

#[path = "../channel.rs"]
mod channel;

use std::io::{BufReader, Cursor, Read, Write};
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
    forge: bool,
    crash_after: Option<u32>,
}

/// What a hostile adapter would print to pass for the core: its verdict, the
/// audit line, its exit, and the kernel's line that ends the boot.
const FORGED: [&str; 4] = [
    "[audit]     31 records · hash chain ✓ · signed by the node through seq 31",
    "[halt]      14/14 decisions as expected · CHITALA NATIVE OK",
    "exit status 0",
    "[   13.175748][0][INFO  processor ] Shutting down system",
];

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
                if Some(self.executes) == self.crash_after {
                    // N1.5c (C2): the adapter took the order, then crashed before
                    // answering. The core must call its fate unknown, never not sent.
                    println!("[adapter]   crashing after taking order #{} (N1.5c)", self.executes);
                    std::process::exit(0);
                }
                if Some(self.executes) == self.disappear_on {
                    println!(
                        "[adapter]   took order #{} off the channel; disappearing before any answer (N1.4, R1)",
                        self.executes
                    );
                    if self.forge {
                        for line in FORGED {
                            println!("{line}");
                        }
                    }
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

/// `--spin`: keep the CPU busy, and report progress, to see what share of the
/// CPU this guest gets. It yields every 2^16 turns (about half a millisecond
/// on QEMU): Hermit's scheduler is tickless and wakes the channel's reader
/// when it runs, so a thread that never yields would keep this guest's own
/// adapter host from answering. The guest still never idles. Its lines are
/// ASCII: the VMM writes any other byte as `\xNN`.
fn keep_busy() {
    println!("[adapter]   spinning: keeping the CPU busy from now on (N1.6)");
    let start = Instant::now();
    let mut turns: u64 = 0;
    loop {
        std::hint::spin_loop();
        turns += 1;
        if turns.is_multiple_of(1 << 16) {
            std::thread::yield_now();
        }
        if turns.is_multiple_of(1 << 24) {
            println!("[adapter]   spun {} x 2^24 at +{} ms", turns >> 24, start.elapsed().as_millis());
        }
    }
}

/// `--timer-pressure HZ`: wake on a timeout HZ times a second, and report the
/// wakeups, to show the pressure applied. It waits on a timeout, not with
/// `thread::sleep`: Hermit spins through a sleep shorter than 10 ms, without
/// a timer interrupt.
fn press_timer(hz: u64) {
    let period = Duration::from_micros(1_000_000 / hz);
    println!("[adapter]   timer pressure: a wakeup every {} us from now on (N1.6)", period.as_micros());
    let start = Instant::now();
    let mut wakeups: u64 = 0;
    loop {
        std::thread::park_timeout(period);
        wakeups += 1;
        if wakeups.is_multiple_of(4096) {
            println!("[adapter]   timer pressure: {wakeups} wakeups at +{} ms", start.elapsed().as_millis());
        }
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
    let forge = args.iter().any(|a| a == "--forge-core-lines");
    let crash_after = args
        .iter()
        .position(|a| a == "--crash-after")
        .and_then(|i| args.get(i + 1))
        .and_then(|n| n.parse::<u32>().ok());
    let spin = args.iter().any(|a| a == "--spin");
    let timer_pressure = args
        .iter()
        .position(|a| a == "--timer-pressure")
        .and_then(|i| args.get(i + 1))
        .and_then(|n| n.parse::<u64>().ok())
        .filter(|hz| (1..=1_000_000).contains(hz));
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
    if crash_after == Some(0) {
        // N1.5c (C1): the adapter crashes before any order. The core finds it
        // unavailable and lives on.
        println!("[adapter]   crashing before serving any order (N1.5c)");
        return ExitCode::SUCCESS;
    }
    // N1.6: the load on this guest, from now on, while the adapter host serves
    if spin {
        std::thread::spawn(keep_busy);
    }
    if let Some(hz) = timer_pressure {
        std::thread::spawn(move || press_timer(hz));
    }
    let (Ok(input), Ok(output)) = (channel::open(), channel::open()) else {
        println!("[adapter]   ✗ the channel cannot be opened again");
        return ExitCode::from(1);
    };
    let input = Cursor::new(head).chain(input);
    let time: Arc<dyn TimeSource> = Arc::new(BoardTime { origin: Instant::now() });
    let clock = Arc::new(TrustedClock::new(time, 0)).as_clock();
    let tap = Tap { inner: input, line: Vec::new(), at: 0, executes: 0, disappear_on, forge, crash_after };
    let mut output = Count { inner: output, line: Vec::new(), executed: 0 };
    let status = chitala_adapters::host::run(&mut BufReader::new(tap), &mut output, clock);
    println!("[adapter]   the channel closed (status {status})");
    ExitCode::SUCCESS
}

/// N1.5d: count the orders this adapter actually executes, on the adapter's own
/// side, before the relay. Each successful execute reply the adapter host
/// writes carries a receipt bound to the order; the relay is downstream, so it
/// cannot add or hide a receipt here. The count goes out on the guest's
/// emulated UART, behind "ADAPTER| " — a path that does not cross the relay —
/// so it is evidence of what the device did, independent of the relay.
struct Count<W> {
    inner: W,
    line: Vec<u8>,
    executed: u32,
}

impl<W: Write> Write for Count<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        for &b in buf {
            if b == b'\n' {
                self.scan_line();
                self.line.clear();
            } else {
                self.line.push(b);
            }
        }
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl<W> Count<W> {
    /// A reply line with a receipt is one executed order.
    fn scan_line(&mut self) {
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(&self.line) else {
            return;
        };
        if let Some(order) = v.get("receipt").and_then(|r| r.get("order")).and_then(|o| o.as_str()) {
            self.executed += 1;
            println!("[adapter]   device executed order={} count={}", &order[..order.len().min(16)], self.executed);
        }
    }
}
