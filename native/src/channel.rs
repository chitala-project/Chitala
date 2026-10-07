//! N1.4: the byte channel between the core's guest and the adapter host's
//! guest (native/spike/README.md).
//!
//! Each guest's virtio console is the file `/dev/chitala-channel` (a carried
//! Hermit patch, native/patches/), and a relay protection domain copies bytes
//! between the two. The relay is hostile transport: it may drop, duplicate,
//! reorder, truncate, flip or delay bytes. Nothing here trusts it. The adapter
//! host's protocol runs on the channel unchanged, and its orders are signed,
//! session-bound and single-use (spec 19), so a channel that lies can only
//! make execution fail.
//!
//! The VMM drops bytes that arrive before a guest's virtio console is up. So
//! before the protocol starts, the two sides shake hands, with lines of their
//! own that the node never sees:
//!
//! ```text
//! adapter guest: HELLO, again and again       core's guest: (waits for HELLO)
//!                                              START, for each HELLO
//! adapter guest: READY, once                  (STARTs still in flight)
//!                                              the protocol
//! ```
//!
//! Every HELLO is written before READY, so the core's guest answers its last
//! START before it reads READY, and the protocol's first byte follows READY.
//! The adapter guest drops the STARTs that were still in flight: up to the
//! protocol, the only lines on its side are STARTs.

// each guest uses its own half: the core connects, the adapter guest accepts
#![allow(dead_code)]

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const PATH: &str = "/dev/chitala-channel";
const HELLO: &str = "CHITALA-CHANNEL HELLO";
const START: &str = "CHITALA-CHANNEL START";
const READY: &str = "CHITALA-CHANNEL READY";
/// The longest handshake line accepted; a longer one is not a handshake.
const MAX_LINE: usize = 64;

/// Whether this guest has a channel: a virtio console joined to a relay.
pub fn present() -> bool {
    Path::new(PATH).exists()
}

/// A handle on the channel. Each use opens its own (the kernel's channel
/// keeps one queue of what was received, so handles share it); a handle is
/// never duplicated.
pub fn open() -> io::Result<File> {
    OpenOptions::new().read(true).write(true).open(PATH)
}

fn step<T>(what: &str, r: io::Result<T>) -> io::Result<T> {
    r.map_err(|e| io::Error::new(e.kind(), format!("{what}: {e}")))
}

/// One line, read a byte at a time, so nothing after its newline is consumed.
/// A line longer than a handshake line is read to its end and returned cut.
fn read_line(r: &mut impl Read) -> io::Result<String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if r.read(&mut byte)? == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the channel closed"));
        }
        match byte[0] {
            b'\n' => return Ok(String::from_utf8_lossy(&line).into_owned()),
            b if line.len() < MAX_LINE => line.push(b),
            _ => {}
        }
    }
}

/// The core's side: wait for the adapter guest's HELLO, answer START to each
/// HELLO, and return once READY has come. Blocks until the other guest is up.
pub fn connect(input: &mut File, output: &mut File) -> io::Result<()> {
    loop {
        match step("read", read_line(input))?.as_str() {
            HELLO => step("write START", writeln!(output, "{START}"))?,
            READY => return Ok(()),
            // the tail of an earlier session, or bytes the relay made up
            _ => {}
        }
    }
}

/// The adapter guest's side: say HELLO until the core's guest says START,
/// then READY, once. Writes are serialised, so no HELLO follows READY.
/// Returns the bytes of the protocol already read, which come first.
pub fn accept() -> io::Result<Vec<u8>> {
    let ready = Arc::new(Mutex::new(false));
    let mut hello_out = step("open for HELLO", open())?;
    let hello_ready = Arc::clone(&ready);
    std::thread::spawn(move || loop {
        {
            let done = hello_ready.lock().unwrap_or_else(|p| p.into_inner());
            if *done || writeln!(hello_out, "{HELLO}").is_err() {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    });
    let mut input = step("open for reading", open())?;
    let mut out = step("open for READY", open())?;
    loop {
        if step("read", read_line(&mut input))? == START {
            let mut done = ready.lock().unwrap_or_else(|p| p.into_inner());
            *done = true;
            step("write READY", writeln!(out, "{READY}"))?;
            return step("read", skip_starts(&mut input));
        }
    }
}

/// Drops whole START lines, and returns the bytes read once one differs: the
/// start of the protocol.
fn skip_starts(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let start = format!("{START}\n").into_bytes();
    let mut read = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if r.read(&mut byte)? == 0 {
            return Ok(read);
        }
        read.push(byte[0]);
        if !start.starts_with(&read) {
            return Ok(read);
        }
        if read.len() == start.len() {
            read.clear();
        }
    }
}
