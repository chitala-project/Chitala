//! The history evaluator in its own process (spec 32).
//!
//! The node starts `chitala-history-evaluator` through the platform's
//! execution host, as it starts adapter hosts, and asks it one question at a
//! time over a typed JSON Lines protocol:
//!
//! - it says hello first: `{"hello": {"protocol": 1, "evaluator": id}}`;
//! - a request is an [`EvalRequest`];
//! - the answer is `{"ok": [signed records]}` or `{"error": why}`.
//!
//! An answer is waited for at most [`EVAL_TIMEOUT`]. An evaluator that does
//! not answer in time, or breaks the protocol, is stopped and started again
//! for the next request. Meanwhile the governed actions are refused
//! (EVALUATOR_UNAVAILABLE): fail closed. The node verifies every record's
//! signature against the authorized evaluator's enrolled key itself
//! (`Node::history_gate`): the process is trusted for its rules, not for
//! anything else.

use std::io::{BufRead, BufReader, Read, Write};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chitala_history::eval::{EvalRequest, HistoryEvaluator};
use chitala_history_check::SignedConstraint;
use chitala_platform::{ComponentHandle, ComponentSpec, ExecutionHost, Spawned};
use serde_json::Value;

/// The protocol's version.
pub const EVAL_PROTOCOL: u64 = 1;
/// The longest wait for an answer.
pub const EVAL_TIMEOUT: Duration = Duration::from_secs(2);
/// The longest line read from the evaluator.
const MAX_LINE: usize = 1 << 20;

struct Running {
    handle: Box<dyn ComponentHandle>,
    input: Box<dyn Write + Send>,
    lines: Receiver<String>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.handle.kill();
    }
}

/// The history evaluator as a separate process.
pub struct ProcessEvaluator {
    exec: Arc<dyn ExecutionHost>,
    spec: ComponentSpec,
    running: Mutex<Option<Running>>,
}

impl ProcessEvaluator {
    pub fn new(exec: Arc<dyn ExecutionHost>, spec: ComponentSpec) -> Self {
        Self { exec, spec, running: Mutex::new(None) }
    }

    fn start(&self) -> Result<Running, String> {
        let Spawned { input, output, handle } =
            self.exec.spawn(&self.spec).map_err(|e| format!("cannot start the history evaluator: {e}"))?;
        let (tx, lines) = mpsc::sync_channel::<String>(4);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(output);
            loop {
                let mut line = String::new();
                match (&mut reader).take(MAX_LINE as u64 + 1).read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(n) if n > MAX_LINE => break,
                    Ok(_) => {
                        if tx.send(line).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        let running = Running { handle, input, lines };
        let hello = recv(&running.lines)?;
        let hello: Value = serde_json::from_str(&hello).map_err(|_| "the evaluator's hello is not JSON".to_string())?;
        if hello["hello"]["protocol"].as_u64() != Some(EVAL_PROTOCOL) {
            return Err(format!("the evaluator speaks another protocol: {hello}"));
        }
        Ok(running)
    }
}

fn recv(lines: &Receiver<String>) -> Result<String, String> {
    lines.recv_timeout(EVAL_TIMEOUT).map_err(|e| match e {
        RecvTimeoutError::Timeout => format!("the history evaluator did not answer in {EVAL_TIMEOUT:?}"),
        RecvTimeoutError::Disconnected => "the history evaluator stopped".to_string(),
    })
}

impl HistoryEvaluator for ProcessEvaluator {
    fn evaluate(&self, req: &EvalRequest) -> Result<Vec<SignedConstraint>, String> {
        let mut slot = self.running.lock().map_err(|_| "the evaluator lock is poisoned".to_string())?;
        if slot.is_none() {
            *slot = Some(self.start()?);
        }
        let running = slot.as_mut().expect("started above");
        let line = serde_json::to_string(req).map_err(|e| e.to_string())?;
        let answer = writeln!(running.input, "{line}")
            .and_then(|()| running.input.flush())
            .map_err(|_| "the history evaluator is not running".to_string())
            .and_then(|()| recv(&running.lines));
        let answer = match answer {
            Ok(a) => a,
            Err(why) => {
                // a hung or dead evaluator is replaced for the next request
                *slot = None;
                return Err(why);
            }
        };
        let v: Value = match serde_json::from_str(&answer) {
            Ok(v) => v,
            Err(_) => {
                *slot = None;
                return Err("the history evaluator broke the protocol".to_string());
            }
        };
        if let Some(why) = v.get("error") {
            return Err(format!("the history evaluator: {}", why.as_str().unwrap_or("error")));
        }
        serde_json::from_value(v["ok"].clone()).map_err(|e| format!("the history evaluator's answer: {e}"))
    }
}
