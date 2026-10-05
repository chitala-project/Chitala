#!/usr/bin/env python3
"""Chitala v0.3 step ③A: the regression on a real Home Assistant.

Runs the scenarios of docs/lab/v0.3-step3a-home-assistant.md against the lab
of this directory and checks each one against independent witnesses: Home
Assistant's own states, its `call_service` events (listen_calls.py), its log,
the logging proxy (tap_proxy.py) and Chitala's audit log. Prints PASS/FAIL per
scenario and exits non-zero on any failure.

    CHITALA_BIN=<dir with chitala, chitala-mcp> CHITALA_CONFIG=<home>/chitala.json \\
        python3 regression.py [--ai]

The node's config is the one configure_node.py writes with --ghosts, its
base_url pointing at the proxy (http://127.0.0.1:8124). `--ai` adds the
scenarios with a real AI (headless Claude Code over MCP). The script starts
and stops Home Assistant (run_hass.sh) and the node itself. No secret is
printed.
"""

import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.environ["CHITALA_BIN"]
CONFIG = os.environ["CHITALA_CONFIG"]
HOME = os.path.dirname(os.path.abspath(CONFIG))
AUDIT = os.path.join(HOME, "audit.audit.jsonl")
HA = os.environ.get("HA_URL", "http://127.0.0.1:8123")
CALLS = os.path.join(HERE, "calls.log")
TAP = os.path.join(HERE, "tap.log")
HA_LOG = os.path.join(HERE, "config", "home-assistant.log")
AI = "--ai" in sys.argv
# --only 11,21: run just these scenarios (by number)
ONLY = next((a.split(",") for a in sys.argv[sys.argv.index("--only") + 1:][:1]), None) if "--only" in sys.argv else None

LIGHT, PLUG, FRONT, BACK = "device:living-room-light", "device:fan-plug", "device:front-door", "device:back-door"
E_LIGHT, E_PLUG, E_FRONT, E_BACK = (
    "light.living_room_rgbww_lights",
    "switch.decorative_lights",
    "lock.front_door",
    "lock.poorly_installed_door",
)

results: list[tuple[str, bool, str]] = []


def token() -> str:
    return open(os.path.join(HERE, "token")).read().strip()


# ─────────────────────────── Chitala ───────────────────────────


def c(*args: str) -> tuple[str, str]:
    """Run the CLI; the summary line and the whole output."""
    p = subprocess.run([os.path.join(BIN, "chitala"), "--config", CONFIG, *args], capture_output=True, text=True)
    out = (p.stdout + p.stderr).strip()
    return (out.splitlines() or [""])[0], out


def view(device: str) -> dict:
    _, out = c("state", "--as", "person:alice", device)
    return json.loads(out[out.index("{") : out.rindex("}") + 1])


def audit_mark() -> int:
    return sum(1 for _ in open(AUDIT))


def audit_since(mark: int, kind: str | None = None) -> list[dict]:
    with open(AUDIT) as f:
        records = [json.loads(line) for line in list(f)[mark:]]
    return [r for r in records if kind is None or r["kind"] == kind]


def wait_fresh(device: str, timeout: float = 45) -> bool:
    """The node has a current observation of `device` (F5 spaces retries up to 30 s)."""
    end = time.time() + timeout
    while time.time() < end:
        if view(device).get("freshness") == "fresh":
            return True
        time.sleep(1)
    return False


def node_pid() -> int | None:
    p = subprocess.run(["lsof", "-t", os.path.join(HOME, "chitala.sock")], capture_output=True, text=True)
    pids = [int(x) for x in p.stdout.split() if x.strip()]
    return pids[0] if pids else None


def node_restart() -> None:
    pid = node_pid()
    if pid:
        os.kill(pid, signal.SIGTERM)
        time.sleep(2)
    env = {**os.environ, "CHITALA_CONFIG": CONFIG, "CHITALA_HA_TOKEN": token()}
    log = open(os.path.join(HOME, "node.log"), "a")
    subprocess.Popen([os.path.join(BIN, "chitala"), "node"], cwd=HOME, env=env, stdout=log, stderr=log,
                     start_new_session=True)
    time.sleep(3)


# ─────────────────────────── Home Assistant ───────────────────────────


def ha_req(method: str, path: str, body: dict | None = None, tok: str | None = None):
    req = urllib.request.Request(HA + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {tok or token()}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read() or b"null")


def ha_state(entity: str) -> str:
    return ha_req("GET", f"/api/states/{entity}")["state"]


def ha_set(entity: str, state: str) -> None:
    ha_req("POST", f"/api/states/{entity}", {"state": state})


def ha_pid() -> int | None:
    p = subprocess.run(["lsof", "-nP", "-iTCP:8123", "-sTCP:LISTEN", "-t"], capture_output=True, text=True)
    pids = [int(x) for x in p.stdout.split() if x.strip()]
    return pids[0] if pids else None


def ha_up(timeout: float = 120) -> bool:
    """Home Assistant answers (without a token: an unauthenticated probe would
    count as a failed login)."""
    end = time.time() + timeout
    while time.time() < end:
        try:
            urllib.request.urlopen(HA + "/manifest.json", timeout=2)
            return True
        except OSError:
            time.sleep(1)
    return False


def ha_start() -> None:
    log = open(os.path.join(HERE, "hass.out"), "a")
    subprocess.Popen(["./run_hass.sh"], cwd=HERE, stdout=log, stderr=log, start_new_session=True)
    ha_up()


def ha_kill() -> None:
    pid = ha_pid()
    if pid:
        os.kill(pid, signal.SIGKILL)
    end = time.time() + 15
    while ha_pid() and time.time() < end:
        time.sleep(0.2)


def tap_pid() -> int | None:
    p = subprocess.run(["lsof", "-nP", "-iTCP:8124", "-sTCP:LISTEN", "-t"], capture_output=True, text=True)
    pids = [int(x) for x in p.stdout.split() if x.strip()]
    return pids[0] if pids else None


def tap_start() -> None:
    if not tap_pid():
        subprocess.Popen([os.path.join(HERE, "venv", "bin", "python"), "tap_proxy.py", TAP], cwd=HERE,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        time.sleep(1)


def tap_kill() -> None:
    pid = tap_pid()
    if pid:
        os.kill(pid, signal.SIGKILL)
        time.sleep(0.5)


def supervised() -> bool:
    return subprocess.run(["pgrep", "-f", "run_hass.sh"], capture_output=True).returncode == 0


def calls_mark() -> int:
    return sum(1 for _ in open(CALLS)) if os.path.exists(CALLS) else 0


def calls_since(mark: int) -> list[str]:
    with open(CALLS) as f:
        lines = list(f)[mark:]
    return [line.split(" ", 1)[1].strip() for line in lines if " listening" not in line and "disconnected" not in line]


def ensure_listener() -> None:
    if subprocess.run(["pgrep", "-f", "listen_calls.py"], capture_output=True).returncode != 0:
        subprocess.Popen([os.path.join(HERE, "venv", "bin", "python"), "listen_calls.py", CALLS], cwd=HERE,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        time.sleep(3)


def tap_lines_since(t0: str) -> list[str]:
    with open(TAP) as f:
        return [line for line in f if line[:15] >= t0 and " -> " in line]


def failed_logins_since(t0: str) -> int:
    """Failed logins Home Assistant counted for Chitala: its REST client
    (ureq) and its link (no user agent); not the lab's own tools."""
    with open(HA_LOG) as f:
        return sum(1 for line in f if "invalid authentication" in line and line[11:19] >= t0
                   and ("(ureq" in line or "(None)" in line))


def now_hms() -> str:
    return time.strftime("%H:%M:%S")


# ─────────────────────────── scenarios ───────────────────────────


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, bool(ok), detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  — {detail}" if detail and not ok else ""), flush=True)


def s1_person_light() -> None:
    # a command that changes something: one that changes nothing gets no new
    # report, and without one nothing proves its effect (F9)
    cap, want = ("light.turn_on", "on") if ha_state(E_LIGHT) == "off" else ("light.turn_off", "off")
    m = audit_mark()
    first, _ = c("invoke", "--as", "person:alice", LIGHT, cap)
    ex = audit_since(m, "execution")
    ok = first == "ALLOW" and ex and ex[-1]["verification"]["status"] == "verified" and ha_state(E_LIGHT) == want
    check(f"1 a person switches the light ({cap}): verified, and Home Assistant agrees", ok, first)


def s2_ai_token() -> None:
    if ha_state(E_LIGHT) != "off":
        c("invoke", "--as", "person:alice", LIGHT, "light.turn_off")
    k = calls_mark()
    first, _ = c("intent", "--as", "ai:guest-assistant", "resource:living-room-light", "light.turn_on")
    check("2a an AI without a token is denied, the light untouched",
          "E_TOKEN_MISSING" in first and ha_state(E_LIGHT) == "off" and not calls_since(k), first)
    c("delegate", "--as", "person:alice", "--to", "ai:assistant", "resource:living-room-light", "light.turn_on")
    first, _ = c("intent", "--as", "ai:assistant", "resource:living-room-light", "light.turn_on")
    check("2b with a token: allowed, the light on", first == "ALLOW" and ha_state(E_LIGHT) == "on", first)


def s3_escalate() -> None:
    c("delegate", "--as", "person:alice", "--to", "ai:assistant", "resource:front-door", "lock.unlock")
    first, out = c("intent", "--as", "ai:assistant", "resource:front-door", "lock.unlock", "--purpose", "regression")
    intent = re.search(r"intent ([0-9a-f]{32})", out)
    ok = first.startswith("ESCALATE") and intent and ha_state(E_FRONT) == "locked"
    check("3a the AI's unlock waits for the owner; the door stays locked", ok, first)
    if not intent:
        return
    m = audit_mark()
    _, out = c("approve", "--as", "person:alice", intent.group(1))
    first = next((line for line in out.splitlines() if line.startswith(("ALLOW", "DENY"))), out[:80])
    ex = audit_since(m, "execution")
    ok = first == "ALLOW" and ha_state(E_FRONT) == "unlocked" and ex and ex[-1]["verification"]["status"] == "verified"
    check("3b approved: unlocked, verified by the witness", ok, first)


def s4_jam() -> None:
    m, k = audit_mark(), calls_mark()
    c("invoke", "--as", "person:alice", BACK, "lock.lock")
    end = time.time() + 25  # two outcomes, each within 5 s of its order
    while len(audit_since(m, "outcome")) < 2 and time.time() < end:
        time.sleep(1)
    time.sleep(3)  # and nothing after them
    outcomes = audit_since(m, "outcome")
    safe = [d for d in audit_since(m, "decision") if d.get("safe_state")]
    locks = [x for x in calls_since(k) if E_BACK in x]
    ok = (
        [o["status"] for o in outcomes] == ["diverged", "diverged"]
        and len(safe) == 1
        and len(locks) == 2
        and any(r["kind"] == "safety" for r in audit_since(m))
    )
    check("4 the jamming lock: diverged, recovery, one safe-state attempt, nothing more", ok,
          f"outcomes={[o['status'] for o in outcomes]} safe={len(safe)} calls={locks}")


def s5_recovery_refuses() -> None:
    k = calls_mark()
    first, _ = c("invoke", "--as", "person:alice", BACK, "lock.unlock")
    check("5 a normal unlock during recovery is refused (SAFE-8), nothing sent",
          "SAFE-8-RECOVERY" in first and not calls_since(k), first)


def s13_release() -> None:
    first, out = c("delegate", "--as", "person:alice", "--to", "ai:assistant", "domain:home", "domain.safety_release")
    check("13a an AI can never be given domain.safety_release (C11)", "X_DELEGATION_DENIED" in out, first)
    first, _ = c("release", "--as", "ai:assistant", "resource:back-door")
    check("13b an AI cannot release (intents only)", "E_INTENT_REQUIRED" in first, first)
    first, _ = c("release", "--as", "person:alice", "resource:back-door")
    first2, _ = c("invoke", "--as", "person:alice", BACK, "lock.unlock")
    check("13c the owner releases; the door takes actions again", first == "ALLOW" and first2 == "ALLOW",
          f"{first} / {first2}")


def s6_restart() -> None:
    t0 = now_hms()
    ha_req("POST", "/api/services/homeassistant/restart", {})
    time.sleep(5)
    up = ha_up()
    fresh = up and wait_fresh(LIGHT)
    # the link comes back after its backoff (up to 30 s); until then REST
    # carries commands, and REST dates a state only to the second (F9)
    end = time.time() + 60
    while time.time() < end and not [x for x in tap_lines_since(t0) if "/api/websocket" in x]:
        time.sleep(1)
    time.sleep(2)
    m = audit_mark()
    first, _ = c("invoke", "--as", "person:alice", LIGHT, "light.turn_off")
    ex = audit_since(m, "execution")
    ws = [x for x in tap_lines_since(t0) if "/api/websocket" in x]
    ok = fresh and first == "ALLOW" and ex and ex[-1]["verification"]["status"] == "verified" and ws
    check("6 Home Assistant restarts: the link reconnects and bootstraps, commands are verified", ok,
          f"up={up} fresh={fresh} {first} ws={len(ws)}")


def s7_down() -> None:
    time.sleep(6)  # what is still pending settles first (within_ms ≤ 5 s)
    # the whole host is gone (Home Assistant and the proxy in front of it)
    m, k = audit_mark(), calls_mark()
    ha_kill()
    tap_kill()
    f1, _ = c("invoke", "--as", "person:alice", LIGHT, "light.turn_on")
    f2, _ = c("invoke", "--as", "person:alice", FRONT, "lock.lock")
    ok = all("X_DEVICE_UNAVAILABLE" in f or "SAFE-3-STATE" in f for f in (f1, f2))
    ok = ok and not audit_since(m, "outcome") and not [r for r in audit_since(m) if r["kind"] == "safety"]
    check("7 Home Assistant unreachable: nothing delivered, no outcome, no recovery", ok, f"{f1} / {f2}")
    tap_start()
    # Home Assistant down behind a proxy that still accepts connections (a
    # reverse proxy): a REST command reached the proxy, so its fate is unknown;
    # the door, whose state the node cannot see any more, is refused by Safety
    time.sleep(2)
    view(FRONT)
    m = audit_mark()
    f1, _ = c("invoke", "--as", "person:alice", LIGHT, "light.turn_on")
    f2, _ = c("invoke", "--as", "person:alice", FRONT, "lock.lock")
    time.sleep(4)
    statuses = [o["status"] for o in audit_since(m, "outcome")]
    ok = "X_EXECUTION_UNKNOWN" in f1 and "SAFE-3-STATE" in f2 and statuses == ["unconfirmed"]
    ok = ok and not [r for r in audit_since(m) if r["kind"] == "safety"]
    check("7c Home Assistant down behind a live proxy: the light's fate unknown (low risk: reported), the door "
          "refused (F6)", ok, f"{f1[:70]} / {f2[:70]} / {statuses}")
    ha_start()
    ensure_listener()
    back = wait_fresh(LIGHT) and wait_fresh(FRONT)
    check("7b back up: the node sees its devices again (F5 spaces the attempts)", back and not calls_since(k),
          str(calls_since(k)))


def s11_kill_mid_unlock() -> None:
    if ha_state(E_FRONT) != "locked":
        c("invoke", "--as", "person:alice", FRONT, "lock.lock")
    time.sleep(61)  # out of SAFE-6's window for the door
    wait_fresh(FRONT)
    m, k = audit_mark(), calls_mark()
    out: dict = {}
    t = threading.Thread(target=lambda: out.setdefault("r", c("invoke", "--as", "person:alice", FRONT, "lock.unlock")))
    t.start()
    time.sleep(0.8)
    ha_kill()
    t.join()
    time.sleep(8)
    outcomes = [o["status"] for o in audit_since(m, "outcome")]
    safe = [d for d in audit_since(m, "decision") if d.get("safe_state")]
    unlocks = [x for x in calls_since(k) if "lock.unlock" in x]
    ok = "X_EXECUTION_UNKNOWN" in out["r"][0] and outcomes == ["unconfirmed"] and not safe and len(unlocks) == 1
    ok = ok and any(r["kind"] == "safety" for r in audit_since(m))
    check("11 Home Assistant killed mid-unlock: unknown, recovery, no blind command, one call", ok,
          f"{out['r'][0][:60]} outcomes={outcomes} safe={len(safe)} unlocks={unlocks}")
    k2 = calls_mark()
    ha_start()
    ensure_listener()
    time.sleep(15)
    check("11b back up: nothing resent", not [x for x in calls_since(k2) if "lock." in x], str(calls_since(k2)))
    c("release", "--as", "person:alice", "resource:front-door")


def s12_ghosts() -> None:
    k, m = calls_mark(), audit_mark()
    f1, _ = c("invoke", "--as", "person:alice", "device:ghost-door", "lock.unlock")
    f2, _ = c("invoke", "--as", "person:alice", "device:ghost-door", "lock.lock")
    check("12a a door mapped to a missing entity: refused by Safety (unknown state)",
          "SAFE-3-STATE" in f1 and "SAFE-3-STATE" in f2, f"{f1} / {f2}")
    f3, _ = c("invoke", "--as", "person:alice", "device:ghost-light", "light.turn_on")
    ok = "X_ADAPTER" in f3 and "has no entity" in f3 and not calls_since(k) and not audit_since(m, "outcome")
    check("12b F2: a light mapped to a missing entity is not sent (live inventory)", ok, f3)
    t0 = now_hms()
    time.sleep(20)
    ghost_reads = [x for x in tap_lines_since(t0) if "ghost" in x]
    check("12c F2+F5: no REST read for the missing entities", not ghost_reads, str(ghost_reads[:3]))


def s15_race() -> None:
    c("delegate", "--as", "person:alice", "--to", "ai:assistant", "resource:front-door", "lock.lock")
    wait_fresh(FRONT)
    k = calls_mark()
    out: dict = {}
    t = threading.Thread(target=lambda: out.setdefault("a", c("invoke", "--as", "person:alice", FRONT, "lock.unlock")))
    t.start()
    time.sleep(0.3)
    b, _ = c("intent", "--as", "ai:assistant", "resource:front-door", "lock.lock", "--purpose", "race")
    t.join()
    check("15 two actions on one door: the second is SAFE-7-BUSY, one call",
          out["a"][0] == "ALLOW" and "SAFE-7-BUSY" in b and len(calls_since(k)) == 1, f"{out['a'][0]} / {b}")


def s16_burst() -> None:
    wait_fresh(LIGHT)
    k = calls_mark()
    firsts: list[str] = []
    threads = [
        threading.Thread(target=lambda i=i: firsts.append(
            c("invoke", "--as", "person:alice", LIGHT, "light.turn_on" if i % 2 else "light.turn_off")[0]))
        for i in range(12)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    time.sleep(1)
    allowed = sum(1 for f in firsts if f == "ALLOW")
    busy = sum(1 for f in firsts if "SAFE-7-BUSY" in f)
    calls = len(calls_since(k))
    check("16 a burst of 12: Home Assistant gets exactly the allowed commands",
          allowed >= 1 and allowed + busy == 12 and calls == allowed, f"allowed={allowed} busy={busy} calls={calls}")


def s21_unavailable() -> None:
    if ha_state(E_FRONT) != "locked":
        c("invoke", "--as", "person:alice", FRONT, "lock.lock")
    time.sleep(61)  # out of SAFE-6's window for the door
    wait_fresh(FRONT)
    k = calls_mark()
    ha_set(E_FRONT, "unavailable")
    time.sleep(1)
    v = view(FRONT)
    first, _ = c("invoke", "--as", "person:alice", FRONT, "lock.unlock")
    ok = v.get("freshness") == "unknown" and v["reported"].get("locked") is True and "unobservable_since_ms" in v
    ok = ok and "SAFE-3-STATE" in first and not calls_since(k)
    check("21 F6: a lock Home Assistant reports unavailable is not known to be locked", ok,
          f"freshness={v.get('freshness')} {first}")
    ha_set(E_FRONT, "locked")
    back = wait_fresh(FRONT)
    first, _ = c("invoke", "--as", "person:alice", FRONT, "lock.unlock")
    check("21b F6: available again and observed: the unlock goes through", back and first == "ALLOW", first)
    c("invoke", "--as", "person:alice", FRONT, "lock.lock")


def s20_secrets() -> None:
    t = token()
    files = [AUDIT, os.path.join(HOME, "node.log"), os.path.join(HOME, "domain-state.json"), CONFIG, HA_LOG]
    leaks = [f for f in files if os.path.exists(f) and t in open(f, errors="replace").read()]
    ps = subprocess.run(["ps", "-axww", "-o", "command="], capture_output=True, text=True).stdout
    check("20 the Home Assistant token is in no file and no command line", not leaks and t not in ps, str(leaks))


def s17_revoke() -> None:
    subprocess.run([os.path.join(HERE, "venv", "bin", "python"), "revoke_token.py"], cwd=HERE, capture_output=True)
    m = audit_mark()
    first, _ = c("invoke", "--as", "person:alice", LIGHT, "light.turn_on")
    check("17 a revoked token: the command certainly did not run (X_ADAPTER), no outcome",
          "X_ADAPTER" in first and not audit_since(m, "outcome"), first)
    t0 = now_hms()
    time.sleep(40)
    failed = failed_logins_since(t0)
    rest = [x for x in tap_lines_since(t0) if "/api/states" in x or "/api/services" in x]
    # the gate reopens after 5, 15 and 35 s, one attempt each (before F4: ~240)
    check("18 F4/F5: the rejected token is not presented again and again",
          failed <= 6 and len(rest) <= 8, f"failed logins={failed} REST={len(rest)} in 40 s")
    print(f"      (failed logins in 40 s: {failed}; REST requests: {len(rest)})")
    subprocess.run([os.path.join(HERE, "venv", "bin", "python"), "new_token.py"], cwd=HERE, capture_output=True)
    node_restart()
    wait_fresh(LIGHT)
    first, _ = c("invoke", "--as", "person:alice", LIGHT, "light.turn_off")
    check("19 a new token, the node restarted: back to normal", first == "ALLOW", first)


def claude(prompt: str) -> list[dict]:
    mcp = {"mcpServers": {"chitala": {"command": os.path.join(BIN, "chitala-mcp"),
                                      "args": ["--config", CONFIG, "--as", "ai:assistant"]}}}
    p = subprocess.run(
        ["claude", "-p", prompt, "--tools", "", "--strict-mcp-config", "--mcp-config", json.dumps(mcp),
         "--allowedTools", "mcp__chitala", "--permission-mode", "dontAsk", "--output-format", "stream-json",
         "--verbose"], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=600)
    return [json.loads(line) for line in p.stdout.splitlines() if line.startswith("{")]


def at_home() -> None:
    c("invoke", "--as", "person:alice", FRONT, "lock.unlock")
    c("invoke", "--as", "person:alice", LIGHT, "light.turn_on")
    c("invoke", "--as", "person:alice", PLUG, "switch.turn_on")
    for target, cap in (("resource:living-room-light", "light.turn_off"), ("resource:fan", "switch.turn_off"),
                        ("resource:front-door", "lock.lock")):
        c("delegate", "--as", "person:alice", "--to", "ai:assistant", target, cap)


def s8_ai_leaving() -> None:
    at_home()
    m = audit_mark()
    claude("I'm Alice. I'm leaving home now: please make sure the living room light is off, the fan plug is off "
           "and the front door is locked. Tell me what actually happened.")
    verified = [e for e in audit_since(m, "execution") if e.get("verification", {}).get("status") == "verified"]
    ok = (ha_state(E_LIGHT), ha_state(E_PLUG), ha_state(E_FRONT)) == ("off", "off", "locked") and len(verified) >= 3
    check("8 a real AI, leaving home: three actions, verified; Home Assistant agrees", ok,
          f"{ha_state(E_LIGHT)} {ha_state(E_PLUG)} {ha_state(E_FRONT)} verified={len(verified)}")


def s10_ai_unlock() -> None:
    c("delegate", "--as", "person:alice", "--to", "ai:assistant", "resource:front-door", "lock.unlock")
    m = audit_mark()
    claude("I'm Alice. The plumber is arriving: please unlock the front door. Also send an unlock request for "
           "resource:back-door through chitala_request. Report each answer exactly.")
    records = audit_since(m)
    escalated = [d for d in records if d.get("decision") == "escalate" and d.get("capability") == "lock.unlock"]
    denied = [d for d in records if d.get("decision") == "deny"]
    expired = [d for d in records if "expired" in json.dumps(d)]
    ok = escalated and denied and not expired and ha_state(E_FRONT) == "locked"
    check("10 F3: a real AI uses the right delegated again (escalate), and is denied what it has no right to", ok,
          f"escalated={len(escalated)} denied={len(denied)} expired={len(expired)}")
    for line in c("approvals", "--as", "person:alice")[1].splitlines():
        found = re.search(r'"intent": "([0-9a-f]{32})"', line)
        if found:
            c("approve", "--as", "person:alice", "--reject", found.group(1))


def s14_ai_plan() -> None:
    at_home()
    k, m = calls_mark(), audit_mark()
    claude("I'm Alice, leaving home. Do it as ONE Chitala plan, in this order: living room light off, then the fan "
           "plug off, then lock the front door. Then tell me exactly what Chitala reports for each step.")
    order = [x.split(" ")[0] for x in calls_since(k)]
    verified = [e for e in audit_since(m, "execution") if e.get("verification", {}).get("status") == "verified"]
    ok = order == ["light.turn_off", "switch.turn_off", "lock.lock"] and len(verified) == 3
    check("14 a real AI's plan: three steps in order, each verified, each sent once", ok, str(order))


def main() -> int:
    if not (ha_pid() and supervised()):
        ha_kill()
        ha_start()
    ensure_listener()
    node_restart()  # the build under test
    for r in ("resource:front-door", "resource:back-door"):
        c("release", "--as", "person:alice", r)
    wait_fresh(LIGHT)
    wait_fresh(FRONT)
    scenarios = [s1_person_light, s2_ai_token, s3_escalate, s4_jam, s5_recovery_refuses, s13_release, s6_restart,
                 s7_down, s11_kill_mid_unlock, s12_ghosts, s15_race, s16_burst, s21_unavailable, s20_secrets,
                 s17_revoke]
    if AI:
        scenarios += [s8_ai_leaving, s10_ai_unlock, s14_ai_plan]
    for s in scenarios:
        if ONLY is None or s.__name__[1:].split("_")[0] in ONLY:
            s()
    failed = [r for r in results if not r[1]]
    print(f"\n{len(results) - len(failed)}/{len(results)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
