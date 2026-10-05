#!/usr/bin/env python3
"""Chitala v0.3 step ③A: virtual Matter devices behind a real Home Assistant.

Chitala → Home Assistant (adapter) → Home Assistant's Matter integration →
OHF Matter Server (matter.js) → virtual devices from the Matter SDK
(connectedhomeip). Each scenario is checked against Home Assistant's states,
its `call_service` events, the device's own log, and Chitala's audit log.
Losing a device or the controller must reach Chitala as one thing:
observability lost (spec 10, F6).

    CHITALA_BIN=... CHITALA_CONFIG=... python3 regression_matter.py

Expects the lab home of configure_node.py --matter, the devices of
run_devices.sh commissioned with commission.py, and the Home Assistant lab next
to this directory (../ha, with regression.py).
"""

import os
import re
import signal
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
HA_LAB = os.environ.get("HA_DIR", os.path.join(HERE, "..", "ha"))
sys.path.insert(0, HA_LAB)
import regression as r  # noqa: E402  (the Home Assistant lab's helpers)

M_LIGHT, M_PLUG, M_LOCK = "device:matter-light", "device:matter-plug", "device:matter-lock"
E_LIGHT, E_PLUG, E_LOCK = "light.test_product", "switch.test_product", "lock.test_product"
SERVER = os.path.join(HERE, "server")


def device_log_since(name: str, mark: int) -> str:
    with open(os.path.join(HERE, "logs", f"{name}.log"), errors="replace") as f:
        return "".join(list(f)[mark:])


def device_mark(name: str) -> int:
    with open(os.path.join(HERE, "logs", f"{name}.log"), errors="replace") as f:
        return sum(1 for _ in f)


def device_pid(name: str) -> int | None:
    try:
        pid = int(open(os.path.join(HERE, "state", f"{name}.pid")).read())
        os.kill(pid, 0)
        return pid
    except (OSError, ValueError):
        return None


def devices(cmd: str) -> None:
    subprocess.run(["./run_devices.sh", cmd], cwd=HERE, env={**os.environ, "SDK_OUT": os.path.join(HERE, "connectedhomeip", "out")},
                   capture_output=True)


def restart_devices() -> None:
    """Start the devices that are down. A device killed a moment ago may not
    bind its port yet (macOS keeps it in TIME_WAIT): try again until it stays up."""
    for _ in range(20):
        devices("start")
        time.sleep(4)
        if all(device_pid(n) for n in ("light", "plug", "lock")):
            return
        time.sleep(6)


def wait_ha(entity: str, want: str | None = None, avoid: str | None = None, timeout: float = 120) -> float | None:
    """Seconds until Home Assistant shows `entity` in state `want` (or out of `avoid`)."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        s = r.ha_state(entity)
        if (want and s == want) or (avoid and s != avoid):
            return time.time() - t0
        time.sleep(1)
    return None


def server_pid() -> int | None:
    p = subprocess.run(["lsof", "-nP", "-iTCP:5580", "-sTCP:LISTEN", "-t"], capture_output=True, text=True)
    return int(p.stdout.split()[0]) if p.stdout.split() else None


def server_stop() -> None:
    pid = server_pid()
    if pid:
        os.kill(pid, signal.SIGINT)
        for _ in range(30):
            if not server_pid():
                break
            time.sleep(1)


def server_start() -> None:
    log = open(os.path.join(SERVER, "matter-server.out"), "a")
    subprocess.Popen(["node", "--enable-source-maps", "node_modules/matter-server/dist/esm/MatterServer.js",
                      "--storage-path", os.path.join(SERVER, "storage"), "--listen-address", "127.0.0.1",
                      "--port", "5580", "--enable-test-net-dcl", "--log-file", os.path.join(SERVER, "matter-server.log")],
                     cwd=SERVER, stdout=log, stderr=log, start_new_session=True)
    for _ in range(60):
        if server_pid():
            return
        time.sleep(1)


def settled(mark: int, resource: str, timeout: float = 15) -> str | None:
    """The outcome of the last action on `resource` since `mark`: at once, or
    once it settles. Followed by its own id: an earlier action's outcome (say,
    superseded by this one) is not this action's."""
    end = time.time() + timeout
    while time.time() < end:
        ex = [e for e in r.audit_since(mark, "execution") if (e.get("verification") or {}).get("resource") == resource]
        if ex:
            mine = ex[-1]
            if mine["verification"]["status"] != "pending":
                return mine["verification"]["status"]
            out = [o for o in r.audit_since(mark, "outcome") if o.get("mid") == mine.get("mid")]
            if out:
                return out[-1]["status"]
        time.sleep(0.5)
    return None


def mt1_light() -> None:
    r.c("invoke", "--as", "person:alice", M_LIGHT, "light.turn_off")
    time.sleep(2)
    for cap, want, action in (("light.turn_on", "on", "ON_ACTION"), ("light.turn_off", "off", "OFF_ACTION")):
        m, d = r.audit_mark(), device_mark("light")
        first, _ = r.c("invoke", "--as", "person:alice", M_LIGHT, cap)
        status = settled(m, "resource:matter-light")
        ok = first == "ALLOW" and status == "verified" and r.ha_state(E_LIGHT) == want
        ok = ok and action in device_log_since("light", d)
        r.check(f"MT1 {cap} on a Matter light: verified; Home Assistant and the device agree", ok, f"{first} {status}")


def mt2_plug() -> None:
    r.c("invoke", "--as", "person:alice", M_PLUG, "switch.turn_off")
    time.sleep(2)
    for cap, want in (("switch.turn_on", "on"), ("switch.turn_off", "off")):
        m = r.audit_mark()
        first, _ = r.c("invoke", "--as", "person:alice", M_PLUG, cap)
        status = settled(m, "resource:matter-plug")
        r.check(f"MT2 {cap} on a Matter plug: verified; Home Assistant agrees",
                first == "ALLOW" and status == "verified" and r.ha_state(E_PLUG) == want, f"{first} {status}")


def mt3_lock() -> None:
    r.c("delegate", "--as", "person:alice", "--to", "ai:assistant", "resource:matter-door", "lock.unlock")
    first, out = r.c("intent", "--as", "ai:assistant", "resource:matter-door", "lock.unlock", "--purpose", "matter")
    intent = re.search(r"intent ([0-9a-f]{32})", out)
    r.check("MT3a an AI's unlock of a Matter lock waits for the owner; still locked",
            first.startswith("ESCALATE") and intent and r.ha_state(E_LOCK) == "locked", first)
    if not intent:
        return
    m, d = r.audit_mark(), device_mark("lock")
    _, out = r.c("approve", "--as", "person:alice", intent.group(1))
    first = next((line for line in out.splitlines() if line.startswith(("ALLOW", "DENY"))), out[:80])
    status = settled(m, "resource:matter-door")
    log = device_log_since("lock", d)
    ok = first == "ALLOW" and status == "verified" and r.ha_state(E_LOCK) == "unlocked" and "unlock" in log.lower()
    r.check("MT3b approved: the Matter lock unlocks (a timed invoke), verified", ok, f"{first} {status}")
    time.sleep(61)  # SAFE-6
    m = r.audit_mark()
    first, _ = r.c("invoke", "--as", "person:alice", M_LOCK, "lock.lock")
    status = settled(m, "resource:matter-door")
    r.check("MT3c the owner locks it again: verified", first == "ALLOW" and status == "verified"
            and r.ha_state(E_LOCK) == "locked", f"{first} {status}")


def mt4_by_hand() -> None:
    fifo = os.path.join(HERE, "state", "lock.fifo")
    with open(fifo, "w") as f:
        f.write('{"Cmd": "Unlock", "Params": {"EndpointId": 1, "OperationSource": 1}}\n')
    seen = wait_ha(E_LOCK, want="unlocked", timeout=30)
    v = r.view(M_LOCK)  # the node looks
    r.check("MT4 unlocked by hand, outside Chitala: Home Assistant and Chitala's witness follow",
            seen is not None and v["reported"].get("locked") is False, f"seen={seen} reported={v.get('reported')}")
    with open(fifo, "w") as f:
        f.write('{"Cmd": "Lock", "Params": {"EndpointId": 1, "OperationSource": 1}}\n')
    wait_ha(E_LOCK, want="locked", timeout=30)
    r.view(M_LOCK)


def mt5_unreachable() -> None:
    time.sleep(61)  # SAFE-6
    r.wait_fresh(M_LOCK)
    pid = device_pid("lock")
    os.kill(pid, signal.SIGKILL)
    died = time.time()
    # F9: until Home Assistant notices, it serves the dead lock's last state as current
    time.sleep(5)
    v = r.view(M_LOCK)
    m, k = r.audit_mark(), r.calls_mark()
    first, _ = r.c("invoke", "--as", "person:alice", M_LOCK, "lock.unlock")
    time.sleep(15)
    outcomes = [o["status"] for o in r.audit_since(m, "outcome") if o.get("resource") == "resource:matter-door"]
    ex = r.audit_since(m, "execution")
    verification = (ex[-1].get("verification") or {}).get("status") if ex else None
    recovery = any(x["kind"] == "safety" for x in r.audit_since(m))
    calls = [x for x in r.calls_since(k) if E_LOCK in x]
    final = outcomes[-1] if outcomes else verification
    print(f"      (F9 window: 5 s after the lock died Chitala saw freshness={v.get('freshness')} "
          f"reported={v.get('reported')}; the unlock: {first[:80]}; final={final} recovery={recovery} calls={len(calls)})")
    # the dead lock cannot say what happened: whatever Home Assistant shows
    # (its cache, its optimistic `unlocking`) is no evidence of the order (F9)
    ok = len(calls) <= 1 and ((final == "unconfirmed" and recovery) or first.startswith("DENY"))
    r.check("MT5a F9: a command in the window before the controller notices: unconfirmed, recovery, no blind "
            "command", ok, f"{first[:70]} final={final} recovery={recovery}")
    if recovery:  # F6 is checked on its own: Safety's state rule, not the recovery
        r.c("release", "--as", "person:alice", "resource:matter-door")
    k = r.calls_mark()
    after = wait_ha(E_LOCK, want="unavailable", timeout=900)  # 250 to 431 s seen (F9)
    v = r.view(M_LOCK)
    first, _ = r.c("invoke", "--as", "person:alice", M_LOCK, "lock.unlock")
    ok = after is not None and v.get("freshness") == "unknown" and "SAFE-3-STATE" in first
    ok = ok and not [x for x in r.calls_since(k) if E_LOCK in x]
    r.check("MT5 a Matter lock that drops off: observability lost, the unlock refused, nothing sent", ok,
            f"unavailable after {after and round(after)} s; freshness={v.get('freshness')}; {first}")
    print(f"      (Home Assistant showed the lock unavailable {round(time.time() - died)} s after it died)")
    restart_devices()
    back = wait_ha(E_LOCK, avoid="unavailable", timeout=300)
    fresh = r.wait_fresh(M_LOCK, timeout=60)
    r.check("MT5b back: the lock is observed again", back is not None and fresh, f"back={back} fresh={fresh}")
    r.c("release", "--as", "person:alice", "resource:matter-door")


def mt6_controller_lost() -> None:
    k = r.calls_mark()
    server_stop()
    after = wait_ha(E_LIGHT, want="unavailable", timeout=120)
    v = r.view(M_LOCK)
    f_lock, _ = r.c("invoke", "--as", "person:alice", M_LOCK, "lock.unlock")
    ok = after is not None and v.get("freshness") == "unknown" and "SAFE-3-STATE" in f_lock
    ok = ok and not [x for x in r.calls_since(k) if E_LOCK in x]
    r.check("MT6 the Matter controller is lost: every Matter device unobservable, the door refused", ok,
            f"unavailable after {after and round(after)} s; {f_lock}")
    m = r.audit_mark()
    f_light, _ = r.c("invoke", "--as", "person:alice", M_LIGHT, "light.turn_on")
    time.sleep(4)
    statuses = [o["status"] for o in r.audit_since(m, "outcome")]
    ok = ("X_" in f_light or "DENY" in f_light) and not [x for x in r.audit_since(m) if x["kind"] == "safety"]
    r.check("MT6b a light command meanwhile: not done, never recovery (low risk)", ok, f"{f_light[:90]} {statuses}")
    server_start()
    back = wait_ha(E_LIGHT, avoid="unavailable", timeout=180)
    fresh = r.wait_fresh(M_LOCK, timeout=60) and r.wait_fresh(M_LIGHT, timeout=60)
    r.check("MT6c the controller is back: the devices are observed again", back is not None and fresh,
            f"back={back} fresh={fresh}")


def mt7_dies_after_command() -> None:
    time.sleep(61)  # SAFE-6
    r.wait_fresh(M_LOCK)
    m, k = r.audit_mark(), r.calls_mark()
    out: dict = {}
    t = threading.Thread(target=lambda: out.setdefault("r", r.c("invoke", "--as", "person:alice", M_LOCK, "lock.unlock")))
    t.start()
    time.sleep(0.3)
    os.kill(device_pid("lock"), signal.SIGKILL)
    t.join()
    time.sleep(12)
    statuses = [o["status"] for o in r.audit_since(m, "outcome") if o.get("resource") == "resource:matter-door"]
    ex = [e for e in r.audit_since(m, "execution")]
    verification = (ex[-1].get("verification") or {}).get("status") if ex else None
    calls = [x for x in r.calls_since(k) if "lock." in x]
    recovery = any(x["kind"] == "safety" for x in r.audit_since(m))
    final = statuses[-1] if statuses else verification
    consistent = (final in ("verified", "applied") and not recovery) or (final == "unconfirmed" and recovery) \
        or (final == "not_applied" and not recovery) or (out["r"][0].startswith("DENY") and not calls)
    r.check("MT7 the lock dies right after a command: one call at most, never resent, an outcome that matches",
            len(calls) <= 1 and consistent, f"{out['r'][0][:70]} final={final} recovery={recovery} calls={calls}")
    restart_devices()
    wait_ha(E_LOCK, avoid="unavailable", timeout=300)
    r.wait_fresh(M_LOCK, timeout=60)
    if recovery:
        r.c("release", "--as", "person:alice", "resource:matter-door")


def ha_ms(stamp: str) -> int:
    """A Home Assistant timestamp (UTC) in ms since the epoch."""
    from datetime import datetime
    return int(datetime.fromisoformat(stamp).timestamp() * 1000)


class Watch:
    """Home Assistant's states of the lock, as they change, with their `last_updated`."""

    def __init__(self) -> None:
        self.seen: list[tuple[float, str, int]] = []
        self.t0 = time.time()
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run)
        self._t.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                st = r.ha_req("GET", f"/api/states/{E_LOCK}")
                if not self.seen or self.seen[-1][1] != st["state"]:
                    self.seen.append((round(time.time() - self.t0, 1), st["state"], ha_ms(st["last_updated"])))
            except Exception:  # noqa: BLE001 — a missed poll is retried
                pass
            time.sleep(0.3)

    def stop(self) -> list[tuple[float, str, int]]:
        self._stop.set()
        self._t.join()
        return self.seen

    def at(self, state: str, after: str | None = None) -> tuple[float, str, int] | None:
        """The first time `state` was seen (after `after`, if given)."""
        states = [x[1] for x in self.seen]
        start = states.index(after) if after in states else (0 if after is None else len(states))
        return next((x for x in self.seen[start:] if x[1] == state), None)


def mt8_lock_a_dead_lock() -> None:
    """F9b: when a Matter lock does not confirm a command, Home Assistant
    writes back the value it held, with a new timestamp, 30 s later (its
    optimistic timer; homeassistant/components/matter/lock.py). Only the lock
    itself can confirm a state, and a dead one does not answer."""
    # a: what the adapter says on the real Home Assistant. A live device's
    # state, confirmed by the device after an outcome; the dead lock's
    # re-emitted state, fresh, and not confirmed
    r.c("invoke", "--as", "person:alice", M_LIGHT, "light.turn_off")
    time.sleep(2)
    m = r.audit_mark()
    first, _ = r.c("invoke", "--as", "person:alice", M_LIGHT, "light.turn_on")  # a change: a new report
    status = settled(m, "resource:matter-light")
    light = r.view(M_LIGHT)
    time.sleep(61)  # SAFE-6
    fifo = os.path.join(HERE, "state", "lock.fifo")
    with open(fifo, "w") as f:  # unlocked by hand: no Chitala action, no SAFE-6
        f.write('{"Cmd": "Unlock", "Params": {"EndpointId": 1, "OperationSource": 1}}\n')
    wait_ha(E_LOCK, want="unlocked", timeout=30)
    r.wait_fresh(M_LOCK)
    os.kill(device_pid("lock"), signal.SIGKILL)
    time.sleep(3)
    w = Watch()
    m, k = r.audit_mark(), r.calls_mark()
    first_a, _ = r.c("invoke", "--as", "person:alice", M_LOCK, "lock.lock")
    while time.time() - w.t0 < 40 and not w.at("unlocked", after="locking"):
        time.sleep(1)
    time.sleep(2)
    lock = r.view(M_LOCK)
    seen = w.stop()
    outcomes = [o["status"] for o in r.audit_since(m, "outcome") if o.get("resource") == "resource:matter-door"]
    recovery = any(x["kind"] == "safety" for x in r.audit_since(m))
    calls = [x for x in r.calls_since(k) if E_LOCK in x]
    print(f"      (Home Assistant showed {[x[:2] for x in seen]}; the lock: {first_a[:60]}; outcome={outcomes} "
          f"recovery={recovery}; the lock's twin: source_at_ms={lock.get('source_at_ms')} "
          f"confirmed_at_ms={lock.get('confirmed_at_ms')}; the light's: {status}, "
          f"confirmed_at_ms={light.get('confirmed_at_ms')})")
    reverted = w.at("unlocked", after="locking")
    ok = status == "verified" and light.get("confirmed_at_ms") is not None
    ok = ok and reverted is not None and lock.get("source_at_ms") is not None and lock.get("confirmed_at_ms") is None
    ok = ok and len(calls) <= 1 and outcomes[-1:] == ["unconfirmed"] and recovery
    r.check("MT8a F9b: a live device's state is confirmed by the device; a dead lock's state written again by Home "
            "Assistant is fresh but not confirmed; unconfirmed, recovery", ok,
            f"light={status} reverted={reverted and reverted[0]} outcome={outcomes}")
    r.c("release", "--as", "person:alice", "resource:matter-door")

    # b: the same revert inside an outcome's window. The node goes down before
    # the outcome's deadline and is back 15 s later: a restored outcome gets a
    # fresh window (5 s), and the revert at 30 s falls inside it
    time.sleep(max(0.0, 61 - (time.time() - w.t0)))  # SAFE-6
    r.wait_fresh(M_LOCK)
    w = Watch()
    m, k = r.audit_mark(), r.calls_mark()
    first_b, _ = r.c("invoke", "--as", "person:alice", M_LOCK, "lock.lock")
    locking = w.at("locking")
    begun = w.t0 + (locking[0] if locking else 0)
    time.sleep(max(0.0, begun + 12 - time.time()))
    pid = r.node_pid()
    if pid:
        os.kill(pid, signal.SIGTERM)
    time.sleep(max(0.0, begun + 26.5 - time.time()))
    r.node_restart()
    while time.time() - begun < 45:
        time.sleep(1)
    seen = w.stop()
    outs = [o for o in r.audit_since(m, "outcome") if o.get("resource") == "resource:matter-door"]
    recovery = any(x["kind"] == "safety" for x in r.audit_since(m))
    calls = [x for x in r.calls_since(k) if E_LOCK in x]
    final = outs[-1]["status"] if outs else None
    reverted = w.at("unlocked", after="locking")
    inside = bool(outs and reverted and reverted[2] < outs[-1]["ts_ms"])
    print(f"      (Home Assistant showed {[x[:2] for x in seen]}; the lock: {first_b[:60]}; final={final} "
          f"recovery={recovery} calls={len(calls)}; the revert {'inside' if inside else 'NOT inside'} the window)")
    ok = inside and len(calls) <= 1 and final == "unconfirmed" and recovery
    r.check("MT8b F9b: the revert inside the window (a restart): unconfirmed, recovery, never not_applied", ok,
            f"{first_b[:60]} final={final} recovery={recovery} inside={inside}")
    restart_devices()
    wait_ha(E_LOCK, avoid="unavailable", timeout=300)
    r.wait_fresh(M_LOCK, timeout=60)
    r.c("release", "--as", "person:alice", "resource:matter-door")


def main() -> int:
    r.ensure_listener()
    r.node_restart()  # the build under test
    restart_devices()
    for d in (M_LIGHT, M_PLUG, M_LOCK):
        r.wait_fresh(d, timeout=90)
    r.c("release", "--as", "person:alice", "resource:matter-door")
    only = sys.argv[sys.argv.index("--only") + 1].split(",") if "--only" in sys.argv else None
    for s in (mt1_light, mt2_plug, mt3_lock, mt4_by_hand, mt5_unreachable, mt6_controller_lost, mt7_dies_after_command,
              mt8_lock_a_dead_lock):
        if only is None or s.__name__.split("_")[0][2:] in only:
            s()
    failed = [x for x in r.results if not x[1]]
    print(f"\n{len(r.results) - len(failed)}/{len(r.results)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
