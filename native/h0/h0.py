#!/usr/bin/env python3
"""H0, the hardware qualification framework (specs/33-hardware-qualification.md).

    native/h0/h0.py check [--self-test]   # the catalogue, manifests, harnesses and kept reports
    native/h0/h0.py plan [--platform ID]  # what each platform is tested for, from its manifest
    native/h0/h0.py run --platform ID [--step ID]... [--fresh] [--out DIR]
    native/h0/h0.py report --platform ID [--out DIR]
    native/h0/h0.py validate REPORT
    native/h0/h0.py established REPORT

A platform has a manifest (platforms/ID.toml): what its hardware has and what
the stack drives, capability by capability. It declares; it never proves. The
plan follows from it: each property of the catalogue (properties.toml) is
required, unsupported, not applicable, or undetermined there.

A platform's harness (harness/ID.toml) has the steps that test it, the
lines of their logs that show each property, and the observations it reads
from them (the entropy provider the core named, for one). `run` runs steps on the N1 Linux
host, keeping each log and the digests of what the step built and booted.
A step that already ran in an output directory is not run again there:
every run counts, and a failure is never retried into a pass (--fresh starts
a new run).

`report` turns the plan, the steps and the build's digests into a report
(chitala.h0.report/1), and `validate` checks it against spec 33's rules:
one result per property, five statuses, nothing that contradicts the plan, no
PASS without evidence and a build binding, and no PASS of a property whose
subject is the hardware on an emulator. `established` lists what a report
establishes: its PASS results, and only on hardware.

Python 3.11 or later, standard library only.
"""

import argparse
import copy
import datetime
import glob
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib

TOOL_VERSION = "0.1"
H0 = pathlib.Path(__file__).resolve().parent
ROOT = H0.parent.parent
CATALOGUE = H0 / "properties.toml"
PLATFORMS = H0 / "platforms"
HARNESSES = H0 / "harness"
REPORTS = H0 / "reports"
SPEC = ROOT / "specs" / "33-hardware-qualification.md"

STATUSES = ("PASS", "FAIL", "NOT_DEMONSTRATED", "UNSUPPORTED", "NOT_APPLICABLE")
PLANNED = ("REQUIRED", "UNSUPPORTED", "NOT_APPLICABLE", "UNDETERMINED")
# what each planned status allows the result to be
ALLOWED = {
    "REQUIRED": ("PASS", "FAIL", "NOT_DEMONSTRATED"),
    "UNSUPPORTED": ("UNSUPPORTED",),
    "NOT_APPLICABLE": ("NOT_APPLICABLE",),
    "UNDETERMINED": ("NOT_DEMONSTRATED",),
}
ENVIRONMENTS = ("emulator", "hardware")
TIERS = ("reference", "1", "2", "experimental")
LAYERS = ("A", "B", "C", "D", "E")
LEVELS = ("platform", "chitala")
SCHEMAS = {
    "properties": "chitala.h0.properties/1",
    "manifest": "chitala.h0.manifest/1",
    "harness": "chitala.h0.harness/1",
    "report": "chitala.h0.report/1",
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
VARIABLE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
EMULATED = ("on the emulator every check of its test held, but its subject is the hardware: "
            "an emulator establishes no hardware property (spec 33, invariant 3)")


class H0Error(Exception):
    pass


# ── reading ───────────────────────────────────────────────────────────────


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def load_toml(path: pathlib.Path) -> dict:
    with open(path, "rb") as f:
        return tomllib.load(f)


def catalogue() -> dict:
    return load_toml(CATALOGUE)


def manifest_path(platform: str) -> pathlib.Path:
    return PLATFORMS / f"{platform}.toml"


def harness_path(platform: str) -> pathlib.Path:
    return HARNESSES / f"{platform}.toml"


def manifest(platform: str) -> dict:
    p = manifest_path(platform)
    if not p.is_file():
        raise H0Error(f"no manifest for {platform} ({p.relative_to(ROOT)})")
    return load_toml(p)


def harness(platform: str) -> dict:
    p = harness_path(platform)
    if not p.is_file():
        raise H0Error(f"no harness for {platform} ({p.relative_to(ROOT)}): it cannot be run yet")
    return load_toml(p)


# ── checking the inputs ───────────────────────────────────────────────────


def check_catalogue(cat: dict, spec_text: str | None = None) -> list:
    problems = []
    if cat.get("schema") != SCHEMAS["properties"]:
        problems.append(f"properties: schema is not {SCHEMAS['properties']}")
    caps = cat.get("capabilities", {})
    if not caps:
        problems.append("properties: no capabilities")
    seen = set()
    for p in cat.get("property", []):
        pid = p.get("id", "?")
        if pid in seen:
            problems.append(f"property {pid}: twice in the catalogue")
        seen.add(pid)
        if p.get("layer") not in LAYERS:
            problems.append(f"property {pid}: layer {p.get('layer')!r} is not one of {LAYERS}")
        if p.get("level") not in LEVELS:
            problems.append(f"property {pid}: level {p.get('level')!r} is not one of {LEVELS}")
        if not isinstance(p.get("hardware_subject"), bool):
            problems.append(f"property {pid}: hardware_subject is not true or false")
        if not p.get("title"):
            problems.append(f"property {pid}: no title")
        needs = p.get("needs", [])
        if not needs:
            problems.append(f"property {pid}: needs no capability")
        for n in needs:
            if n not in caps:
                problems.append(f"property {pid}: needs {n!r}, not a capability of the catalogue")
        observes = p.get("observes", [])
        if not isinstance(observes, list) or not all(isinstance(o, str) and o for o in observes):
            problems.append(f"property {pid}: observes is not a list of names")
        if spec_text is not None and f"`{pid}`" not in spec_text:
            problems.append(f"property {pid}: not in spec 33's table (they change together)")
    if not seen:
        problems.append("properties: none")
    return problems


def check_manifest(m: dict, cat: dict, platform: str | None = None) -> list:
    problems = []
    mid = m.get("id", "?")
    if m.get("schema") != SCHEMAS["manifest"]:
        problems.append(f"manifest {mid}: schema is not {SCHEMAS['manifest']}")
    if platform is not None and mid != platform:
        problems.append(f"manifest {platform}: its id is {mid!r}, not its file's name")
    for field in ("name", "arch"):
        if not m.get(field):
            problems.append(f"manifest {mid}: no {field}")
    if m.get("environment") not in ENVIRONMENTS:
        problems.append(f"manifest {mid}: environment {m.get('environment')!r} is not one of {ENVIRONMENTS}")
    if m.get("tier") not in TIERS:
        problems.append(f"manifest {mid}: tier {m.get('tier')!r} is not one of {TIERS}")
    if "microkit_board" not in m:
        problems.append(f"manifest {mid}: no microkit_board (\"\" when there is none)")
    caps = m.get("capabilities", {})
    for c in cat.get("capabilities", {}):
        v = caps.get(c)
        if v is None:
            problems.append(f"manifest {mid}: capability {c} is not declared")
            continue
        for side in ("hardware", "stack"):
            value = v.get(side)
            if not (value is True or value is False or value == "unknown"):
                problems.append(f"manifest {mid}: capability {c}.{side} is not true, false or \"unknown\"")
        if not v.get("source"):
            problems.append(f"manifest {mid}: capability {c} has no source")
    for c in caps:
        if c not in cat.get("capabilities", {}):
            problems.append(f"manifest {mid}: capability {c} is not in the catalogue")
    return problems


def plan(m: dict, cat: dict) -> dict:
    """Each property's planned status on the platform, with the reason."""
    out = {}
    caps = m.get("capabilities", {})
    for p in cat["property"]:
        lacking, unsupported, unknown = [], [], []
        for n in p["needs"]:
            c = caps.get(n, {})
            hw, stack = c.get("hardware"), c.get("stack")
            if hw is False:
                lacking.append(n)
            elif stack is False:
                unsupported.append(n)
            elif hw == "unknown" or stack == "unknown":
                unknown.append(n)
        why = lambda names: "; ".join(f"{n}: {caps[n]['source']}" for n in names)
        if lacking:
            out[p["id"]] = ("NOT_APPLICABLE", "the hardware lacks " + why(lacking))
        elif unsupported:
            out[p["id"]] = ("UNSUPPORTED", "the stack does not drive " + why(unsupported))
        elif unknown:
            out[p["id"]] = ("UNDETERMINED", "undetermined: " + why(unknown))
        else:
            out[p["id"]] = ("REQUIRED", "required: the hardware has, and the stack drives, " + ", ".join(p["needs"]))
    return out


def check_harness(h: dict, cat: dict, m: dict | None, platform: str | None = None) -> list:
    problems = []
    hid = h.get("platform", "?")
    if h.get("schema") != SCHEMAS["harness"]:
        problems.append(f"harness {hid}: schema is not {SCHEMAS['harness']}")
    if platform is not None and hid != platform:
        problems.append(f"harness {platform}: its platform is {hid!r}, not its file's name")
    if m is None:
        problems.append(f"harness {hid}: no manifest for its platform")
    steps = {}
    for s in h.get("step", []):
        sid = s.get("id", "?")
        if sid in steps:
            problems.append(f"harness {hid}: step {sid} twice")
        steps[sid] = s
        cmd = s.get("command")
        if not cmd or not isinstance(cmd, list) or not all(isinstance(c, str) for c in cmd):
            problems.append(f"harness {hid}: step {sid} has no command (a list of strings)")
    ids = {p["id"] for p in cat.get("property", [])}
    planned = plan(m, cat) if m is not None else {}
    covered = set()
    for e in h.get("evidence", []):
        pid = e.get("property", "?")
        if pid not in ids:
            problems.append(f"harness {hid}: evidence for {pid!r}, not a property of the catalogue")
            continue
        if pid in covered:
            problems.append(f"harness {hid}: two evidence entries for {pid}")
        covered.add(pid)
        if e.get("step") not in steps:
            problems.append(f"harness {hid}: evidence for {pid} names step {e.get('step')!r}, not one of its steps")
        if not e.get("pass"):
            problems.append(f"harness {hid}: evidence for {pid} has no pass lines")
        for rx in list(e.get("pass", [])) + ([e["start"]] if "start" in e else []):
            try:
                re.compile(rx)
            except re.error as err:
                problems.append(f"harness {hid}: evidence for {pid}: /{rx}/ is not a regular expression ({err})")
        if pid in planned and planned[pid][0] in ("UNSUPPORTED", "NOT_APPLICABLE"):
            problems.append(f"harness {hid}: evidence for {pid}, which the manifest rules out ({planned[pid][0]})")
    names = set()
    for o in h.get("observation", []):
        name = o.get("name", "?")
        if name in names:
            problems.append(f"harness {hid}: observation {name} twice")
        names.add(name)
        if o.get("step") not in steps:
            problems.append(f"harness {hid}: observation {name} names step {o.get('step')!r}, not one of its steps")
        try:
            rx = re.compile(o.get("pattern", ""))
            if "value" not in o and rx.groups < 1:
                problems.append(f"harness {hid}: observation {name} has neither a value nor a group to capture")
        except re.error as err:
            problems.append(f"harness {hid}: observation {name}: not a regular expression ({err})")
    by_id = {p["id"]: p for p in cat.get("property", [])}
    for pid in covered:
        for name in by_id.get(pid, {}).get("observes", []):
            if name not in names:
                problems.append(f"harness {hid}: {pid} must name its {name}, and no observation reads it")
    if "static" not in h:
        problems.append(f"harness {hid}: no [static]: a report would bind to nothing")
    return problems


# ── the environment of a harness ──────────────────────────────────────────


def tools_lock(path: pathlib.Path) -> dict:
    values = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            m = re.match(r"^([A-Z][A-Z0-9_]*)=(.*)$", line.strip())
            if m:
                values[m.group(1)] = m.group(2)
    return values


def expand(text: str, variables: dict) -> str:
    def one(m):
        if m.group(1) not in variables:
            raise H0Error(f"${{{m.group(1)}}} is not defined (in {text!r})")
        return variables[m.group(1)]

    return VARIABLE.sub(one, text)


def harness_env(h: dict) -> tuple:
    """(variables for expansion, the environment for the steps).

    A harness's [env] names where things are, for its artifacts and its
    report; it is never passed to the steps. A step runs in the environment
    the harness was started in, plus its own `env`: a default meant for a
    path must not change how a step builds (CARGO_TARGET_DIR, for one, moves
    every cargo build the step makes)."""
    static = h.get("static", {})
    lock = tools_lock(ROOT / static.get("pins_file", "native/spike/tools.lock"))
    variables = dict(os.environ)
    variables.update(lock)
    variables["REPO"] = str(ROOT)
    variables.setdefault("HOME", str(pathlib.Path.home()))
    for key, default in h.get("env", {}).items():
        variables[key] = os.environ[key] if key in os.environ else expand(default, variables)
    return variables, dict(os.environ)


def default_out(platform: str, variables: dict) -> pathlib.Path:
    base = variables.get("N1_BUILD") or str(pathlib.Path.home() / ".cache" / "chitala-n1" / "build")
    return pathlib.Path(base) / "h0" / platform


def shown(path: str) -> str:
    """A path as a report keeps it: under the repository or the home
    directory, without the machine's own prefix."""
    p = os.path.abspath(path)
    for prefix, name in ((str(ROOT), "${REPO}"), (str(pathlib.Path.home()), "~")):
        if p == prefix or p.startswith(prefix + os.sep):
            return name + p[len(prefix):]
    return p


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def hashed(pattern: str) -> list:
    matches = sorted(glob.glob(pattern))
    if not matches:
        return [{"pattern": shown(pattern), "missing": True}]
    return [{"path": shown(p), "sha256": sha256_file(p), "bytes": os.path.getsize(p)} for p in matches if os.path.isfile(p)]


# ── run ───────────────────────────────────────────────────────────────────


def run_step(step: dict, variables: dict, env: dict, out: pathlib.Path) -> dict:
    sid = step["id"]
    (out / "logs").mkdir(parents=True, exist_ok=True)
    (out / "steps").mkdir(parents=True, exist_ok=True)
    record_path = out / "steps" / f"{sid}.json"
    if record_path.exists():
        raise H0Error(f"step {sid} already ran in {out}: every run counts; start a new run with --fresh")
    step_env = dict(env)
    for k, v in step.get("env", {}).items():
        step_env[k] = expand(v, variables)
    log_path = out / "logs" / f"{sid}.log"
    print(f"h0: step {sid}: {' '.join(step['command'])}", flush=True)
    started, t0 = now(), datetime.datetime.now()
    with open(log_path, "wb") as log:
        proc = subprocess.Popen(step["command"], cwd=ROOT, env=step_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in proc.stdout:
            log.write(line)
            sys.stdout.buffer.write(line)
            sys.stdout.flush()
        status = proc.wait()
    commit, dirty = repo_state()
    record = {
        "id": sid,
        "title": step.get("title", ""),
        "repo_commit": commit,
        "repo_dirty": dirty,
        "command": step["command"],
        "env": step.get("env", {}),
        "exit_status": status,
        "started": started,
        "seconds": round((datetime.datetime.now() - t0).total_seconds(), 1),
        "log": f"logs/{sid}.log",
        "log_sha256": sha256_file(log_path),
        "artifacts": [a for pat in step.get("artifacts", []) for a in hashed(expand(pat, variables))],
    }
    if "measurements" in step:
        mp = expand(step["measurements"], variables)
        if os.path.isfile(mp):
            record["measurements"] = {"path": mp, "shown": shown(mp), "sha256": sha256_file(mp)}
    record_path.write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")
    print(f"h0: step {sid}: exit status {status} in {record['seconds']} s", flush=True)
    return record


# ── report ────────────────────────────────────────────────────────────────


def git(*args) -> str | None:
    try:
        return subprocess.run(["git", "-c", f"safe.directory={ROOT}", "-C", str(ROOT), *args],
                              capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None


def repo_state() -> tuple:
    """The repository's commit, and whether its tree differs from it (None if unknown)."""
    commit = (git("rev-parse", "HEAD") or "").strip() or "unknown"
    status = git("status", "--porcelain")
    return commit, None if status is None else bool(status.strip())


def first_line(command: list) -> str:
    try:
        r = subprocess.run(command, capture_output=True, text=True, timeout=30)
        return (r.stdout or r.stderr).strip().splitlines()[0] if (r.stdout or r.stderr).strip() else "unavailable: no output"
    except (OSError, subprocess.SubprocessError) as e:
        return f"unavailable: {e}"


def collect_build(h: dict, variables: dict) -> dict:
    static = h["static"]
    lock = tools_lock(ROOT / static.get("pins_file", "native/spike/tools.lock"))
    build = {
        "pins": {k: lock.get(k) for k in static.get("pins", [])},
        "patches": [{"path": str(pathlib.Path(p).relative_to(ROOT)), "sha256": sha256_file(p)}
                    for pat in static.get("patches", []) for p in sorted(glob.glob(str(ROOT / pat)))],
        "files": [],
        "versions": {v["name"]: first_line(v["command"]) for v in static.get("versions", [])},
    }
    if "kernel_config" in static:
        kp = expand(static["kernel_config"], variables)
        if os.path.isfile(kp):
            with open(kp, encoding="utf-8") as f:
                config = json.load(f)
            build["kernel_config"] = {"path": shown(kp), "sha256": sha256_file(kp),
                                      "options": {o: config.get(o) for o in static.get("kernel_options", [])}}
        else:
            build["kernel_config"] = {"path": shown(kp), "missing": True}
    for f in static.get("files", []):
        p = expand(f["path"], variables)
        if os.path.isfile(p):
            build["files"].append({"name": f["name"], "path": shown(p), "sha256": sha256_file(p), "bytes": os.path.getsize(p)})
        else:
            build["files"].append({"name": f["name"], "path": shown(p), "missing": True})
    return build


def derive_observations(h: dict, steps: dict, logs: dict) -> list:
    """What the harness reads from its steps' logs: a value, with where it came from."""
    out = []
    for o in h.get("observation", []):
        entry = {"name": o["name"], "step": o["step"], "pattern": o["pattern"], "value": None}
        if o["step"] in steps:
            m = re.search(o["pattern"], logs[o["step"]], re.M)
            entry["log_sha256"] = steps[o["step"]]["log_sha256"]
            if m:
                entry["value"] = o.get("value", m.group(1) if m.groups() else None)
        out.append(entry)
    return out


def derive_results(cat: dict, m: dict, h: dict, steps: dict, logs: dict) -> list:
    """Each property's result, from the plan and the logs of the steps that ran."""
    planned = plan(m, cat)
    observed = {o["name"]: o["value"] for o in derive_observations(h, steps, logs)}
    evidence = {e["property"]: e for e in h.get("evidence", [])}
    emulator = m["environment"] == "emulator"
    results = []
    for p in cat["property"]:
        pid = p["id"]
        state, why = planned[pid]
        r = {"property": pid, "layer": p["layer"], "level": p["level"], "hardware_subject": p["hardware_subject"],
             "planned": state, "status": None, "reason": why, "evidence": []}
        if p.get("observes"):
            r["observed"] = {name: observed.get(name) for name in p["observes"]}
        if state == "NOT_APPLICABLE":
            r["status"] = "NOT_APPLICABLE"
        elif state == "UNSUPPORTED":
            r["status"] = "UNSUPPORTED"
        elif state == "UNDETERMINED":
            r["status"] = "NOT_DEMONSTRATED"
        elif pid not in evidence:
            r["status"], r["reason"] = "NOT_DEMONSTRATED", "no test for it in this platform's harness yet"
        elif evidence[pid]["step"] not in steps:
            r["status"], r["reason"] = "NOT_DEMONSTRATED", f"step {evidence[pid]['step']} did not run"
        else:
            e = evidence[pid]
            text = logs[e["step"]]
            found = [bool(re.search(rx, text, re.M)) for rx in e["pass"]]
            r["evidence"] = [{"step": e["step"], "log_sha256": steps[e["step"]]["log_sha256"],
                              "pass": e["pass"], "found": found}]
            unnamed = [name for name, value in r.get("observed", {}).items() if not value]
            if all(found) and unnamed:
                r["status"] = "FAIL"
                r["reason"] = f"every check of its test held, but step {e['step']} named no " + ", no ".join(unnamed)
            elif all(found):
                if p["hardware_subject"] and emulator:
                    r["status"], r["reason"] = "NOT_DEMONSTRATED", EMULATED
                else:
                    r["status"], r["reason"] = "PASS", "every check of its test held"
            elif "start" in e and not re.search(e["start"], text, re.M):
                r["status"], r["reason"] = "NOT_DEMONSTRATED", f"step {e['step']} stopped before this test began"
            else:
                missing = [rx for rx, ok in zip(e["pass"], found) if not ok]
                r["status"] = "FAIL"
                r["reason"] = f"step {e['step']} (exit status {steps[e['step']]['exit_status']}) lacks /" + "/, /".join(missing) + "/"
        results.append(r)
    return results


def read_logs(out: pathlib.Path, steps: dict) -> dict:
    logs = {}
    for sid, s in steps.items():
        p = out / s["log"]
        if sha256_file(p) != s["log_sha256"]:
            raise H0Error(f"the log of step {sid} changed since it ran ({p})")
        logs[sid] = p.read_bytes().decode("utf-8", errors="replace").replace("\r", "")
    return logs


def make_report(platform: str, out: pathlib.Path) -> dict:
    cat, m, h = catalogue(), manifest(platform), harness(platform)
    variables, _ = harness_env(h)
    steps = {}
    order = [s["id"] for s in h.get("step", [])]
    for sid in order:
        p = out / "steps" / f"{sid}.json"
        if p.is_file():
            steps[sid] = json.loads(p.read_text(encoding="utf-8"))
    logs = read_logs(out, steps)
    commit, dirty = repo_state()
    measurements = []
    for s in steps.values():
        if "measurements" in s and os.path.isfile(s["measurements"]["path"]):
            mp = s["measurements"]["path"]
            if sha256_file(mp) == s["measurements"]["sha256"]:
                with open(mp, encoding="utf-8") as f:
                    measurements.append({"step": s["id"], "path": shown(mp), "sha256": s["measurements"]["sha256"], "data": json.load(f)})
    return {
        "schema": SCHEMAS["report"],
        "platform": {
            "id": m["id"], "name": m["name"], "arch": m["arch"], "environment": m["environment"], "tier": m["tier"],
            "microkit_board": m["microkit_board"], "manifest_sha256": sha256_file(manifest_path(platform)),
        },
        "harness": {
            "tool_version": TOOL_VERSION, "tool_sha256": sha256_file(__file__),
            "harness_sha256": sha256_file(harness_path(platform)), "catalogue_sha256": sha256_file(CATALOGUE),
            "repo_commit": commit, "repo_dirty": dirty,
            "generated": now(),
        },
        "build": collect_build(h, variables),
        "steps": [steps[s] for s in order if s in steps],
        "observations": derive_observations(h, steps, logs),
        "results": derive_results(cat, m, h, steps, logs),
        "measurements": measurements,
    }


# ── validate ──────────────────────────────────────────────────────────────


def validate_report(rep: dict, cat: dict | None = None, man: dict | None = None,
                    cat_sha: str | None = None, man_sha: str | None = None) -> list:
    problems = []
    if rep.get("schema") != SCHEMAS["report"]:
        return [f"schema is not {SCHEMAS['report']}"]
    platform = rep.get("platform", {})
    env = platform.get("environment")
    if env not in ENVIRONMENTS:
        problems.append(f"platform: environment {env!r} is not one of {ENVIRONMENTS}")
    steps = {s.get("id"): s for s in rep.get("steps", [])}
    for sid, s in steps.items():
        if not SHA256.match(str(s.get("log_sha256", ""))):
            problems.append(f"step {sid}: no log digest")
    results = rep.get("results", [])
    seen = {}
    for r in results:
        pid = r.get("property", "?")
        if pid in seen:
            problems.append(f"{pid}: two results")
        seen[pid] = r
        status, planned = r.get("status"), r.get("planned")
        if status not in STATUSES:
            problems.append(f"{pid}: status {status!r} is not one of the five")
            continue
        if planned not in PLANNED:
            problems.append(f"{pid}: planned status {planned!r} is not one of {PLANNED}")
            continue
        if status not in ALLOWED[planned]:
            problems.append(f"{pid}: {status} contradicts the plan ({planned})")
        if status != "PASS" and not r.get("reason"):
            problems.append(f"{pid}: {status} without a reason")
        if status == "PASS":
            if not r.get("evidence"):
                problems.append(f"{pid}: PASS without evidence")
            for e in r.get("evidence", []):
                s = steps.get(e.get("step"))
                if s is None:
                    problems.append(f"{pid}: PASS on step {e.get('step')!r}, which did not run")
                    continue
                if e.get("log_sha256") != s.get("log_sha256"):
                    problems.append(f"{pid}: PASS on a log that is not step {s['id']}'s")
                if not e.get("found") or not all(e["found"]) or len(e["found"]) != len(e.get("pass", [])):
                    problems.append(f"{pid}: PASS though a check of its test did not hold")
                if not [a for a in s.get("artifacts", []) if SHA256.match(str(a.get("sha256", "")))]:
                    problems.append(f"{pid}: PASS on step {s['id']}, which bound nothing it built or booted")
                if s.get("repo_commit") != rep.get("harness", {}).get("repo_commit") or s.get("repo_dirty") is not False:
                    problems.append(f"{pid}: PASS on step {s['id']}, which ran on another commit than the report's, or on a changed tree")
            if r.get("hardware_subject") and env != "hardware":
                problems.append(f"{pid}: PASS on an emulator, but its subject is the hardware (invariant 3)")
            observations = {o.get("name"): o for o in rep.get("observations", [])}
            for name, value in r.get("observed", {}).items():
                o = observations.get(name)
                if not value or o is None or o.get("value") != value:
                    problems.append(f"{pid}: PASS, but it names no {name} that the report observed")
                elif o.get("step") not in steps or o.get("log_sha256") != steps[o["step"]].get("log_sha256"):
                    problems.append(f"{pid}: PASS, but its {name} comes from no step's log")
    if any(r.get("status") == "PASS" for r in results):
        build, harness_ = rep.get("build", {}), rep.get("harness", {})
        files = build.get("files", [])
        if not files:
            problems.append("build: PASS results bound to no file")
        for f in files:
            if f.get("missing") or not SHA256.match(str(f.get("sha256", ""))):
                problems.append(f"build: {f.get('name')} is missing, so the PASS results are not bound to it")
        kc = build.get("kernel_config")
        if not kc or kc.get("missing") or not SHA256.match(str(kc.get("sha256", ""))):
            problems.append("build: PASS results bound to no kernel configuration")
        if not COMMIT.match(str(harness_.get("repo_commit", ""))):
            problems.append("harness: PASS results bound to no commit")
        if harness_.get("repo_dirty") is not False:
            problems.append("harness: PASS results from a tree that differs from its commit")
    if cat is not None and cat_sha is not None and rep.get("harness", {}).get("catalogue_sha256") == cat_sha:
        ids = {p["id"]: p for p in cat["property"]}
        for pid in ids:
            if pid not in seen:
                problems.append(f"{pid}: no result")
        for pid, r in seen.items():
            p = ids.get(pid)
            if p is None:
                problems.append(f"{pid}: not a property of the catalogue")
            elif (r.get("layer"), r.get("level"), r.get("hardware_subject")) != (p["layer"], p["level"], p["hardware_subject"]):
                problems.append(f"{pid}: its layer, level or hardware subject differs from the catalogue")
            elif sorted(r.get("observed", {})) != sorted(p.get("observes", [])):
                problems.append(f"{pid}: it observes other names than the catalogue's")
    if cat is not None and man is not None and man_sha is not None and platform.get("manifest_sha256") == man_sha:
        if env != man.get("environment"):
            problems.append(f"platform: environment {env!r} is not the manifest's")
        for pid, (state, _) in plan(man, cat).items():
            if pid in seen and seen[pid].get("planned") != state:
                problems.append(f"{pid}: planned {seen[pid].get('planned')}, but the manifest gives {state}")
    return problems


def established(rep: dict) -> list:
    if rep.get("platform", {}).get("environment") != "hardware":
        return []
    return [r["property"] for r in rep.get("results", []) if r.get("status") == "PASS"]


def validate_file(path: pathlib.Path) -> tuple:
    rep = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    cat = catalogue()
    pid = rep.get("platform", {}).get("id", "")
    man = manifest(pid) if manifest_path(pid).is_file() else None
    man_sha = sha256_file(manifest_path(pid)) if man is not None else None
    return rep, validate_report(rep, cat, man, sha256_file(CATALOGUE), man_sha)


# ── commands ──────────────────────────────────────────────────────────────


def platform_ids() -> list:
    return sorted(p.stem for p in PLATFORMS.glob("*.toml"))


def check() -> list:
    problems = []
    cat = catalogue()
    problems += check_catalogue(cat, SPEC.read_text(encoding="utf-8") if SPEC.is_file() else None)
    manifests = {}
    for pid in platform_ids():
        m = manifest(pid)
        manifests[pid] = m
        problems += check_manifest(m, cat, pid)
    for hp in sorted(HARNESSES.glob("*.toml")):
        problems += check_harness(load_toml(hp), cat, manifests.get(hp.stem), hp.stem)
    for rp in sorted(REPORTS.rglob("*.json")):
        try:
            _, found = validate_file(rp)
        except (OSError, ValueError, H0Error) as e:
            found = [str(e)]
        problems += [f"{rp.relative_to(ROOT)}: {p}" for p in found]
    return problems


SHORT = {"REQUIRED": "required", "UNSUPPORTED": "UNSUPPORTED", "NOT_APPLICABLE": "N/A", "UNDETERMINED": "undetermined"}


def print_plan(platform: str | None) -> None:
    cat = catalogue()
    if platform:
        m = manifest(platform)
        print(f"{m['id']}: {m['name']} ({m['environment']}, tier {m['tier']})")
        for pid, (state, why) in plan(m, cat).items():
            print(f"  {pid:<20} {state:<15} {why}")
        return
    ids = platform_ids()
    planned = {pid: plan(manifest(pid), cat) for pid in ids}
    width = max(len(i) for i in ids) + 2
    print(f"{'':<22}" + "".join(f"{i:<{width}}" for i in ids))
    for p in cat["property"]:
        print(f"{p['layer']} {p['id']:<20}" + "".join(f"{SHORT[planned[i][p['id']][0]]:<{width}}" for i in ids))


def print_report(rep: dict) -> None:
    pl = rep["platform"]
    print(f"H0 report: {pl['id']} ({pl['environment']}), commit {rep['harness']['repo_commit'][:12]}")
    for r in rep["results"]:
        print(f"  {r['layer']} {r['property']:<20} {r['status']:<17} {r['reason']}")
    for o in rep.get("observations", []):
        print(f"  observed {o['name']}: {o['value'] or 'nothing'} (step {o['step']})")
    est = established(rep)
    if pl["environment"] != "hardware":
        print("established: nothing (an emulator establishes no hardware qualification property: spec 33, invariant 3)")
    else:
        print("established: " + (", ".join(est) if est else "nothing"))


# ── self-test ─────────────────────────────────────────────────────────────


def self_test() -> int:
    """Prove that every rule fires: plans, results and report validation."""
    failures = []
    cat = catalogue()
    if check_catalogue(cat):
        failures.append("the catalogue as it is does not pass")
    cap = lambda hw, st: {"hardware": hw, "stack": st, "source": "self-test"}
    full = {c: cap(True, True) for c in cat["capabilities"]}
    board = {"schema": SCHEMAS["manifest"], "id": "selftest", "name": "a board", "arch": "aarch64",
             "environment": "hardware", "tier": "1", "microkit_board": "selftest", "capabilities": full}
    if check_manifest(board, cat):
        failures.append(f"a sound manifest does not pass: {check_manifest(board, cat)}")
    # plans: no hardware wins over no stack, which wins over unknown
    states = lambda caps: {k: v[0] for k, v in plan(dict(board, capabilities=caps), cat).items()}
    if set(states(full).values()) != {"REQUIRED"}:
        failures.append("a board with everything does not require everything")
    s = states(dict(full, iommu=cap(False, False)))
    if s["dma_isolation"] != "NOT_APPLICABLE" or s["memory_isolation"] != "REQUIRED":
        failures.append(f"no IOMMU hardware is not NOT_APPLICABLE for DMA alone: {s}")
    s = states(dict(full, iommu=cap(True, False)))
    if s["dma_isolation"] != "UNSUPPORTED":
        failures.append("an IOMMU the stack does not drive is not UNSUPPORTED")
    s = states(dict(full, entropy=cap("unknown", False), hermit_guest=cap(True, False)))
    if s["core_guest"] != "UNSUPPORTED" or s["guest_vm"] != "REQUIRED":
        failures.append(f"unsupported does not win over unknown: {s}")
    s = states(dict(full, entropy=cap("unknown", False)))
    if s["hardware_entropy"] != "UNSUPPORTED":
        failures.append(f"a stack that drives no source is not UNSUPPORTED when the hardware's is unknown: {s}")
    s = states(dict(full, entropy=cap("unknown", True)))
    if s["core_guest"] != "UNDETERMINED" or s["boot"] != "REQUIRED":
        failures.append(f"an unknown capability is not UNDETERMINED: {s}")
    s = states(dict(full, iommu=cap(False, True), microkit=cap(True, False)))
    if s["dma_isolation"] != "NOT_APPLICABLE":
        failures.append("no hardware does not win over no stack")
    for bad, expected in [
        (dict(board, capabilities=dict(full, iommu={"hardware": "yes", "stack": True, "source": "x"})), "is not true, false"),
        (dict(board, capabilities={k: v for k, v in full.items() if k != "entropy"}), "is not declared"),
        (dict(board, environment="simulator"), "environment"),
        (dict(board, tier="gold"), "tier"),
    ]:
        if not any(expected in p for p in check_manifest(bad, cat)):
            failures.append(f"a broken manifest is not caught: {expected}")
    # a harness, its steps' logs, and the results they give
    pids = [p["id"] for p in cat["property"]]
    h = {"schema": SCHEMAS["harness"], "platform": "selftest", "static": {},
         "step": [{"id": "one", "command": ["true"]}, {"id": "two", "command": ["true"]}],
         "evidence": [{"property": pid, "step": "one", "pass": [f"^{pid}: ok$"]} for pid in pids if pid not in ("long_run", "temporal_isolation")]
         + [{"property": "temporal_isolation", "step": "two", "start": "^temporal begins$", "pass": ["^temporal: ok$"]}],
         "observation": [{"name": "entropy_provider", "step": "one", "pattern": "^entropy provider ([a-z0-9-]+)$"}]}
    if check_harness(h, cat, board):
        failures.append(f"a sound harness does not pass: {check_harness(h, cat, board)}")
    if not any("rules out" in p for p in check_harness(h, cat, dict(board, capabilities=dict(full, iommu=cap(False, False))))):
        failures.append("evidence for a property the manifest rules out is not caught")
    if not any("not one of its steps" in p for p in check_harness(dict(h, evidence=[{"property": "boot", "step": "zero", "pass": ["x"]}]), cat, board)):
        failures.append("evidence on a step the harness does not have is not caught")
    variables, step_env = harness_env({"env": {"H0_SELF_TEST_PATH": "${REPO}/x"}})
    if variables.get("H0_SELF_TEST_PATH") != f"{ROOT}/x" or "H0_SELF_TEST_PATH" in step_env:
        failures.append("a harness's [env] does not expand, or leaks into the steps' environment")
    if not any("must name its entropy_provider" in p for p in check_harness(dict(h, observation=[]), cat, board)):
        failures.append("a harness that cannot name the entropy provider is not caught")
    digest = "a" * 64
    steps = {"one": {"id": "one", "repo_commit": "c" * 40, "repo_dirty": False, "exit_status": 0, "log": "logs/one.log", "log_sha256": digest,
                     "artifacts": [{"path": "/x/loader.img", "sha256": digest, "bytes": 1}]},
             "two": {"id": "two", "repo_commit": "c" * 40, "repo_dirty": False, "exit_status": 1, "log": "logs/two.log", "log_sha256": "b" * 64,
                     "artifacts": [{"path": "/x/loader.img", "sha256": digest, "bytes": 1}]}}
    one = "\n".join(f"{pid}: ok" for pid in pids if pid != "boot") + "\nentropy provider test-rng"
    logs = {"one": one, "two": "temporal begins\nsomething broke"}
    results = {r["property"]: r for r in derive_results(cat, board, h, steps, logs)}
    expect = {"guest_vm": "PASS", "boot": "FAIL", "long_run": "NOT_DEMONSTRATED", "temporal_isolation": "FAIL", "dma_isolation": "PASS"}
    for pid, st in expect.items():
        if results[pid]["status"] != st:
            failures.append(f"{pid} derived {results[pid]['status']}, not {st}")
    unnamed = {r["property"]: r for r in derive_results(cat, board, h, steps, dict(logs, one=one.replace("entropy provider", "no provider")))}
    if unnamed["hardware_entropy"]["status"] != "FAIL":
        failures.append("hardware entropy passes without naming its provider")
    results = {r["property"]: r for r in derive_results(cat, board, h, steps, dict(logs, two="no start line"))}
    if results["temporal_isolation"]["status"] != "NOT_DEMONSTRATED":
        failures.append("a step that stopped before a test does not leave it NOT_DEMONSTRATED")
    results = {r["property"]: r for r in derive_results(cat, board, h, {"one": steps["one"]}, logs)}
    if results["temporal_isolation"]["status"] != "NOT_DEMONSTRATED":
        failures.append("a step that did not run does not leave its properties NOT_DEMONSTRATED")
    emulator = dict(board, environment="emulator")
    results = {r["property"]: r for r in derive_results(cat, emulator, h, steps, logs)}
    if results["dma_isolation"]["status"] != "NOT_DEMONSTRATED" or results["guest_vm"]["status"] != "PASS":
        failures.append("a hardware-subject property passes on an emulator, or a software one does not")
    # a report, valid as built, and each rule breaking it
    rep = {
        "schema": SCHEMAS["report"],
        "platform": {"id": "selftest", "environment": "hardware", "manifest_sha256": "m" * 64},
        "harness": {"repo_commit": "c" * 40, "repo_dirty": False, "catalogue_sha256": "k" * 64},
        "build": {"files": [{"name": "seL4 kernel", "path": "/x/sel4.elf", "sha256": digest}],
                  "kernel_config": {"path": "/x/gen_config.json", "sha256": digest, "options": {}}},
        "steps": list(steps.values()),
        "observations": derive_observations(h, steps, logs),
        "results": derive_results(cat, board, h, steps, logs),
    }
    ok = validate_report(rep, cat, board, "k" * 64, "m" * 64)
    if ok:
        failures.append(f"a sound report does not pass: {ok}")
    if sorted(established(rep)) != sorted(r["property"] for r in rep["results"] if r["status"] == "PASS"):
        failures.append("a hardware report does not establish its PASS results")
    if established(dict(rep, platform=dict(rep["platform"], environment="emulator"))):
        failures.append("an emulator's report establishes something")

    def broken(change):
        r = copy.deepcopy(rep)
        change(r)
        return validate_report(r, cat, board, "k" * 64, "m" * 64)

    def result(r, pid):
        return next(x for x in r["results"] if x["property"] == pid)

    injections = {
        "is not one of the five": lambda r: result(r, "guest_vm").update(status="ESTABLISHED"),
        "no result": lambda r: r["results"].remove(result(r, "long_run")),
        "two results": lambda r: r["results"].append(copy.deepcopy(result(r, "guest_vm"))),
        "contradicts the plan": lambda r: result(r, "guest_vm").update(planned="UNSUPPORTED"),
        "but the manifest gives": lambda r: result(r, "long_run").update(planned="UNDETERMINED"),
        "PASS without evidence": lambda r: result(r, "guest_vm").update(evidence=[]),
        "which did not run": lambda r: r.update(steps=[steps["two"]]),
        "is not step": lambda r: result(r, "guest_vm")["evidence"][0].update(log_sha256="d" * 64),
        "did not hold": lambda r: result(r, "guest_vm")["evidence"][0].update(found=[False]),
        "bound nothing it built": lambda r: r["steps"][0].update(artifacts=[]),
        "subject is the hardware": lambda r: r["platform"].update(environment="emulator"),
        "is missing": lambda r: r["build"]["files"][0].update(missing=True, sha256=None),
        "no kernel configuration": lambda r: r["build"].pop("kernel_config"),
        "bound to no commit": lambda r: r["harness"].update(repo_commit="unknown"),
        "a tree that differs": lambda r: r["harness"].update(repo_dirty=True),
        "on another commit than the report's": lambda r: r["steps"][0].update(repo_commit="f" * 40),
        "without a reason": lambda r: result(r, "long_run").update(reason=""),
        "differs from the catalogue": lambda r: result(r, "guest_vm").update(level="chitala"),
        "no log digest": lambda r: r["steps"][1].update(log_sha256=None),
        "names no entropy_provider": lambda r: r["observations"][0].update(value="another-rng"),
        "comes from no step's log": lambda r: r["observations"][0].update(log_sha256="e" * 64),
        "observes other names": lambda r: result(r, "hardware_entropy").update(observed={}),
    }
    for expected, change in injections.items():
        found = broken(change)
        if not any(expected in p for p in found):
            failures.append(f"not caught: {expected} (got {found})")
    # a log changed after its step ran is refused
    with tempfile.TemporaryDirectory() as tmp:
        out = pathlib.Path(tmp)
        (out / "logs").mkdir()
        (out / "logs" / "one.log").write_text("boot: ok\n", encoding="utf-8")
        rec = {"id": "one", "log": "logs/one.log", "log_sha256": sha256_file(out / "logs" / "one.log")}
        read_logs(out, {"one": rec})
        (out / "logs" / "one.log").write_text("boot: ok\nguest_vm: ok\n", encoding="utf-8")
        try:
            read_logs(out, {"one": rec})
            failures.append("a log changed after its step ran is not refused")
        except H0Error:
            pass
        (out / "steps").mkdir()
        (out / "steps" / "one.json").write_text("{}", encoding="utf-8")
        try:
            run_step({"id": "one", "command": ["true"]}, {}, dict(os.environ), out)
            failures.append("a step run twice in one run is not refused")
        except H0Error:
            pass
    for f in failures:
        print(f"self-test FAILED: {f}")
    if not failures:
        print("h0 self-test: every rule fires (plans, results, reports, logs, re-runs)")
    return 1 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="command", required=True)
    c = sub.add_parser("check")
    c.add_argument("--self-test", action="store_true")
    p = sub.add_parser("plan")
    p.add_argument("--platform")
    r = sub.add_parser("run")
    r.add_argument("--platform", required=True)
    r.add_argument("--step", action="append")
    r.add_argument("--fresh", action="store_true")
    r.add_argument("--out")
    rp = sub.add_parser("report")
    rp.add_argument("--platform", required=True)
    rp.add_argument("--out")
    v = sub.add_parser("validate")
    v.add_argument("report")
    e = sub.add_parser("established")
    e.add_argument("report")
    a = ap.parse_args()
    try:
        if a.command == "check":
            if a.self_test:
                return self_test()
            problems = check()
            for p_ in problems:
                print(f"h0 check: {p_}")
            if not problems:
                print(f"h0 check: the catalogue, {len(platform_ids())} manifests, "
                      f"{len(list(HARNESSES.glob('*.toml')))} harnesses and {len(list(REPORTS.rglob('*.json')))} kept reports hold")
            return 1 if problems else 0
        if a.command == "plan":
            print_plan(a.platform)
            return 0
        if a.command in ("run", "report"):
            m, h = manifest(a.platform), harness(a.platform)
            problems = check_manifest(m, catalogue(), a.platform) + check_harness(h, catalogue(), m, a.platform)
            if problems:
                raise H0Error("; ".join(problems))
            variables, env = harness_env(h)
            out = pathlib.Path(a.out) if a.out else default_out(a.platform, variables)
            if a.command == "run":
                if a.fresh and out.exists():
                    shutil.rmtree(out)
                known = {s["id"]: s for s in h["step"]}
                for sid in a.step or list(known):
                    if sid not in known:
                        raise H0Error(f"{a.platform} has no step {sid} (it has {', '.join(known)})")
                for sid in a.step or list(known):
                    rec = run_step(known[sid], variables, env, out)
                    if rec["exit_status"] != 0:
                        return rec["exit_status"]
                return 0
            rep = make_report(a.platform, out)
            path = out / "report.json"
            path.write_text(json.dumps(rep, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
            print_report(rep)
            _, problems = validate_file(path)
            for p_ in problems:
                print(f"h0 report INVALID: {p_}")
            print(f"report: {path}")
            return 1 if problems else 0
        if a.command in ("validate", "established"):
            rep, problems = validate_file(pathlib.Path(a.report))
            for p_ in problems:
                print(f"h0 validate: {p_}")
            if problems:
                return 1
            if a.command == "validate":
                print_report(rep)
                return 0
            est = established(rep)
            if rep["platform"]["environment"] != "hardware":
                print("nothing: an emulator establishes no hardware qualification property (spec 33, invariant 3)")
            else:
                print("\n".join(est) if est else "nothing")
            return 0
    except H0Error as err:
        print(f"h0: {err}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
