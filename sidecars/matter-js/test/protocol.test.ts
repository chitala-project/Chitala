// The sidecar's protocol checks (spec 27): a request that is not exactly a
// typed profile operation is refused before anything reaches a device.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { loadProfile, parseProfile } from "../src/profile.ts";
import { MAX_LINE, parseRequest, Refused } from "../src/protocol.ts";

const profile = loadProfile();
const target = { node: "1", endpoint: 1 };
const lockRead = { id: 1, op: "ReadProfileAttributes", target, class: "lock", attributes: [[257, 0]] };
const unlock = {
    id: 2,
    op: "InvokeProfileCommand",
    target,
    class: "lock",
    capability: "lock.unlock",
    cluster: 257,
    command: 1,
    timed: true,
};

function refused(request: unknown, mode: "serve" | "admin" = "serve"): string {
    const text = typeof request === "string" ? request : JSON.stringify(request);
    try {
        parseRequest(text, mode, profile);
    } catch (e) {
        assert.ok(e instanceof Refused, `refused, not ${String(e)}`);
        return e.message;
    }
    assert.fail(`accepted: ${text}`);
}

test("the sidecar's profile is the specification's, byte for byte", () => {
    const ours = readFileSync(new URL("../profile.json", import.meta.url), "utf8");
    const spec = readFileSync(new URL("../../../specs/profiles/home-v0.1.json", import.meta.url), "utf8");
    assert.equal(ours, spec);
    assert.equal(parseProfile(spec).name, profile.name);
});

test("profile operations are accepted as typed requests", () => {
    const read = parseRequest(JSON.stringify(lockRead), "serve", profile);
    assert.equal(read.op, "ReadProfileAttributes");
    assert.ok(read.op === "ReadProfileAttributes" && read.target.node === 1n && read.class.name === "lock");
    const invoke = parseRequest(JSON.stringify(unlock), "serve", profile);
    assert.ok(invoke.op === "InvokeProfileCommand" && invoke.command.timed && invoke.command.command === 1);
    // the largest operational node id, as a decimal string
    const far = { ...lockRead, target: { node: "18446744004990074879", endpoint: 2 } };
    const r = parseRequest(JSON.stringify(far), "serve", profile);
    assert.ok(r.op === "ReadProfileAttributes" && r.target.node === 0xffff_ffef_ffff_ffffn);
});

test("anything not exactly a profile operation is refused", () => {
    assert.match(refused("{nope"), /not JSON/);
    assert.match(refused({ op: "Hello" }), /id/);
    assert.match(refused({ id: 1, op: "WriteAttribute" }), /not an operation/);
    assert.match(refused({ id: 1, op: "Hello", extra: 1 }), /exactly/);
    assert.match(refused({ ...unlock, args: {} }), /exactly/);
    // paths the profile does not map for the class
    assert.match(refused({ ...lockRead, attributes: [[6, 0]] }), /not an attribute lock maps/);
    assert.match(refused({ ...lockRead, attributes: [[257, 0], [257, 0]] }), /attributes/);
    assert.match(refused({ ...lockRead, class: "light", attributes: [[6, 0], [6, 0]] }), /once/);
    assert.match(refused({ ...lockRead, class: "robot" }), /not a class/);
    assert.match(refused({ ...unlock, capability: "lock.open" }), /not one lock maps/);
    // the command must be the profile's, exactly, Timed Invoke included
    assert.match(refused({ ...unlock, command: 0 }), /cluster 257 command 1, timed true/);
    assert.match(refused({ ...unlock, cluster: 6 }), /cluster 257 command 1/);
    assert.match(refused({ ...unlock, timed: false }), /timed true/);
    // targets: a decimal operational node id, never the root endpoint
    assert.match(refused({ ...lockRead, target: { node: 1, endpoint: 1 } }), /target/);
    assert.match(refused({ ...lockRead, target: { node: "0", endpoint: 1 } }), /target/);
    assert.match(refused({ ...lockRead, target: { node: "18446744073709551615", endpoint: 1 } }), /target/);
    assert.match(refused({ ...lockRead, target: { node: "1", endpoint: 0 } }), /target/);
    assert.match(refused({ ...lockRead, target: { node: "1", endpoint: 1, fabric: 2 } }), /target/);
});

test("each mode has its own operations only", () => {
    assert.match(refused({ id: 1, op: "CommissionDevice", code: "34970112332" }), /not available in serve mode/);
    assert.match(refused({ id: 1, op: "RemoveDevice", node: "1" }), /not available in serve mode/);
    assert.match(refused(lockRead, "admin"), /not available in admin mode/);
    assert.match(refused(unlock, "admin"), /not available in admin mode/);
    const c = parseRequest(JSON.stringify({ id: 1, op: "CommissionDevice", code: "3497-011-2332" }), "admin", profile);
    assert.ok(c.op === "CommissionDevice" && c.code === "34970112332");
    assert.ok(parseRequest(JSON.stringify({ id: 1, op: "CommissionDevice", code: "MT:-24J06PF15KA0648G00" }), "admin", profile));
    assert.match(refused({ id: 1, op: "CommissionDevice", code: "1234" }, "admin"), /code/);
});

test("a request longer than the limit is refused", () => {
    const long = JSON.stringify({ ...lockRead, pad: "x".repeat(MAX_LINE) });
    assert.match(refused(long), /too large/);
});
