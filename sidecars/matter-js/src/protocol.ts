// The sidecar's protocol (spec 27): JSON Lines on stdio, typed and
// allowlisted. There is no generic command: each operation has its own
// fields, and every endpoint, cluster, command and attribute is checked
// against the Home profile before anything is done. A request that is not
// exactly right is refused, and nothing reaches a device.
//
// Requests: {"id": n, "op": <operation>, ...its fields}
// Answers:  {"id": n, "ok": {...}} or {"id": n | null, "error": {"kind", "message", ...}}
// Events:   {"event": "values" | "heard" | "link", "node": "<decimal>", ...}

import type { Profile, ProfileClass, ProfileCommand } from "./profile.ts";

/** serve: spawned by the adapter host; admin: run by `chitala matter`. */
export type { Mode } from "./args.ts";
import type { Mode } from "./args.ts";

export interface Target {
    node: bigint;
    endpoint: number;
}

/** (cluster, attribute) */
export type Attribute = readonly [number, number];

export type Request =
    | { id: number; op: "Hello" }
    | { id: number; op: "SubscribeProfileAttributes"; target: Target; class: ProfileClass; attributes: Attribute[] }
    | { id: number; op: "ReadProfileAttributes"; target: Target; class: ProfileClass; attributes: Attribute[] }
    | {
          id: number;
          op: "InvokeProfileCommand";
          target: Target;
          class: ProfileClass;
          capability: string;
          command: ProfileCommand;
      }
    | { id: number; op: "CommissionDevice"; code: string }
    | { id: number; op: "RemoveDevice"; node: bigint }
    | { id: number; op: "ListDevices" };

/** A request refused before anything was done. */
export class Refused extends Error {
    readonly id: number | null;
    constructor(id: number | null, message: string) {
        super(message);
        this.id = id;
    }
}

/** The longest request line, newline included (the node's own IPC limit). */
export const MAX_LINE = 64 * 1024;

const OPERATIONS: Record<Mode, readonly string[]> = {
    serve: ["Hello", "SubscribeProfileAttributes", "ReadProfileAttributes", "InvokeProfileCommand"],
    admin: ["Hello", "CommissionDevice", "RemoveDevice", "ListDevices"],
};

const FIELDS: Record<string, readonly string[]> = {
    Hello: [],
    SubscribeProfileAttributes: ["target", "class", "attributes"],
    ReadProfileAttributes: ["target", "class", "attributes"],
    InvokeProfileCommand: ["target", "class", "capability", "cluster", "command", "timed"],
    CommissionDevice: ["code"],
    RemoveDevice: ["node"],
    ListDevices: [],
};

/** Operational node ids (Matter Core specification, 2.5.5.1). */
const NODE_MAX = 0xffff_ffef_ffff_ffffn;

function isObject(v: unknown): v is Record<string, unknown> {
    return typeof v === "object" && v !== null && !Array.isArray(v);
}

function uint(v: unknown, max: number): number | undefined {
    return Number.isSafeInteger(v) && (v as number) >= 0 && (v as number) <= max ? (v as number) : undefined;
}

export function node(v: unknown): bigint | undefined {
    if (typeof v !== "string" || !/^[1-9][0-9]{0,19}$/.test(v)) return undefined;
    const n = BigInt(v);
    return n <= NODE_MAX ? n : undefined;
}

function target(id: number, v: unknown): Target {
    if (!isObject(v) || Object.keys(v).sort().join() !== "endpoint,node") {
        throw new Refused(id, "target must be {node, endpoint}");
    }
    const n = node(v.node);
    // endpoint 0 is the node's root, never a device of the profile
    const endpoint = uint(v.endpoint, 0xfffe);
    if (n === undefined || endpoint === undefined || endpoint === 0) {
        throw new Refused(id, "target: node is a decimal operational node id, endpoint 1..65534");
    }
    return { node: n, endpoint };
}

function profileClass(id: number, v: unknown, profile: Profile): ProfileClass {
    const c = typeof v === "string" ? profile.classes.get(v) : undefined;
    if (c === undefined) throw new Refused(id, `class: not a class of ${profile.name}`);
    return c;
}

function attributes(id: number, v: unknown, c: ProfileClass): Attribute[] {
    if (!Array.isArray(v) || v.length === 0 || v.length > c.attributes.size) {
        throw new Refused(id, "attributes: a non-empty list of the class's attributes");
    }
    const seen = new Set<string>();
    return v.map(a => {
        const cluster = Array.isArray(a) && a.length === 2 ? uint(a[0], 0xffff_ffff) : undefined;
        const attribute = Array.isArray(a) && a.length === 2 ? uint(a[1], 0xffff_ffff) : undefined;
        const key = `${cluster}/${attribute}`;
        if (cluster === undefined || attribute === undefined || !c.attributes.has(key) || seen.has(key)) {
            throw new Refused(id, `attributes: ${JSON.stringify(a)} is not an attribute ${c.name} maps (once)`);
        }
        seen.add(key);
        return [cluster, attribute] as const;
    });
}

/** Parse one request line. Throws [`Refused`] for anything not exactly right. */
export function parseRequest(line: string, mode: Mode, profile: Profile): Request {
    if (Buffer.byteLength(line) > MAX_LINE) throw new Refused(null, "request too large");
    let v: unknown;
    try {
        v = JSON.parse(line);
    } catch {
        throw new Refused(null, "not JSON");
    }
    if (!isObject(v)) throw new Refused(null, "a request is an object");
    const id = uint(v.id, Number.MAX_SAFE_INTEGER);
    if (id === undefined) throw new Refused(null, "id: a non-negative integer");
    const op = v.op;
    if (typeof op !== "string" || !Object.hasOwn(FIELDS, op)) throw new Refused(id, "op: not an operation");
    if (!OPERATIONS[mode].includes(op)) throw new Refused(id, `${op} is not available in ${mode} mode`);
    const fields = Object.keys(v).filter(k => k !== "id" && k !== "op");
    const expected = FIELDS[op] ?? [];
    if (fields.length !== expected.length || !fields.every(f => expected.includes(f))) {
        throw new Refused(id, `${op} takes exactly: ${expected.join(", ") || "nothing"}`);
    }
    switch (op) {
        case "Hello":
            return { id, op };
        case "ListDevices":
            return { id, op };
        case "SubscribeProfileAttributes":
        case "ReadProfileAttributes": {
            const c = profileClass(id, v.class, profile);
            return { id, op, target: target(id, v.target), class: c, attributes: attributes(id, v.attributes, c) };
        }
        case "InvokeProfileCommand": {
            const c = profileClass(id, v.class, profile);
            const capability = v.capability;
            const command = typeof capability === "string" ? c.commands.get(capability) : undefined;
            if (typeof capability !== "string" || command === undefined) {
                throw new Refused(id, `capability: not one ${c.name} maps to a Matter command`);
            }
            // the caller states the command; it must be the profile's, exactly
            if (v.cluster !== command.cluster || v.command !== command.command || v.timed !== command.timed) {
                throw new Refused(id, `${capability} is cluster ${command.cluster} command ${command.command}, timed ${command.timed}`);
            }
            return { id, op, target: target(id, v.target), class: c, capability, command };
        }
        case "CommissionDevice": {
            const code = v.code;
            const manual = typeof code === "string" && /^[0-9]{11}([0-9]{10})?$/.test(code.replace(/[- ]/g, ""));
            const qr = typeof code === "string" && /^MT:[0-9A-Z.-]{1,60}$/.test(code);
            if (typeof code !== "string" || !(manual || qr)) {
                throw new Refused(id, "code: a manual pairing code (11 or 21 digits) or a QR code (MT:…)");
            }
            return { id, op, code: manual ? code.replace(/[- ]/g, "") : code };
        }
        case "RemoveDevice": {
            const n = node(v.node);
            if (n === undefined) throw new Refused(id, "node: a decimal operational node id");
            return { id, op, node: n };
        }
    }
    throw new Refused(id, "op: not an operation");
}

/** JSON of a value, with 64-bit integers as decimal strings. */
export function line(v: unknown): string {
    return JSON.stringify(v, (_k, x) => (typeof x === "bigint" ? x.toString() : x));
}
