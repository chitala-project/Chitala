// chitala-matter-js: Chitala's Matter controller sidecar (spec 27).
//
//   node src/main.ts serve --storage <dir> [--subscription-ceiling <s>]
//   node src/main.ts admin --storage <dir> [--accept-test-attestation]
//
// stdin and stdout carry the protocol (protocol.ts), and nothing else: every
// log, matter.js's included, goes to stderr. There is no network API. The
// adapter host runs `serve`; `chitala matter` runs `admin`, which alone can
// commission or remove a device.

// first: the command line is taken before matter.js loads
import { options } from "./args.ts";

import { Logger } from "@matter/main";

import { Controller, InvokeFailure, type Event } from "./controller.ts";
import { loadProfile } from "./profile.ts";
import { line, MAX_LINE, parseRequest, Refused, type Request } from "./protocol.ts";

/** The protocol's version: the Rust backend refuses another. */
const PROTOCOL = 1;

// stdout is the protocol's: everything else writes to stderr
const protocolOut = process.stdout.write.bind(process.stdout);
process.stdout.write = process.stderr.write.bind(process.stderr) as typeof process.stdout.write;
console.log = console.info = console.debug = console.warn = (...a: unknown[]) => console.error(...a);
const defaultDestination = Logger.destinations.default;
if (defaultDestination !== undefined) {
    defaultDestination.write = (text: string) => void process.stderr.write(`${text}\n`);
}
Logger.level = process.env.CHITALA_MATTER_LOG ?? "notice";

function send(v: unknown): void {
    protocolOut(`${line(v)}\n`);
}

const profile = loadProfile();
const { mode } = options;
const controller = new Controller({ ...options, emit: (e: Event) => send(e) });
await controller.start();

async function handle(r: Request): Promise<unknown> {
    switch (r.op) {
        case "Hello":
            return { protocol: PROTOCOL, mode, profile: profile.name, fabric: controller.fabric() };
        case "SubscribeProfileAttributes":
            await controller.subscribe(r.id, r.target, r.class, r.attributes);
            return {};
        case "ReadProfileAttributes":
            return { values: await controller.read(r.id, r.target, r.class, r.attributes) };
        case "InvokeProfileCommand":
            await controller.invoke(r.id, r.target, r.class, r.command);
            return {};
        case "CommissionDevice":
            return { node: await controller.commission(r.code) };
        case "RemoveDevice":
            await controller.remove(r.node);
            return {};
        case "ListDevices":
            return { devices: await controller.list() };
    }
}

function failure(r: Request, e: unknown): { kind: string; message: string; status?: number; cluster_status?: number } {
    const message = (e instanceof Error ? e.message : String(e)).slice(0, 300);
    if (e instanceof Refused) return { kind: "refused", message };
    if (e instanceof InvokeFailure) {
        return { kind: e.kind, message, status: e.status, cluster_status: e.clusterStatus };
    }
    // anything else after an invoke began may have reached the device
    if (r.op === "InvokeProfileCommand") return { kind: "indeterminate", message };
    if (r.op === "ReadProfileAttributes") return { kind: "read", message };
    return { kind: "failed", message };
}

function dispatch(text: string): void {
    let request: Request;
    try {
        request = parseRequest(text, mode, profile);
    } catch (e) {
        const r = e instanceof Refused ? e : new Refused(null, String(e));
        send({ id: r.id, error: { kind: "refused", message: r.message } });
        return;
    }
    handle(request).then(
        ok => send({ id: request.id, ok }),
        e => send({ id: request.id, error: failure(request, e) }),
    );
}

// lines of at most MAX_LINE bytes: a longer one ends the session
let pending = Buffer.alloc(0);
process.stdin.on("data", (chunk: Buffer) => {
    pending = Buffer.concat([pending, chunk]);
    for (;;) {
        const nl = pending.indexOf(0x0a);
        if (nl < 0) break;
        const text = pending.subarray(0, nl).toString("utf8").trim();
        pending = pending.subarray(nl + 1);
        if (text !== "") dispatch(text);
    }
    if (pending.length > MAX_LINE) {
        send({ id: null, error: { kind: "refused", message: "request too large" } });
        void shutdown(2);
    }
});
process.stdin.on("end", () => void shutdown(0));
process.on("SIGTERM", () => void shutdown(0));

let closing = false;
async function shutdown(code: number): Promise<void> {
    if (closing) return;
    closing = true;
    try {
        await controller.close();
    } finally {
        process.exit(code);
    }
}
