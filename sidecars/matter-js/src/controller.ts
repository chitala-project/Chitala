// Chitala's Matter controller on matter.js (spec 27): Chitala's own fabric,
// and only what the protocol allows. It reads and subscribes to profile
// attributes, invokes profile commands once, and (in admin mode)
// commissions and removes devices. It never writes attributes and never
// sends anything it was not asked for.

import { Environment, Logger, Millis, NodeId } from "@matter/main";
import { DoorLock, GeneralCommissioning, OnOff } from "@matter/main/clusters";
import { Invoke, Read } from "@matter/main/protocol";
import {
    AttributeId,
    ClusterId,
    EndpointNumber,
    ManualPairingCodeCodec,
    QrPairingCodeCodec,
    Status,
    StatusResponseError,
} from "@matter/main/types";
import { CommissioningController } from "@project-chip/matter.js";
import { NodeStates, type PairedNode } from "@project-chip/matter.js/device";

import type { ProfileClass, ProfileCommand } from "./profile.ts";
import { Refused, type Attribute, type Target } from "./protocol.ts";

const logger = Logger.get("chitala-matter");

/** The commands this sidecar can send at all, whatever the profile says. */
const COMMANDS = new Map<string, { cluster: typeof OnOff.Cluster | typeof DoorLock.Cluster; name: string }>([
    [`${0x0006}/${0x00}`, { cluster: OnOff.Cluster, name: "off" }],
    [`${0x0006}/${0x01}`, { cluster: OnOff.Cluster, name: "on" }],
    [`${0x0101}/${0x00}`, { cluster: DoorLock.Cluster, name: "lockDoor" }],
    [`${0x0101}/${0x01}`, { cluster: DoorLock.Cluster, name: "unlockDoor" }],
]);

/** How long a Timed Invoke's window stays open. */
const TIMED_MS = 10_000;
/** How long a read is waited for. */
const READ_MS = 10_000;
/** How long listing waits for a node's structure. */
const LIST_MS = 15_000;

/** Why an invoke did not succeed: what the Rust backend makes of it (spec 27). */
export class InvokeFailure extends Error {
    readonly kind: "not_sent" | "status" | "indeterminate";
    readonly status?: number;
    readonly clusterStatus?: number;
    constructor(kind: InvokeFailure["kind"], message: string, status?: number, clusterStatus?: number) {
        super(message);
        this.kind = kind;
        this.status = status;
        this.clusterStatus = clusterStatus;
    }
}

export type Event =
    | { event: "values"; node: bigint; endpoint: number; values: [number, number, unknown][] }
    | { event: "heard"; node: bigint }
    | { event: "link"; node: bigint; live: boolean };

function message(e: unknown): string {
    return (e instanceof Error ? e.message : String(e)).slice(0, 300);
}

function withTimeout<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`${what}: no answer in ${ms} ms`)), ms);
        p.then(
            v => {
                clearTimeout(timer);
                resolve(v);
            },
            e => {
                clearTimeout(timer);
                reject(e);
            },
        );
    });
}

export class Controller {
    readonly #controller: CommissioningController;
    readonly #emit: (e: Event) => void;
    readonly #ceiling: number;
    readonly #acceptTestAttestation: boolean;
    readonly #nodes = new Map<bigint, PairedNode>();
    /** "node/endpoint" → the subscribed class and its attributes ("cluster/attribute"). */
    readonly #subscribed = new Map<string, { target: Target; class: ProfileClass; attributes: Attribute[] }>();

    constructor(options: {
        storage: string;
        emit: (e: Event) => void;
        subscriptionCeilingSeconds: number;
        acceptTestAttestation: boolean;
    }) {
        const environment = Environment.default;
        environment.vars.set("storage.path", options.storage);
        this.#controller = new CommissioningController({
            environment: { environment, id: "chitala" },
            autoConnect: false,
            adminFabricLabel: "Chitala",
        });
        this.#emit = options.emit;
        this.#ceiling = options.subscriptionCeilingSeconds;
        this.#acceptTestAttestation = options.acceptTestAttestation;
    }

    async start(): Promise<void> {
        await this.#controller.start();
    }

    async close(): Promise<void> {
        await this.#controller.close();
    }

    fabric(): { nodes: number } {
        return { nodes: this.#controller.getCommissionedNodes().length };
    }

    // ───────────────────────────── serve ─────────────────────────────

    /** The node, connected and subscribed (matter.js keeps the subscription). */
    async #node(id: number, n: bigint): Promise<PairedNode> {
        const known = this.#nodes.get(n);
        if (known !== undefined) return known;
        if (!this.#controller.getCommissionedNodes().some(x => BigInt(x) === n)) {
            throw new Refused(id, `node ${n} is not on Chitala's fabric`);
        }
        const node = await this.#controller.getNode(NodeId(n));
        node.events.stateChanged.on(state => {
            const live = state === NodeStates.Connected;
            this.#emit({ event: "link", node: n, live });
            if (live) void this.#refresh(n);
        });
        node.events.connectionAlive.on(() => this.#emit({ event: "heard", node: n }));
        node.events.attributeChanged.on(data => {
            const { endpointId, clusterId, attributeId } = data.path;
            const s = this.#subscribed.get(`${n}/${endpointId}`);
            if (s?.attributes.some(([c, a]) => c === clusterId && a === attributeId)) {
                this.#emit({ event: "values", node: n, endpoint: endpointId, values: [[clusterId, attributeId, data.value]] });
                this.#emit({ event: "heard", node: n });
            }
        });
        node.connect({ subscribeMinIntervalFloorSeconds: 0, subscribeMaxIntervalCeilingSeconds: this.#ceiling });
        this.#nodes.set(n, node);
        return node;
    }

    /** Whether the endpoint carries one of the class's device types; undefined while unknown. */
    #endpointIs(node: PairedNode, endpoint: number, c: ProfileClass): boolean | undefined {
        if (!node.initialized) return undefined;
        const device = node.getDeviceById(endpoint);
        if (device === undefined) return false;
        return device.getDeviceTypes().some(t => c.deviceTypes.has(t.code));
    }

    #check(id: number, node: PairedNode, target: Target, c: ProfileClass): void {
        const is = this.#endpointIs(node, target.endpoint, c);
        if (is === undefined) throw new Refused(id, `node ${target.node}: its endpoints are not known yet`);
        if (!is) throw new Refused(id, `node ${target.node} endpoint ${target.endpoint} is not a ${c.name} device`);
    }

    /** After a (re)connection: the subscribed values, read now. */
    async #refresh(n: bigint): Promise<void> {
        for (const s of this.#subscribed.values()) {
            if (s.target.node !== n) continue;
            try {
                const values = await this.#read(s.target, s.attributes);
                this.#emit({ event: "values", node: n, endpoint: s.target.endpoint, values });
                this.#emit({ event: "heard", node: n });
            } catch (e) {
                logger.info(`node ${n}: read after connecting failed: ${message(e)}`);
            }
        }
    }

    async subscribe(id: number, target: Target, c: ProfileClass, attributes: Attribute[]): Promise<void> {
        const node = await this.#node(id, target.node);
        if (this.#endpointIs(node, target.endpoint, c) === false) {
            throw new Refused(id, `node ${target.node} endpoint ${target.endpoint} is not a ${c.name} device`);
        }
        this.#subscribed.set(`${target.node}/${target.endpoint}`, { target, class: c, attributes });
        if (node.isConnected) {
            this.#emit({ event: "link", node: target.node, live: true });
            void this.#refresh(target.node);
        }
    }

    async #read(target: Target, attributes: Attribute[]): Promise<[number, number, unknown][]> {
        const node = this.#nodes.get(target.node);
        if (node === undefined) throw new Error("not subscribed");
        const request = {
            ...Read({
                attributes: attributes.map(([c, a]) => ({
                    endpointId: EndpointNumber(target.endpoint),
                    clusterId: ClusterId(c),
                    attributeId: AttributeId(a),
                })),
            }),
            // no data version filter: the device sends every value
            includeKnownVersions: true,
        };
        const read = async () => {
            const out: [number, number, unknown][] = [];
            for await (const chunk of node.node.interaction.read(request)) {
                for await (const e of chunk) {
                    if (e.kind === "attr-value") out.push([e.path.clusterId, e.path.attributeId, e.value]);
                }
            }
            return out;
        };
        const values = await withTimeout(read(), READ_MS, "read");
        if (values.length === 0) throw new Error("the device answered none of the attributes");
        return values;
    }

    async read(id: number, target: Target, c: ProfileClass, attributes: Attribute[]): Promise<[number, number, unknown][]> {
        const node = await this.#node(id, target.node);
        this.#check(id, node, target, c);
        return this.#read(target, attributes);
    }

    /**
     * The command, once. A read just before it: if the device does not
     * answer, nothing was sent. After that, anything but the device's own
     * answer leaves the order's fate unknown. matter.js never sends it again.
     */
    async invoke(id: number, target: Target, c: ProfileClass, command: ProfileCommand): Promise<void> {
        const node = await this.#node(id, target.node);
        this.#check(id, node, target, c);
        const spec = COMMANDS.get(`${command.cluster}/${command.command}`);
        if (spec === undefined) throw new Refused(id, "this sidecar does not send that command");
        const first = [...c.attributes][0]?.split("/").map(Number);
        if (first === undefined || first.length !== 2) throw new Refused(id, `${c.name} maps no attribute to read`);
        try {
            await this.#read(target, [[first[0] ?? 0, first[1] ?? 0]]);
        } catch (e) {
            throw new InvokeFailure("not_sent", `the device did not answer a read just before: ${message(e)}`);
        }
        try {
            const request = {
                endpoint: EndpointNumber(target.endpoint),
                cluster: spec.cluster,
                command: spec.name,
            } as unknown as Invoke.ConcreteCommandRequest;
            const invoke = Invoke({ commands: [request], ...(command.timed ? { timeout: Millis(TIMED_MS) } : {}) });
            for await (const data of node.node.interaction.invoke(invoke)) {
                for (const e of data) {
                    if (e.kind === "cmd-status" && e.status !== Status.Success) {
                        throw new InvokeFailure("status", `status ${e.status}`, e.status, e.clusterStatus);
                    }
                }
            }
        } catch (e) {
            if (e instanceof InvokeFailure) throw e;
            if (e instanceof StatusResponseError) throw new InvokeFailure("status", message(e), e.code, e.clusterCode);
            throw new InvokeFailure("indeterminate", `no answer: ${message(e)}`);
        }
    }

    // ───────────────────────────── admin ─────────────────────────────

    async commission(code: string): Promise<bigint> {
        let passcode: number;
        let identifierData: { longDiscriminator: number } | { shortDiscriminator: number };
        if (code.startsWith("MT:")) {
            const [qr] = QrPairingCodeCodec.decode(code);
            if (qr === undefined || qr.discriminator === undefined) throw new Error("the QR code holds no device");
            passcode = qr.passcode;
            identifierData = { longDiscriminator: qr.discriminator };
        } else {
            const manual = ManualPairingCodeCodec.decode(code);
            if (manual.shortDiscriminator === undefined) throw new Error("the code holds no discriminator");
            passcode = manual.passcode;
            identifierData = { shortDiscriminator: manual.shortDiscriminator };
        }
        const nodeId = await this.#controller.commissionNode(
            {
                commissioning: {
                    regulatoryLocation: GeneralCommissioning.RegulatoryLocationType.IndoorOutdoor,
                    regulatoryCountryCode: "XX",
                    // lab only: development devices carry test certificates
                    ...(this.#acceptTestAttestation ? { onAttestationFailure: () => true } : {}),
                },
                discovery: { identifierData, discoveryCapabilities: { onIpNetwork: true } },
                passcode,
            },
            { connectNodeAfterCommissioning: false },
        );
        return BigInt(nodeId);
    }

    async remove(n: bigint): Promise<void> {
        if (!this.#controller.getCommissionedNodes().some(x => BigInt(x) === n)) {
            throw new Error(`node ${n} is not on Chitala's fabric`);
        }
        await this.#controller.removeNode(NodeId(n), true);
    }

    /** The fabric's devices: each node's endpoints and their device types, as last known. */
    async list(): Promise<{ node: bigint; endpoints: { endpoint: number; deviceTypes: number[] }[] }[]> {
        const out = [];
        for (const id of this.#controller.getCommissionedNodes()) {
            const node = await this.#controller.getNode(id);
            if (!node.initialized) {
                // never connected since commissioning: the structure is learned by connecting
                const known = new Promise<void>(resolve => node.events.initializedFromRemote.once(() => resolve()));
                node.connect({ subscribeMinIntervalFloorSeconds: 0, subscribeMaxIntervalCeilingSeconds: this.#ceiling });
                await withTimeout(known, LIST_MS, `node ${id}`).catch(e => logger.info(message(e)));
            }
            const endpoints = node.initialized
                ? node.getDevices().map(d => ({
                      endpoint: Number(d.number ?? 0),
                      deviceTypes: d.getDeviceTypes().map(t => t.code),
                  }))
                : [];
            out.push({ node: BigInt(id), endpoints });
        }
        return out;
    }
}
