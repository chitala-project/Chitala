// The sidecar's command line, parsed before matter.js loads: matter.js reads
// its own options from the command line and the environment, and must get
// none of ours. main.ts imports this module first.

export type Mode = "serve" | "admin";

export interface Options {
    mode: Mode;
    storage: string;
    subscriptionCeilingSeconds: number;
    acceptTestAttestation: boolean;
}

function usage(why: string): never {
    process.stderr.write(`chitala-matter-js: ${why}\nusage: main.ts serve|admin --storage <dir> [options]\n`);
    process.exit(2);
}

function parse(argv: string[]): Options {
    const [mode, ...args] = argv;
    if (mode !== "serve" && mode !== "admin") usage("the mode is serve or admin");
    let storage: string | undefined;
    let ceiling = 60;
    let acceptTestAttestation = false;
    for (let i = 0; i < args.length; i++) {
        const a = args[i];
        if (a === "--storage") storage = args[++i];
        else if (a === "--subscription-ceiling") ceiling = Number(args[++i]);
        else if (a === "--accept-test-attestation" && mode === "admin") acceptTestAttestation = true;
        else usage(`unknown option ${a}`);
    }
    if (storage === undefined || storage === "") usage("--storage is required");
    if (!Number.isInteger(ceiling) || ceiling < 1 || ceiling > 3600) usage("--subscription-ceiling: 1..3600 seconds");
    return { mode, storage, subscriptionCeilingSeconds: ceiling, acceptTestAttestation };
}

export const options = parse(process.argv.slice(2));
process.argv = process.argv.slice(0, 2);
