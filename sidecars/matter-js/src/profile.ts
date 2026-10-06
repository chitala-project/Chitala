// The Home profile, as the sidecar checks every request against it (spec 27).
// The sidecar keeps its own copy (profile.json, identical to
// specs/profiles/home-v0.1.json; scripts/check.sh compares them), so a
// request is checked here independently of the process that sent it.

import { readFileSync } from "node:fs";

export interface ProfileCommand {
    cluster: number;
    command: number;
    timed: boolean;
}

export interface ProfileClass {
    name: string;
    deviceTypes: Set<number>;
    /** "cluster/attribute", decimal. */
    attributes: Set<string>;
    /** capability → command. */
    commands: Map<string, ProfileCommand>;
}

export interface Profile {
    name: string;
    classes: Map<string, ProfileClass>;
}

/** A Matter id written as `0x…`. */
function hexId(s: unknown, what: string): number {
    if (typeof s !== "string" || !/^0x[0-9A-Fa-f]{1,8}$/.test(s)) {
        throw new Error(`profile: ${what} is not a 0x… id: ${String(s)}`);
    }
    return Number.parseInt(s.slice(2), 16);
}

export function parseProfile(text: string): Profile {
    const json = JSON.parse(text) as {
        profile: string;
        profile_version: string;
        classes: {
            class: string;
            matter: {
                device_types: string[];
                commands: Record<string, { cluster: string; command: string; timed?: boolean }>;
                attributes: { cluster: string; attribute: string }[];
            };
        }[];
    };
    const classes = new Map<string, ProfileClass>();
    for (const c of json.classes) {
        const commands = new Map<string, ProfileCommand>();
        for (const [capability, m] of Object.entries(c.matter.commands)) {
            commands.set(capability, {
                cluster: hexId(m.cluster, `${c.class} ${capability} cluster`),
                command: hexId(m.command, `${c.class} ${capability} command`),
                timed: m.timed === true,
            });
        }
        classes.set(c.class, {
            name: c.class,
            deviceTypes: new Set(c.matter.device_types.map(t => hexId(t, `${c.class} device type`))),
            attributes: new Set(
                c.matter.attributes.map(
                    a => `${hexId(a.cluster, `${c.class} cluster`)}/${hexId(a.attribute, `${c.class} attribute`)}`,
                ),
            ),
            commands,
        });
    }
    return { name: `${json.profile}@${json.profile_version}`, classes };
}

export function loadProfile(): Profile {
    return parseProfile(readFileSync(new URL("../profile.json", import.meta.url), "utf8"));
}
