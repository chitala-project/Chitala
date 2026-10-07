#!/usr/bin/env python3
"""Separate the adapter's lines from the core's in a two-guests boot log.

The two guests share one UART. The core's guest writes to it directly; the
adapter's guest writes through its VMM, which puts each of its lines behind
"ADAPTER| " and ends it with a newline (N1.5a). When a line of the adapter's
lands in the middle of one of the core's, the core's line is cut in two:

    [boot]      platform native-hermit · entropy: CPU RNDR (FEAT_RNGADAPTER| ...
    ) · clock ...

This joins the core's pieces again and puts the adapter's line on its own,
before it. Everything from "ADAPTER| " to the end of its line is the
adapter's, and nothing else is, so a joined line holds only the core's bytes,
in their order: the adapter cannot add to it. Without this, a check of the
core's lines failed now and then on a line cut in two (CI, 2026-10-07).

Usage: core-lines.py < log > log   or   core-lines.py --self-test
"""
import sys

PREFIX = "ADAPTER| "


def separate(text):
    out, core = [], ""
    for line in text.split("\n"):
        at = line.find(PREFIX)
        if at > 0:
            # the core was mid-line: keep its piece, and the adapter's line apart
            core += line[:at]
            out.append(line[at:])
        elif at == 0:
            out.append(line)
        else:
            out.append(core + line)
            core = ""
    if core:
        out.append(core)
    return "\n".join(out)


def self_test():
    cut = (
        "[boot]      platform native-hermit · entropy: CPU RNDR (FEAT_RNG"
        "ADAPTER| [halt]      14/14 decisions as expected · CHITALA NATIVE OK\n"
        ") · clock\n"
        "[halt]  ADAPTER| one\n"
        "ADAPTER| two\n"
        "    13/13\n"
        "done"
    )
    want = (
        "ADAPTER| [halt]      14/14 decisions as expected · CHITALA NATIVE OK\n"
        "[boot]      platform native-hermit · entropy: CPU RNDR (FEAT_RNG) · clock\n"
        "ADAPTER| one\n"
        "ADAPTER| two\n"
        "[halt]      13/13\n"
        "done"
    )
    got = separate(cut)
    if got != want:
        print("FAIL  core-lines: the core's line is not joined again")
        print(got)
        return 1
    print("ok    core-lines: a line of the core's cut by the adapter's is joined again; the adapter's stays apart")
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        sys.exit(self_test())
    sys.stdout.write(separate(sys.stdin.read()))
