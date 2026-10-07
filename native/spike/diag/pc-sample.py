#!/usr/bin/env python3
"""N1.6 diagnosis: sample the emulated CPU's PC and exception level through
QEMU's monitor, about every INTERVAL s, while a boot runs.

Usage: pc-sample.py MONITOR_SOCKET OUT [INTERVAL]
Writes one line per sample: host time (s), EL, PC.
"""
import re, socket, sys, time

sock_path, out = sys.argv[1], sys.argv[2]
interval = float(sys.argv[3]) if len(sys.argv) > 3 else 0.05
for _ in range(200):
    try:
        s = socket.socket(socket.AF_UNIX); s.connect(sock_path); break
    except OSError:
        time.sleep(0.1)
else:
    sys.exit("no monitor")
s.settimeout(5)
def until_prompt():
    buf = b""
    while not buf.endswith(b"(qemu) "):
        chunk = s.recv(65536)
        if not chunk:
            raise EOFError
        buf += chunk
    return buf.decode(errors="replace")
until_prompt()
pc_re = re.compile(r"PC=([0-9a-f]{16})")
el_re = re.compile(r"PSTATE=[0-9a-f]+ \S+ (EL\d)")
start = time.time()
with open(out, "w") as f:
    try:
        while True:
            s.sendall(b"info registers\n")
            text = until_prompt()
            pc, el = pc_re.search(text), el_re.search(text)
            if pc:
                f.write(f"{time.time() - start:.3f} {el.group(1) if el else '?'} {pc.group(1)}\n")
            time.sleep(interval)
    except (EOFError, OSError, socket.timeout):
        pass
