"""Chitala ③A lab: a logging TCP proxy, 127.0.0.1:8124 -> 127.0.0.1:8123.

The ground truth of what Chitala sends to Home Assistant: one line per
connection with the request line and the status line of the answer. Bytes are
forwarded untouched; the Authorization header is never logged.
"""

import asyncio
import datetime
import os
import sys

LOG = open(sys.argv[1], "a")
UPSTREAM = int(os.environ.get("HA_PORT", "8123"))


def note(text: str) -> None:
    print(f"{datetime.datetime.now():%H:%M:%S.%f} {text}", file=LOG, flush=True)


async def pipe(reader, writer, first_line_tag=None):
    seen = False
    try:
        while data := await reader.read(65536):
            if first_line_tag and not seen:
                seen = True
                note(f"{first_line_tag} {data.split(b'\r\n', 1)[0].decode(errors='replace')[:80]}")
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        writer.close()


async def handle(client_r, client_w):
    peer = client_w.get_extra_info("peername")
    try:
        ha_r, ha_w = await asyncio.open_connection("127.0.0.1", UPSTREAM)
    except OSError as e:
        note(f"{peer[1]} cannot reach Home Assistant: {e}")
        client_w.close()
        return
    await asyncio.gather(pipe(client_r, ha_w, f"{peer[1]} ->"), pipe(ha_r, client_w, f"{peer[1]} <-"))


async def main():
    server = await asyncio.start_server(handle, "127.0.0.1", 8124)
    note("tap listening on 127.0.0.1:8124")
    async with server:
        await server.serve_forever()


asyncio.run(main())
