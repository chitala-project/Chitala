"""Chitala ③A lab: commission the virtual Matter devices into Home Assistant's
Matter fabric (through the OHF Matter Server), by their QR setup codes.

    <ha venv>/bin/python commission.py light=MT:... plug=MT:... lock=MT:...

Uses Home Assistant's `matter/commission` WebSocket command, on the IP network
only (no Bluetooth). The owner's token is read from HA_DIR/token; nothing
secret is printed.
"""

import asyncio
import os
import sys

import aiohttp

HA = os.environ.get("HA_URL", "http://127.0.0.1:8123")
HA_DIR = os.environ.get("HA_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ha"))


async def main() -> int:
    token = open(os.path.join(HA_DIR, "token")).read().strip()
    async with aiohttp.ClientSession() as http:
        async with http.ws_connect(HA + "/api/websocket") as ws:
            await ws.receive_json()
            await ws.send_json({"type": "auth", "access_token": token})
            assert (await ws.receive_json())["type"] == "auth_ok"
            failed = 0
            for n, arg in enumerate(sys.argv[1:], start=1):
                name, code = arg.split("=", 1)
                await ws.send_json({"id": n, "type": "matter/commission", "code": code, "network_only": True})
                while True:
                    msg = await ws.receive_json(timeout=180)
                    if msg.get("id") == n and msg.get("type") == "result":
                        break
                ok = msg["success"]
                failed += not ok
                print(f"{name}: {'commissioned' if ok else msg['error']}", flush=True)
    return 1 if failed else 0


sys.exit(asyncio.run(main()))
