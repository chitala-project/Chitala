"""Chitala ③A lab: an independent witness of every service call Home Assistant
receives (its `call_service` bus events), to count commands and catch any
resend. One line per call: time, domain.service, entity. Reconnects when Home
Assistant restarts. Run with the Home Assistant venv's Python.
"""

import asyncio
import datetime
import os
import sys

import aiohttp

BASE = os.environ.get("HA_URL", "http://127.0.0.1:8123")
HERE = os.path.dirname(os.path.abspath(__file__))


async def listen(out) -> None:
    async with aiohttp.ClientSession() as http:
        async with http.ws_connect(BASE + "/api/websocket", heartbeat=10) as ws:
            await ws.receive_json()
            # the token file is read on every connection: it may have been replaced
            token = open(os.path.join(HERE, "token")).read().strip()
            await ws.send_json({"type": "auth", "access_token": token})
            if (await ws.receive_json())["type"] != "auth_ok":
                raise PermissionError("token rejected")
            await ws.send_json({"id": 1, "type": "subscribe_events", "event_type": "call_service"})
            print(f"{datetime.datetime.now():%H:%M:%S.%f} listening", file=out, flush=True)
            async for msg in ws:
                data = msg.json()
                if data.get("type") != "event":
                    continue
                d = data["event"]["data"]
                entity = (d.get("service_data") or {}).get("entity_id")
                print(f"{datetime.datetime.now():%H:%M:%S.%f} {d['domain']}.{d['service']} {entity}", file=out, flush=True)


async def main() -> None:
    out = open(sys.argv[1], "a")
    while True:
        try:
            await listen(out)
        except Exception as e:  # Home Assistant down or restarting, or the token revoked
            print(f"{datetime.datetime.now():%H:%M:%S.%f} disconnected: {type(e).__name__}", file=out, flush=True)
            # a rejected token counts as a failed login in Home Assistant: wait longer
            await asyncio.sleep(5 if isinstance(e, PermissionError) else 1)


asyncio.run(main())
