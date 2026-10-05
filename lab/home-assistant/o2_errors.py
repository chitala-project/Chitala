"""Chitala ③A, audit item O2: what does a real Home Assistant answer, and did
anything run, for each error the adapter classifies as "did not run"?

For every case: the entity's state and last_changed before and after the call,
over the WebSocket API and over REST. Tokens are read from 0600 files, never
printed. Run with the Home Assistant venv's Python.
"""

import asyncio
import json
import os

import aiohttp

BASE = os.environ.get("HA_URL", "http://127.0.0.1:8123")
HERE = os.path.dirname(os.path.abspath(__file__))
OWNER = open(os.path.join(HERE, "token")).read().strip()
READER = open(os.path.join(HERE, "reader.token")).read().strip()

# (case, token, domain, service, service_data)
CASES = [
    ("unknown service", OWNER, "lock", "explode", {"entity_id": "lock.kitchen_door"}),
    ("unknown entity", OWNER, "lock", "unlock", {"entity_id": "lock.no_such_door"}),
    ("bad parameter type", OWNER, "light", "turn_on", {"entity_id": "light.kitchen_lights", "brightness_pct": "abc"}),
    ("parameter out of range", OWNER, "light", "turn_on", {"entity_id": "light.kitchen_lights", "brightness_pct": 400}),
    ("unsupported feature (open)", OWNER, "lock", "open", {"entity_id": "lock.kitchen_door"}),
    ("read-only user", READER, "lock", "lock", {"entity_id": "lock.kitchen_door"}),
    ("read-only user, light", READER, "light", "turn_off", {"entity_id": "light.kitchen_lights"}),
]


async def state(http, entity):
    async with http.get(f"{BASE}/api/states/{entity}", headers={"Authorization": f"Bearer {OWNER}"}) as r:
        if r.status != 200:
            return (f"HTTP {r.status}", None)
        s = await r.json()
        return (s["state"], s["last_changed"])


async def ws_call(http, token, domain, service, data):
    ws = await http.ws_connect(BASE + "/api/websocket")
    await ws.receive_json()
    await ws.send_json({"type": "auth", "access_token": token})
    assert (await ws.receive_json())["type"] == "auth_ok"
    await ws.send_json({"id": 1, "type": "call_service", "domain": domain, "service": service, "service_data": data})
    while True:
        msg = await ws.receive_json()
        if msg.get("id") == 1 and msg.get("type") == "result":
            await ws.close()
            if msg["success"]:
                return "success"
            e = msg["error"]
            return f"error code={e.get('code')!r} key={e.get('translation_key')!r} msg={e.get('message', '')[:70]!r}"


async def rest_call(http, token, domain, service, data):
    async with http.post(
        f"{BASE}/api/services/{domain}/{service}", headers={"Authorization": f"Bearer {token}"}, data=json.dumps(data)
    ) as r:
        body = (await r.text())[:70]
        return f"HTTP {r.status} {body!r}"


async def main():
    async with aiohttp.ClientSession() as http:
        for name, token, domain, service, data in CASES:
            entity = data["entity_id"]
            for transport, fn in (("ws", ws_call), ("rest", rest_call)):
                before = await state(http, entity)
                answer = await fn(http, token, domain, service, data)
                await asyncio.sleep(2.5)  # the demo lock moves for 2 s
                after = await state(http, entity)
                ran = "UNCHANGED" if before == after else f"CHANGED {before[0]} -> {after[0]}"
                print(f"{name:28} {transport:4} {answer:110} {ran}")


asyncio.run(main())
