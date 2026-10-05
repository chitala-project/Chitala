"""Chitala ③A lab: onboard a fresh Home Assistant and mint long-lived tokens.

Creates the owner user through onboarding, and a read-only user (for the
`unauthorized` check of audit item O2). Tokens and passwords go to 0600 files
next to this script and are never printed.

Run with the Home Assistant venv's Python (it has aiohttp).
"""

import asyncio
import os
import secrets
import sys

import aiohttp

BASE = os.environ.get("HA_URL", "http://127.0.0.1:8123")
CLIENT_ID = BASE + "/"
HERE = os.path.dirname(os.path.abspath(__file__))


def secret_file(name: str, value: str) -> None:
    path = os.path.join(HERE, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(value)
    print(f"wrote {name} (0600)")


async def ws_session(http: aiohttp.ClientSession, access_token: str):
    ws = await http.ws_connect(BASE + "/api/websocket")
    assert (await ws.receive_json())["type"] == "auth_required"
    await ws.send_json({"type": "auth", "access_token": access_token})
    msg = await ws.receive_json()
    assert msg["type"] == "auth_ok", msg
    return ws


async def call(ws, msg_id: int, payload: dict) -> dict:
    await ws.send_json({"id": msg_id, **payload})
    while True:
        msg = await ws.receive_json()
        if msg.get("id") == msg_id and msg.get("type") == "result":
            if not msg["success"]:
                raise RuntimeError(f"{payload['type']}: {msg['error']}")
            return msg["result"]


async def token_for_login(http: aiohttp.ClientSession, username: str, password: str) -> str:
    """Log in through the auth flow and return a short-lived access token."""
    async with http.post(
        BASE + "/auth/login_flow",
        json={"client_id": CLIENT_ID, "handler": ["homeassistant", None], "redirect_uri": CLIENT_ID},
    ) as r:
        flow = await r.json()
    async with http.post(
        BASE + f"/auth/login_flow/{flow['flow_id']}",
        json={"client_id": CLIENT_ID, "username": username, "password": password},
    ) as r:
        done = await r.json()
    assert done.get("type") == "create_entry", done.get("type")
    return await exchange(http, done["result"])


async def exchange(http: aiohttp.ClientSession, code: str) -> str:
    async with http.post(
        BASE + "/auth/token",
        data={"grant_type": "authorization_code", "code": code, "client_id": CLIENT_ID},
    ) as r:
        r.raise_for_status()
        return (await r.json())["access_token"]


async def main() -> int:
    owner_pw = secrets.token_urlsafe(24)
    reader_pw = secrets.token_urlsafe(24)
    async with aiohttp.ClientSession() as http:
        async with http.post(
            BASE + "/api/onboarding/users",
            json={
                "client_id": CLIENT_ID,
                "name": "Chitala Lab",
                "username": "chitala-lab",
                "password": owner_pw,
                "language": "en",
            },
        ) as r:
            if r.status != 200:
                print(f"onboarding refused: HTTP {r.status} (already onboarded?)", file=sys.stderr)
                return 1
            auth_code = (await r.json())["auth_code"]
        secret_file("owner.password", owner_pw)
        access = await exchange(http, auth_code)

        ws = await ws_session(http, access)
        token = await call(
            ws, 1, {"type": "auth/long_lived_access_token", "client_name": "chitala-lab", "lifespan": 365}
        )
        secret_file("token", token)

        # Home Assistant 2026.9 moves the http: YAML into storage as a config on
        # trial; unless it is confirmed within five minutes it reverts to the
        # default (every interface) and restarts. Confirm the loopback listener.
        http_conf = await call(ws, 2, {"type": "http/config"})
        if http_conf.get("pending") and not http_conf["pending"].get("error"):
            await call(ws, 3, {"type": "http/config/promote"})
            print("confirmed the HTTP config:", http_conf["pending"].get("server_host"))

        # A read-only user: Home Assistant refuses its service calls (O2, `unauthorized`).
        user = await call(
            ws, 4, {"type": "config/auth/create", "name": "Chitala Reader", "group_ids": ["system-read-only"]}
        )
        await call(
            ws,
            5,
            {
                "type": "config/auth_provider/homeassistant/create",
                "user_id": user["user"]["id"],
                "username": "chitala-reader",
                "password": reader_pw,
            },
        )
        secret_file("reader.password", reader_pw)
        await ws.close()

        reader_access = await token_for_login(http, "chitala-reader", reader_pw)
        ws = await ws_session(http, reader_access)
        reader_token = await call(
            ws, 1, {"type": "auth/long_lived_access_token", "client_name": "chitala-reader", "lifespan": 365}
        )
        secret_file("reader.token", reader_token)
        await ws.close()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
