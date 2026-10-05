"""Chitala ③A lab: revoke the long-lived token named `chitala-lab`, as an owner
who deletes it in the Home Assistant UI would. Logs in with the owner's
password (0600 file); prints no secret.
"""

import asyncio
import os

import aiohttp

from bootstrap_token import call, token_for_login, ws_session

HERE = os.path.dirname(os.path.abspath(__file__))


async def main() -> None:
    password = open(os.path.join(HERE, "owner.password")).read().strip()
    async with aiohttp.ClientSession() as http:
        access = await token_for_login(http, "chitala-lab", password)
        ws = await ws_session(http, access)
        tokens = await call(ws, 1, {"type": "auth/refresh_tokens"})
        target = [t for t in tokens if t.get("client_name") == "chitala-lab" and t.get("type") == "long_lived_access_token"]
        assert len(target) == 1, f"expected one chitala-lab token, found {len(target)}"
        await call(ws, 2, {"type": "auth/delete_refresh_token", "refresh_token_id": target[0]["id"]})
        print("revoked the long-lived token chitala-lab")
        await ws.close()


asyncio.run(main())
