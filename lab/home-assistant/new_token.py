"""Chitala ③A lab: issue a new long-lived token `chitala-lab` (0600 file `token`),
as an owner would after revoking the old one. Logs in with the owner's password
(0600 file); prints no secret. Run with the Home Assistant venv's Python.
"""

import asyncio
import os

import aiohttp

from bootstrap_token import call, secret_file, token_for_login, ws_session

HERE = os.path.dirname(os.path.abspath(__file__))


async def main() -> None:
    password = open(os.path.join(HERE, "owner.password")).read().strip()
    async with aiohttp.ClientSession() as http:
        ws = await ws_session(http, await token_for_login(http, "chitala-lab", password))
        token = await call(
            ws, 1, {"type": "auth/long_lived_access_token", "client_name": "chitala-lab", "lifespan": 365}
        )
        secret_file("token", token)
        await ws.close()


asyncio.run(main())
