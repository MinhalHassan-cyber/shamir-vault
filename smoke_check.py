"""End-to-end smoke test against a running server, local or deployed.

Usage:  python smoke_check.py [BASE_URL]        (default http://127.0.0.1:8000)
Creates a vault, opens a live unlock session with 3 simultaneous WebSocket members,
checks the secret comes back, then rotates the vault and checks the old one is revoked.
"""
import asyncio
import contextlib
import json
import sys

import httpx
import websockets

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000").rstrip("/")
WS_BASE = BASE.replace("https://", "wss://").replace("http://", "ws://")
SECRET = "smoke-test-secret"


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


async def main():
    async with httpx.AsyncClient(base_url=BASE, timeout=60) as http:
        r = await http.get("/api/health")
        r.raise_for_status()
        print("ok  health")

        r = await http.post("/api/vaults", json={"name": "Smoke test", "secret": SECRET, "k": 3, "n": 5})
        r.raise_for_status()
        vault = r.json()
        print(f"ok  created vault {vault['vault_id']} with {len(vault['shares'])} shares")

        r = await http.post(f"/api/vaults/{vault['vault_id']}/sessions")
        r.raise_for_status()
        sid = r.json()["session_id"]
        print("ok  opened unlock session")

        token = None
        async with contextlib.AsyncExitStack() as stack:
            socks = [await stack.enter_async_context(websockets.connect(f"{WS_BASE}/ws/sessions/{sid}")) for _ in range(3)]
            for s in socks:
                if json.loads(await s.recv())["type"] != "hello":
                    fail("expected hello")
            for s, share in zip(socks, vault["shares"][:3]):
                await s.send(json.dumps({"type": "submit_share", "share": share}))
            for s in socks:
                while True:
                    m = json.loads(await asyncio.wait_for(s.recv(), 30))
                    if m["type"] in ("error", "failed"):
                        fail(m)
                    if m["type"] == "unlocked":
                        if m["secret"] != SECRET:
                            fail("wrong secret returned")
                        token = m["rotate_token"]
                        break
        print("ok  3 simultaneous members unlocked the vault and recovered the secret")

        r = await http.post(f"/api/sessions/{sid}/rotate", json={"token": token})
        r.raise_for_status()
        new = r.json()
        meta = (await http.get(f"/api/vaults/{vault['vault_id']}")).json()
        if meta["status"] != "revoked":
            fail("old vault was not revoked")
        print(f"ok  rotated: old vault revoked, new vault {new['vault_id']} issued")

    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
