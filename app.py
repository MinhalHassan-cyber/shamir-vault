"""FastAPI application: REST + WebSocket API for the Shamir secret-sharing vault.

Run locally:  uvicorn app:app --reload --port 8000
The frontend in ./static is served from the same origin, so no CORS is needed.
"""
import asyncio
import contextlib
import json
import os
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import crypto_core as cc
import storage
from ratelimit import Lockout, RateLimiter
from sessions import SessionError, SessionManager

# ---------- configuration ----------

TRUST_PROXY = os.environ.get("TRUST_PROXY") == "1"  # set on hosts behind a reverse proxy (Render)
ALLOWED_ORIGINS = {o.strip() for o in os.environ.get("ALLOWED_ORIGINS", "").split(",") if o.strip()}
MAX_SUBMITS_PER_CONNECTION = 10
MAX_MESSAGE_CHARS = 512
STATIC_DIR = Path(__file__).parent / "static"


def _env_int(name: str, default: int) -> int:
    return int(os.environ.get(name, default))


SESSIONS: SessionManager
CREATE_LIMIT: RateLimiter
SESSION_LIMIT: RateLimiter
LOCKOUT: Lockout


def reset_state() -> None:
    """(Re)build all in-memory state. Called at import and by tests."""
    global SESSIONS, CREATE_LIMIT, SESSION_LIMIT, LOCKOUT
    SESSIONS = SessionManager()
    CREATE_LIMIT = RateLimiter(_env_int("CREATE_LIMIT", 10), 60)
    SESSION_LIMIT = RateLimiter(_env_int("SESSION_LIMIT", 20), 60)
    LOCKOUT = Lockout(_env_int("LOCKOUT_FAILS", 5), 300, _env_int("LOCKOUT_SECONDS", 300))


reset_state()


# ---------- helpers ----------

def _client_ip(headers, client) -> str:
    if TRUST_PROXY:
        forwarded = headers.get("x-forwarded-for")
        if forwarded:
            # The proxy appends the real client address last; earlier entries are client-supplied.
            return forwarded.split(",")[-1].strip()
    return client.host if client else "unknown"


def _err(message: str) -> dict:
    return {"type": "error", "message": message}


def _progress(s, msg_type: str = "progress") -> dict:
    return {
        "type": msg_type,
        "state": s.state,
        "collected": len(s.conn_idx),
        "k": s.record["k"],
        "n": s.record["n"],
        "members": sorted(s.conn_idx.values()),  # share indices only, never share values
        "expires_in": max(0, int(s.expires_at - SESSIONS.clock())),
    }


async def _safe_send(ws: WebSocket, msg: dict) -> None:
    with contextlib.suppress(Exception):
        await ws.send_json(msg)


async def _broadcast(s, msg: dict) -> None:
    for ws in list(s.connections.values()):
        await _safe_send(ws, msg)


async def _close_all(s, msg: dict) -> None:
    for ws in list(s.connections.values()):
        await _safe_send(ws, msg)
        with contextlib.suppress(Exception):
            await ws.close()


async def _purge_loop() -> None:
    while True:
        await asyncio.sleep(15)
        with contextlib.suppress(Exception):
            for s in SESSIONS.purge():
                await _close_all(s, {"type": "expired", "message": "session expired"})
            CREATE_LIMIT.prune()
            SESSION_LIMIT.prune()
            LOCKOUT.prune()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    storage.init_db()
    task = asyncio.create_task(_purge_loop())
    yield
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


app = FastAPI(title="Shamir Secret Sharing Vault", lifespan=lifespan)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


# ---------- REST ----------

class CreateVault(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    secret: str = Field(min_length=1, max_length=4096)
    k: int = Field(ge=2, le=10)
    n: int = Field(ge=2, le=10)


class RotateBody(BaseModel):
    token: str = Field(min_length=1, max_length=200)
    k: Optional[int] = Field(default=None, ge=2, le=10)
    n: Optional[int] = Field(default=None, ge=2, le=10)
    name: Optional[str] = Field(default=None, min_length=1, max_length=60)


def _public(vault_id: str, name: str, k: int, n: int, status: str = "active") -> dict:
    return {"vault_id": vault_id, "name": name, "k": k, "n": n, "status": status}


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/vaults", status_code=201)
def api_create_vault(body: CreateVault, request: Request):
    ip = _client_ip(request.headers, request.client)
    if not CREATE_LIMIT.allow(ip):
        raise HTTPException(429, "too many vaults created, slow down")
    if body.k > body.n:
        raise HTTPException(422, "k must not exceed n")
    record, shares = cc.create_vault(body.secret.encode("utf-8"), body.k, body.n)
    vault_id = storage.new_vault_id()
    storage.save_vault(vault_id, body.name, record)
    storage.log_event("vault_created", vault_id, ip, f"k={body.k} n={body.n}")
    # The shares leave the server exactly once, in this response.
    return {**_public(vault_id, body.name, body.k, body.n), "shares": shares}


@app.get("/api/vaults/{vault_id}")
def api_get_vault(vault_id: str):
    v = storage.get_vault(vault_id)
    if v is None:
        raise HTTPException(404, "vault not found")
    return _public(v["id"], v["name"], v["k"], v["n"], v["status"])


@app.get("/api/vaults/{vault_id}/audit")
def api_audit(vault_id: str):
    if storage.get_vault(vault_id) is None:
        raise HTTPException(404, "vault not found")
    return {"events": storage.recent_events(vault_id)}


@app.post("/api/vaults/{vault_id}/sessions", status_code=201)
async def api_open_session(vault_id: str, request: Request):
    ip = _client_ip(request.headers, request.client)
    if not SESSION_LIMIT.allow(ip):
        raise HTTPException(429, "too many sessions, slow down")
    v = storage.get_vault(vault_id)
    if v is None:
        raise HTTPException(404, "vault not found")
    if v["status"] != "active":
        raise HTTPException(409, f"vault is {v['status']}")
    if LOCKOUT.is_locked(vault_id):
        raise HTTPException(429, "vault temporarily locked after repeated bad attempts")
    try:
        s = SESSIONS.create(vault_id, v["record"])
    except SessionError as e:
        raise HTTPException(503, str(e))
    storage.log_event("session_opened", vault_id, ip)
    return {"session_id": s.sid, "k": v["k"], "n": v["n"], "expires_in": SESSIONS.ttl}


@app.post("/api/sessions/{sid}/rotate", status_code=201)
async def api_rotate(sid: str, body: RotateBody, request: Request):
    """Revocation: after a successful unlock, re-split the secret into a brand-new vault
    and revoke the old one. Only a member who submitted a share holds the token."""
    ip = _client_ip(request.headers, request.client)
    s = SESSIONS.get(sid)
    if s is None:
        raise HTTPException(404, "unknown or expired session")
    try:
        plaintext = SESSIONS.rotate_secret(s, body.token)
    except PermissionError:
        storage.log_event("rotate_denied", s.vault_id, ip)
        raise HTTPException(403, "invalid rotation token")
    except SessionError as e:
        raise HTTPException(409, str(e))

    old = storage.get_vault(s.vault_id)
    if old is None or old["status"] != "active":
        raise HTTPException(409, "vault is not active")
    k, n = body.k or old["k"], body.n or old["n"]
    if k > n:
        raise HTTPException(422, "k must not exceed n")

    record, shares = cc.create_vault(plaintext, k, n)
    new_id = storage.new_vault_id()
    name = body.name or old["name"]
    storage.save_vault(new_id, name, record)
    storage.set_status(old["id"], "revoked")
    storage.log_event("vault_rotated", old["id"], ip, f"new_vault={new_id}")
    storage.log_event("vault_created", new_id, ip, f"k={k} n={n} (rotation)")

    for dropped in SESSIONS.drop_vault(old["id"]):
        await _close_all(dropped, {"type": "notice", "message": "this vault was rotated and revoked"})
    return {**_public(new_id, name, k, n), "shares": shares, "revoked_vault_id": old["id"]}


# ---------- WebSocket: live unlock ----------

async def _handle_submit(s, conn_id: str, ws: WebSocket, share, ip: str) -> None:
    if not isinstance(share, str) or not share or len(share) > 200:
        await ws.send_json(_err("invalid share"))
        return
    if LOCKOUT.is_locked(s.vault_id):
        await ws.send_json(_err("vault is temporarily locked after repeated bad attempts"))
        return
    try:
        result = SESSIONS.submit(s, conn_id, share)
    except cc.ShareError as e:  # bad, forged or foreign share: counts toward lockout
        locked = LOCKOUT.record_failure(s.vault_id)
        storage.log_event("bad_share", s.vault_id, ip, str(e))
        message = str(e)
        if locked:
            storage.log_event("vault_locked_out", s.vault_id, ip)
            message += f"; too many bad attempts, vault locked for {int(LOCKOUT.lock_for)}s"
        await ws.send_json(_err(message))
        return
    except SessionError as e:  # duplicates, wrong state, expiry: not an attack signal
        await ws.send_json(_err(str(e)))
        return
    except cc.VaultError:
        storage.log_event("unlock_failed", s.vault_id, ip, "integrity check failed")
        await _broadcast(s, {"type": "failed", "message": "vault data failed its integrity check; it may have been tampered with"})
        return

    storage.log_event("share_accepted", s.vault_id, ip, f"idx={result['idx']}")
    await _broadcast(s, _progress(s))
    if s.state == "unlocked":
        storage.log_event("vault_unlocked", s.vault_id, ip)
        secret_text = s.plaintext.decode("utf-8", errors="replace")
        for cid, sock in list(s.connections.items()):
            if cid in s.conn_idx:  # only connections that contributed a share get the secret
                await _safe_send(sock, {
                    "type": "unlocked",
                    "secret": secret_text,
                    "rotate_token": s.rotate_token,
                    "expires_in": max(0, int(s.expires_at - SESSIONS.clock())),
                })
            else:
                await _safe_send(sock, {"type": "notice", "message": "vault was unlocked by the participating members"})


@app.websocket("/ws/sessions/{sid}")
async def ws_session(ws: WebSocket, sid: str):
    origin = ws.headers.get("origin")
    if ALLOWED_ORIGINS and origin is not None and origin not in ALLOWED_ORIGINS:
        await ws.close(code=1008)
        return
    s = SESSIONS.get(sid)
    if s is None:
        await ws.close(code=4404)
        return
    if len(s.connections) >= s.record["n"] + 2:
        await ws.close(code=1013)
        return

    await ws.accept()
    conn_id = uuid.uuid4().hex
    s.connections[conn_id] = ws
    ip = _client_ip(ws.headers, ws.client)
    submits = 0
    try:
        await ws.send_json(_progress(s, "hello"))
        while True:
            raw = await ws.receive_text()
            if len(raw) > MAX_MESSAGE_CHARS:
                await ws.send_json(_err("message too large"))
                continue
            try:
                msg = json.loads(raw)
            except ValueError:
                await ws.send_json(_err("invalid JSON"))
                continue
            kind = msg.get("type") if isinstance(msg, dict) else None
            if kind == "ping":
                await ws.send_json({"type": "pong"})
            elif kind == "submit_share":
                submits += 1
                if submits > MAX_SUBMITS_PER_CONNECTION:
                    await ws.send_json(_err("too many attempts on this connection"))
                    await ws.close(code=1008)
                    break
                await _handle_submit(s, conn_id, ws, msg.get("share"), ip)
            else:
                await ws.send_json(_err("unknown message type"))
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        s.connections.pop(conn_id, None)
        with contextlib.suppress(Exception):
            if SESSIONS.release(s, conn_id):  # member left before unlock: their share is dropped
                await _broadcast(s, _progress(s))


# ---------- frontend (mounted last so API routes win) ----------

if STATIC_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
