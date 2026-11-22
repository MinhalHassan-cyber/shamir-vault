"""In-memory unlock sessions.

Shares submitted during an unlock live only here, in RAM, and are discarded when
the session ends. Nothing in this module touches the database.
"""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Optional

import crypto_core as cc

SESSION_TTL = 300        # seconds a session stays open for collecting shares
POST_UNLOCK_GRACE = 120  # seconds the plaintext stays available so a participant can rotate
FAILED_LINGER = 30       # seconds a failed session lingers before cleanup


class SessionError(Exception):
    """Action not allowed in the session's current state (not a bad-share event)."""


@dataclass
class UnlockSession:
    sid: str
    vault_id: str
    record: dict
    expires_at: float
    state: str = "open"                               # open | unlocked | failed
    shares: dict = field(default_factory=dict)        # share index -> share text (RAM only)
    conn_idx: dict = field(default_factory=dict)      # connection id -> share index
    connections: dict = field(default_factory=dict)   # connection id -> websocket
    plaintext: Optional[bytes] = None
    rotate_token: Optional[str] = None


class SessionManager:
    def __init__(self, clock=time.monotonic, ttl: int = SESSION_TTL, max_sessions: int = 200):
        self.clock = clock
        self.ttl = ttl
        self.max_sessions = max_sessions
        self._sessions = {}

    # ----- lifecycle -----

    def create(self, vault_id: str, record: dict) -> UnlockSession:
        if len(self._sessions) >= self.max_sessions:
            raise SessionError("server is busy, try again shortly")
        s = UnlockSession(
            sid=secrets.token_urlsafe(32),  # 256-bit capability: unguessable
            vault_id=vault_id,
            record=record,
            expires_at=self.clock() + self.ttl,
        )
        self._sessions[s.sid] = s
        return s

    def get(self, sid: str) -> Optional[UnlockSession]:
        s = self._sessions.get(sid)
        if s is None or self.clock() >= s.expires_at:
            return None
        return s

    def purge(self):
        """Wipe and remove expired sessions. Returns them so callers can notify sockets."""
        now = self.clock()
        dead = [s for s in self._sessions.values() if now >= s.expires_at]
        for s in dead:
            self._wipe(s)
            del self._sessions[s.sid]
        return dead

    def drop_vault(self, vault_id: str):
        """Wipe and remove every session on a vault (used when the vault is rotated)."""
        dropped = [s for s in self._sessions.values() if s.vault_id == vault_id]
        for s in dropped:
            self._wipe(s)
            del self._sessions[s.sid]
        return dropped

    @staticmethod
    def _wipe(s: UnlockSession) -> None:
        # Best effort: Python cannot guarantee memory is overwritten, only unreferenced.
        s.shares.clear()
        s.plaintext = None
        s.rotate_token = None

    # ----- share handling -----

    def submit(self, s: UnlockSession, conn_id: str, share_text: str) -> dict:
        """Verify and add one share. Raises cc.ShareError (bad share), SessionError
        (not allowed right now) or cc.VaultError (stored vault failed integrity check)."""
        now = self.clock()
        if now >= s.expires_at:
            self._wipe(s)
            raise SessionError("session expired")
        if s.state != "open":
            raise SessionError(f"session is {s.state}")
        if conn_id in s.conn_idx:
            raise SessionError("this connection already submitted a share")

        idx = cc.verify_share(s.record, share_text)  # checks format, checksum, commitment
        if idx in s.shares:
            raise SessionError(f"share #{idx} was already submitted")

        s.shares[idx] = share_text
        s.conn_idx[conn_id] = idx

        if len(s.shares) >= s.record["k"]:
            try:
                s.plaintext = cc.unlock_vault(s.record, list(s.shares.values()))
            except (cc.ShareError, cc.VaultError):
                s.state = "failed"
                s.expires_at = now + FAILED_LINGER
                self._wipe(s)
                raise
            s.state = "unlocked"
            s.rotate_token = secrets.token_urlsafe(32)
            s.expires_at = now + POST_UNLOCK_GRACE
            s.shares.clear()  # shares are no longer needed once the key is recovered
        return {"idx": idx, "state": s.state}

    def release(self, s: UnlockSession, conn_id: str) -> bool:
        """A member disconnected before unlock: drop their share. This is what enforces
        that all k members are connected at the same moment."""
        if s.state != "open":
            return False
        idx = s.conn_idx.pop(conn_id, None)
        if idx is None:
            return False
        s.shares.pop(idx, None)
        return True

    # ----- rotation -----

    def rotate_secret(self, s: UnlockSession, token: str) -> bytes:
        if s.state != "unlocked" or s.plaintext is None or self.clock() >= s.expires_at:
            raise SessionError("session is not unlocked, or the rotation window has closed")
        if not secrets.compare_digest(token.encode(), (s.rotate_token or "").encode()):
            raise PermissionError("invalid rotation token")
        return s.plaintext
