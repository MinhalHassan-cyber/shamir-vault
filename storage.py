"""SQLite persistence layer.

Stores ciphertext records (with per-share commitments) and an audit trail.
It never receives the master secret, the derived key, or any share.
The rest of the app only calls these functions, so swapping SQLite for another
database later means changing this file only.
"""
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager

DB_PATH = os.environ.get("VAULT_DB", "vault.db")


@contextmanager
def _conn():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


def init_db() -> None:
    with _conn() as con:
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS vaults (
                id         TEXT PRIMARY KEY,
                name       TEXT NOT NULL,
                k          INTEGER NOT NULL,
                n          INTEGER NOT NULL,
                record     TEXT NOT NULL,
                status     TEXT NOT NULL DEFAULT 'active',
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                ts       REAL NOT NULL,
                event    TEXT NOT NULL,
                vault_id TEXT,
                ip       TEXT,
                detail   TEXT
            );
            """
        )


def new_vault_id() -> str:
    # 96 random bits: unguessable, so vault IDs cannot be enumerated.
    return secrets.token_urlsafe(12)


def save_vault(vault_id: str, name: str, record: dict) -> None:
    with _conn() as con:
        con.execute(
            "INSERT INTO vaults (id, name, k, n, record, status, created_at) VALUES (?,?,?,?,?,?,?)",
            (vault_id, name, record["k"], record["n"], json.dumps(record), "active", time.time()),
        )


def get_vault(vault_id: str):
    with _conn() as con:
        row = con.execute("SELECT * FROM vaults WHERE id = ?", (vault_id,)).fetchone()
    if row is None:
        return None
    vault = dict(row)
    vault["record"] = json.loads(vault["record"])
    return vault


def set_status(vault_id: str, status: str) -> None:
    with _conn() as con:
        con.execute("UPDATE vaults SET status = ? WHERE id = ?", (status, vault_id))


def log_event(event: str, vault_id=None, ip=None, detail: str = "") -> None:
    with _conn() as con:
        con.execute(
            "INSERT INTO audit_log (ts, event, vault_id, ip, detail) VALUES (?,?,?,?,?)",
            (time.time(), event, vault_id, ip, detail),
        )


def recent_events(vault_id: str, limit: int = 50):
    """Public audit view: no IP addresses, and by construction no secrets."""
    with _conn() as con:
        rows = con.execute(
            "SELECT ts, event, detail FROM audit_log WHERE vault_id = ? ORDER BY id DESC LIMIT ?",
            (vault_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]
