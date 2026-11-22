import base64
import json
import sqlite3
from contextlib import ExitStack, contextmanager

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import app as appmod
import crypto_core as cc
import storage

SECRET = "MASTER-KEY: board-vault-2026"
BAD_SHARE = "SSS1-1-" + "-".join(["AAAA"] * 8)  # well-formed, but fails its checksum


# ---------- fixtures and helpers ----------

@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "test.db"))
    appmod.reset_state()
    with TestClient(appmod.app) as c:
        yield c


def make_vault(client, k=3, n=5, secret=SECRET, name="Board vault"):
    r = client.post("/api/vaults", json={"name": name, "secret": secret, "k": k, "n": n})
    assert r.status_code == 201, r.text
    return r.json()


def open_session(client, vault_id):
    r = client.post(f"/api/vaults/{vault_id}/sessions")
    assert r.status_code == 201, r.text
    return r.json()["session_id"]


@contextmanager
def sockets(client, sid, count):
    with ExitStack() as stack:
        socks = [stack.enter_context(client.websocket_connect(f"/ws/sessions/{sid}")) for _ in range(count)]
        for s in socks:
            assert s.receive_json()["type"] == "hello"
        yield socks


def submit(ws, share):
    ws.send_json({"type": "submit_share", "share": share})


def unlock(client, vault, picks=(0, 1, 2)):
    """Run a full live unlock. Returns (session_id, rotate_token, secret)."""
    sid = open_session(client, vault["vault_id"])
    with sockets(client, sid, len(picks)) as socks:
        for w, p in zip(socks, picks):
            submit(w, vault["shares"][p])
            for x in socks:
                assert x.receive_json()["type"] == "progress"
        msgs = [w.receive_json() for w in socks]
    assert all(m["type"] == "unlocked" for m in msgs)
    return sid, msgs[0]["rotate_token"], msgs[0]["secret"]


# ---------- vault creation ----------

def test_create_returns_n_unique_shares_once(client):
    v = make_vault(client)
    assert len(v["shares"]) == 5 and len(set(v["shares"])) == 5
    meta = client.get(f"/api/vaults/{v['vault_id']}").json()
    assert meta == {"vault_id": v["vault_id"], "name": "Board vault", "k": 3, "n": 5, "status": "active"}
    assert "shares" not in meta and "record" not in meta


@pytest.mark.parametrize("body", [
    {"name": "x", "secret": "s", "k": 1, "n": 5},
    {"name": "x", "secret": "s", "k": 6, "n": 5},
    {"name": "x", "secret": "s", "k": 3, "n": 11},
    {"name": "x", "secret": "", "k": 3, "n": 5},
    {"name": "", "secret": "s", "k": 3, "n": 5},
])
def test_create_validation(client, body):
    assert client.post("/api/vaults", json=body).status_code == 422


def test_database_holds_no_secrets(client, tmp_path):
    v = make_vault(client)
    data = (tmp_path / "test.db").read_bytes()
    assert SECRET.encode() not in data
    for share in v["shares"]:
        _, raw = cc.decode_share(share)
        assert share.encode() not in data
        assert raw not in data and raw.hex().encode() not in data and base64.b64encode(raw) not in data


def test_unknown_vault_404(client):
    assert client.get("/api/vaults/nope").status_code == 404
    assert client.post("/api/vaults/nope/sessions").status_code == 404


# ---------- live unlock ----------

def test_live_unlock_3_of_5(client):
    v = make_vault(client)
    sid = open_session(client, v["vault_id"])
    with sockets(client, sid, 3) as (a, b, c):
        for w, share, expected in ((a, v["shares"][0], 1), (b, v["shares"][2], 2), (c, v["shares"][4], 3)):
            submit(w, share)
            for x in (a, b, c):
                m = x.receive_json()
                assert m["type"] == "progress" and m["collected"] == expected
        for w in (a, b, c):
            m = w.receive_json()
            assert m["type"] == "unlocked" and m["secret"] == SECRET and m["rotate_token"]


def test_fewer_than_k_never_unlocks(client):
    v = make_vault(client)
    sid = open_session(client, v["vault_id"])
    with sockets(client, sid, 2) as (a, b):
        submit(a, v["shares"][0])
        submit(b, v["shares"][1])
        msgs = [a.receive_json() for _ in range(2)]
        assert all(m["type"] == "progress" for m in msgs)
        assert msgs[-1]["collected"] == 2 and msgs[-1]["state"] == "open"


def test_observer_never_receives_secret_or_token(client):
    v = make_vault(client)
    sid = open_session(client, v["vault_id"])
    with sockets(client, sid, 4) as (a, b, c, observer):
        for w, p in zip((a, b, c), (0, 1, 2)):
            submit(w, v["shares"][p])
        seen = [observer.receive_json() for _ in range(4)]   # 3 progress + 1 notice
    assert seen[-1]["type"] == "notice"
    blob = json.dumps(seen)
    assert SECRET not in blob and "rotate_token" not in blob


def test_bad_share_rejected_and_session_survives(client):
    v = make_vault(client)
    sid = open_session(client, v["vault_id"])
    with sockets(client, sid, 3) as (a, b, c):
        submit(a, BAD_SHARE)
        assert a.receive_json()["type"] == "error"
        for w, p in zip((a, b, c), (0, 1, 2)):  # same socket may still submit a good share
            submit(w, v["shares"][p])
            for x in (a, b, c):
                assert x.receive_json()["type"] == "progress"
        assert a.receive_json()["secret"] == SECRET


def test_forged_share_with_valid_checksum_rejected(client):
    v = make_vault(client)
    sid = open_session(client, v["vault_id"])
    idx, raw = cc.decode_share(v["shares"][0])
    forged = cc.encode_share(idx, bytes([raw[0] ^ 1]) + raw[1:])
    with sockets(client, sid, 1) as (a,):
        submit(a, forged)
        m = a.receive_json()
        assert m["type"] == "error" and "altered" in m["message"]


def test_share_from_another_vault_rejected(client):
    v = make_vault(client)
    other = make_vault(client)
    sid = open_session(client, v["vault_id"])
    with sockets(client, sid, 1) as (a,):
        submit(a, other["shares"][0])
        assert a.receive_json()["type"] == "error"


def test_duplicate_share_rejected_without_lockout(client):
    v = make_vault(client)
    sid = open_session(client, v["vault_id"])
    with sockets(client, sid, 2) as (a, b):
        submit(a, v["shares"][0])
        a.receive_json(); b.receive_json()
        for _ in range(6):
            submit(b, v["shares"][0])
            m = b.receive_json()
            assert m["type"] == "error" and "already" in m["message"]
    assert client.post(f"/api/vaults/{v['vault_id']}/sessions").status_code == 201  # not locked


def test_one_share_per_connection(client):
    v = make_vault(client)
    sid = open_session(client, v["vault_id"])
    with sockets(client, sid, 2) as (a, b):
        submit(a, v["shares"][0])
        a.receive_json(); b.receive_json()
        submit(a, v["shares"][1])
        m = a.receive_json()
        assert m["type"] == "error" and "already submitted" in m["message"]


def test_disconnect_drops_share_so_members_must_be_simultaneous(client):
    v = make_vault(client)
    sid = open_session(client, v["vault_id"])
    with sockets(client, sid, 2) as (b, c):
        with client.websocket_connect(f"/ws/sessions/{sid}") as a:
            assert a.receive_json()["type"] == "hello"
            submit(a, v["shares"][0])
            for x in (a, b, c):
                assert x.receive_json()["collected"] == 1
        m = b.receive_json()                      # a left: its share was dropped
        assert m["type"] == "progress" and m["collected"] == 0
        c.receive_json()
        submit(b, v["shares"][1]); submit(c, v["shares"][2])
        last = None
        for _ in range(2):
            last = b.receive_json()
        assert last["collected"] == 2 and last["state"] == "open"   # only 2 present: no unlock


def test_lockout_after_repeated_bad_shares(client):
    v = make_vault(client)
    sid = open_session(client, v["vault_id"])
    with sockets(client, sid, 1) as (a,):
        msg = None
        for _ in range(5):
            submit(a, BAD_SHARE)
            msg = a.receive_json()
            assert msg["type"] == "error"
        assert "locked" in msg["message"]
    assert client.post(f"/api/vaults/{v['vault_id']}/sessions").status_code == 429


def test_per_connection_attempt_cap(client, monkeypatch):
    monkeypatch.setenv("LOCKOUT_FAILS", "100")
    appmod.reset_state()
    v = make_vault(client)
    sid = open_session(client, v["vault_id"])
    with sockets(client, sid, 1) as (a,):
        for _ in range(10):
            submit(a, BAD_SHARE)
            assert a.receive_json()["type"] == "error"
        submit(a, BAD_SHARE)
        assert "too many attempts" in a.receive_json()["message"]
        with pytest.raises(WebSocketDisconnect):
            a.receive_json()


def test_malformed_messages_handled(client):
    v = make_vault(client)
    sid = open_session(client, v["vault_id"])
    with sockets(client, sid, 1) as (a,):
        a.send_text("not json")
        assert a.receive_json()["type"] == "error"
        a.send_text("x" * 600)
        assert "too large" in a.receive_json()["message"]
        a.send_json({"type": "dance"})
        assert a.receive_json()["type"] == "error"
        a.send_json({"type": "ping"})
        assert a.receive_json()["type"] == "pong"


def test_unknown_session_rejected(client):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/sessions/does-not-exist"):
            pass


def test_expired_session_rejected(client):
    v = make_vault(client)
    sid = open_session(client, v["vault_id"])
    with sockets(client, sid, 1) as (a,):
        s = appmod.SESSIONS._sessions[sid]
        s.expires_at = appmod.SESSIONS.clock() - 1
        submit(a, v["shares"][0])
        assert "expired" in a.receive_json()["message"]
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/ws/sessions/{sid}"):
            pass


def test_tampered_ciphertext_detected_at_unlock(client):
    v = make_vault(client)
    con = sqlite3.connect(storage.DB_PATH)
    rec = json.loads(con.execute("SELECT record FROM vaults WHERE id=?", (v["vault_id"],)).fetchone()[0])
    ct = bytearray(base64.b64decode(rec["ciphertext"]))
    ct[0] ^= 1
    rec["ciphertext"] = base64.b64encode(bytes(ct)).decode()
    con.execute("UPDATE vaults SET record=? WHERE id=?", (json.dumps(rec), v["vault_id"]))
    con.commit()
    con.close()

    sid = open_session(client, v["vault_id"])
    with sockets(client, sid, 3) as socks:
        for w, p in zip(socks, (0, 1, 2)):
            submit(w, v["shares"][p])
        for w in socks:
            assert w.receive_json()["type"] == "progress"
            assert w.receive_json()["type"] == "progress"
            m = w.receive_json()
            assert m["type"] == "failed" and SECRET not in json.dumps(m)


# ---------- rotation (revocation) ----------

def test_rotate_revokes_old_vault_and_issues_new_shares(client):
    v = make_vault(client)
    sid, token, secret = unlock(client, v)
    assert secret == SECRET
    r = client.post(f"/api/sessions/{sid}/rotate", json={"token": token})
    assert r.status_code == 201, r.text
    new = r.json()
    assert new["vault_id"] != v["vault_id"] and len(new["shares"]) == 5
    assert client.get(f"/api/vaults/{v['vault_id']}").json()["status"] == "revoked"
    assert client.post(f"/api/vaults/{v['vault_id']}/sessions").status_code == 409

    _, _, secret2 = unlock(client, new, picks=(1, 3, 4))   # new shares unlock the same secret
    assert secret2 == SECRET

    sid2 = open_session(client, new["vault_id"])           # old shares are useless on the new vault
    with sockets(client, sid2, 1) as (a,):
        submit(a, v["shares"][0])
        assert a.receive_json()["type"] == "error"


def test_rotate_requires_valid_token(client):
    v = make_vault(client)
    sid, token, _ = unlock(client, v)
    assert client.post(f"/api/sessions/{sid}/rotate", json={"token": "wrong"}).status_code == 403
    assert client.post(f"/api/sessions/{sid}/rotate", json={}).status_code == 422
    assert client.post(f"/api/sessions/{sid}/rotate", json={"token": token}).status_code == 201


def test_rotate_before_unlock_rejected(client):
    v = make_vault(client)
    sid = open_session(client, v["vault_id"])
    assert client.post(f"/api/sessions/{sid}/rotate", json={"token": "x"}).status_code == 409
    assert client.post("/api/sessions/unknown/rotate", json={"token": "x"}).status_code == 404


# ---------- abuse controls, headers, audit, static ----------

def test_create_rate_limited(client, monkeypatch):
    monkeypatch.setenv("CREATE_LIMIT", "3")
    appmod.reset_state()
    codes = [client.post("/api/vaults", json={"name": "x", "secret": "s", "k": 2, "n": 3}).status_code for _ in range(4)]
    assert codes == [201, 201, 201, 429]


def test_security_headers(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["cache-control"] == "no-store"
    assert "max-age" in r.headers["strict-transport-security"]


def test_audit_log_records_events_without_secrets(client):
    v = make_vault(client)
    unlock(client, v)
    events = client.get(f"/api/vaults/{v['vault_id']}/audit").json()["events"]
    names = {e["event"] for e in events}
    assert {"vault_created", "session_opened", "share_accepted", "vault_unlocked"} <= names
    blob = json.dumps(events)
    assert SECRET not in blob
    assert all(share not in blob for share in v["shares"])


def test_frontend_is_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "Shamir" in r.text
