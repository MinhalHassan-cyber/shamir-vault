"""
Crypto core for the Shamir Secret Sharing emergency vault.

Only vetted primitives from PyCryptodome are used (Shamir over GF(2^128),
HKDF-SHA256, AES-256-GCM, CSPRNG). Nothing here implements a primitive by hand.

Design:
  master secret S (16 random bytes)
    -> Shamir split into n shares, any k reconstruct S
    -> vault key K = HKDF(S, salt)  (256-bit)
    -> vault payload encrypted with AES-256-GCM under K

The server stores only: ciphertext, nonce, tag, salt, k, n and one SHA-256
commitment per share. It never stores S, K, or any share.
"""
import base64
import hashlib
import hmac

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Random import get_random_bytes

SECRET_LEN = 16          # PyCryptodome Shamir operates on exactly 16-byte secrets
SHARE_PREFIX = "SSS1"
VERSION = 1


class ShareError(ValueError):
    """A share is malformed, foreign, altered, duplicated, or there are too few."""


class VaultError(Exception):
    """Authenticated decryption failed."""


# ---------- helpers ----------

def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _b64d(s: str) -> bytes:
    return base64.b64decode(s)


def _checksum(idx: int, raw: bytes) -> bytes:
    # Typo detection only (not a security control).
    return hashlib.sha256(b"share-checksum/v1" + bytes([idx]) + raw).digest()[:4]


def _commit(salt: bytes, idx: int, raw: bytes) -> str:
    # Shares are 128-bit uniform random, so a plain hash is a safe commitment.
    return hashlib.sha256(b"share-commit/v1" + salt + bytes([idx]) + raw).hexdigest()


def _derive_key(master: bytes, salt: bytes) -> bytes:
    return HKDF(master, 32, salt, SHA256, context=b"shamir-vault/aes-256-gcm/v1")


def _aad(k: int, n: int, salt: bytes) -> bytes:
    return f"SSSV{VERSION}|{k}|{n}|".encode() + salt


# ---------- share encoding ----------

def encode_share(idx: int, raw: bytes) -> str:
    """SSS1-<idx>-XXXX-XXXX-... (16-byte share + 4-byte checksum, base32, grouped)."""
    if not (1 <= idx <= 255) or len(raw) != SECRET_LEN:
        raise ShareError("invalid share index or length")
    body = base64.b32encode(raw + _checksum(idx, raw)).decode()  # 20 bytes -> 32 chars
    groups = "-".join(body[i:i + 4] for i in range(0, len(body), 4))
    return f"{SHARE_PREFIX}-{idx}-{groups}"


def decode_share(text: str):
    parts = text.strip().upper().split("-")
    if len(parts) < 3 or parts[0] != SHARE_PREFIX or not parts[1].isdigit():
        raise ShareError("malformed share")
    idx = int(parts[1])
    if not (1 <= idx <= 255):
        raise ShareError("malformed share index")
    try:
        blob = base64.b32decode("".join(parts[2:]))
    except Exception as e:
        raise ShareError("malformed share encoding") from e
    if len(blob) != SECRET_LEN + 4:
        raise ShareError("malformed share length")
    raw, chk = blob[:SECRET_LEN], blob[SECRET_LEN:]
    if not hmac.compare_digest(chk, _checksum(idx, raw)):
        raise ShareError("share failed checksum (typo?)")
    return idx, raw


# ---------- vault lifecycle ----------

def create_vault(plaintext: bytes, k: int, n: int):
    """Returns (vault_record: dict, shares: list[str]). Shares are shown once, never stored."""
    if not (2 <= k <= n <= 255):
        raise ValueError("require 2 <= k <= n <= 255")
    master = get_random_bytes(SECRET_LEN)
    raw_shares = Shamir.split(k, n, master, ssss=False)  # [(idx, 16-byte share)]

    salt = get_random_bytes(16)
    nonce = get_random_bytes(12)
    cipher = AES.new(_derive_key(master, salt), AES.MODE_GCM, nonce=nonce)
    cipher.update(_aad(k, n, salt))
    ct, tag = cipher.encrypt_and_digest(plaintext)

    record = {
        "version": VERSION, "k": k, "n": n,
        "salt": _b64e(salt), "nonce": _b64e(nonce),
        "ciphertext": _b64e(ct), "tag": _b64e(tag),
        "commitments": {str(i): _commit(salt, i, s) for i, s in raw_shares},
    }
    shares = [encode_share(i, s) for i, s in raw_shares]
    return record, shares


def verify_share(record: dict, share_text: str) -> int:
    """Check one share against the vault's commitment. Returns its index or raises ShareError."""
    idx, raw = decode_share(share_text)
    expected = record["commitments"].get(str(idx))
    if expected is None:
        raise ShareError(f"share #{idx} is not part of this vault")
    if not hmac.compare_digest(_commit(_b64d(record["salt"]), idx, raw), expected):
        raise ShareError(f"share #{idx} does not belong to this vault or was altered")
    return idx


def unlock_vault(record: dict, share_texts, *, check_commitments: bool = True) -> bytes:
    """Reconstruct the key from >= k shares and decrypt. Raises ShareError / VaultError."""
    k, n = record["k"], record["n"]
    salt = _b64d(record["salt"])
    parsed = {}
    for text in share_texts:
        idx, raw = decode_share(text)
        if idx in parsed:
            raise ShareError(f"duplicate share #{idx}")
        if check_commitments:
            verify_share(record, text)
        parsed[idx] = raw
    if len(parsed) < k:
        raise ShareError(f"need {k} shares, got {len(parsed)}")

    chosen = sorted(parsed.items())[:k]
    master = Shamir.combine(chosen, ssss=False)

    cipher = AES.new(_derive_key(master, salt), AES.MODE_GCM, nonce=_b64d(record["nonce"]))
    cipher.update(_aad(k, n, salt))
    try:
        return cipher.decrypt_and_verify(_b64d(record["ciphertext"]), _b64d(record["tag"]))
    except ValueError as e:
        raise VaultError("decryption failed: wrong or altered shares, or tampered vault") from e
