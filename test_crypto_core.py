import copy
import itertools

import pytest

import crypto_core as cc

SECRET = b"MASTER-DECRYPTION-KEY: 7f3a9c-vault-2026"


@pytest.fixture()
def vault():
    return cc.create_vault(SECRET, 3, 5)


def test_any_3_of_5_unlock(vault):
    record, shares = vault
    for combo in itertools.combinations(shares, 3):
        assert cc.unlock_vault(record, list(combo)) == SECRET


def test_more_than_k_shares_unlock(vault):
    record, shares = vault
    assert cc.unlock_vault(record, shares[:4]) == SECRET
    assert cc.unlock_vault(record, shares) == SECRET


def test_fewer_than_k_rejected(vault):
    record, shares = vault
    with pytest.raises(cc.ShareError):
        cc.unlock_vault(record, shares[:2])


def test_shares_are_unique(vault):
    _, shares = vault
    assert len(set(shares)) == 5


def test_fresh_vaults_differ():
    r1, s1 = cc.create_vault(SECRET, 3, 5)
    r2, s2 = cc.create_vault(SECRET, 3, 5)
    assert r1["ciphertext"] != r2["ciphertext"]
    assert set(s1).isdisjoint(s2)


def test_duplicate_share_rejected(vault):
    record, shares = vault
    with pytest.raises(cc.ShareError):
        cc.unlock_vault(record, [shares[0], shares[0], shares[1]])


def test_typo_caught_by_checksum(vault):
    _, shares = vault
    s = shares[0]
    pos = len(s) - 3
    bad = s[:pos] + ("A" if s[pos] != "A" else "B") + s[pos + 1:]
    with pytest.raises(cc.ShareError):
        cc.decode_share(bad)


def test_tampered_share_rejected_by_commitment(vault):
    record, shares = vault
    idx, raw = cc.decode_share(shares[0])
    forged = cc.encode_share(idx, bytes([raw[0] ^ 1]) + raw[1:])  # valid checksum, wrong value
    with pytest.raises(cc.ShareError):
        cc.unlock_vault(record, [forged, shares[1], shares[2]])


def test_tampered_share_caught_by_gcm_when_commitments_off(vault):
    record, shares = vault
    idx, raw = cc.decode_share(shares[0])
    forged = cc.encode_share(idx, bytes([raw[0] ^ 1]) + raw[1:])
    with pytest.raises(cc.VaultError):
        cc.unlock_vault(record, [forged, shares[1], shares[2]], check_commitments=False)


def test_foreign_vault_share_rejected(vault):
    record, shares = vault
    _, other_shares = cc.create_vault(b"other", 3, 5)
    with pytest.raises(cc.ShareError):
        cc.unlock_vault(record, [other_shares[0], shares[1], shares[2]])


def test_ciphertext_tamper_detected(vault):
    record, shares = vault
    bad = copy.deepcopy(record)
    ct = bytearray(cc._b64d(bad["ciphertext"]))
    ct[0] ^= 1
    bad["ciphertext"] = cc._b64e(bytes(ct))
    with pytest.raises(cc.VaultError):
        cc.unlock_vault(bad, shares[:3])


def test_header_tamper_detected_by_aad(vault):
    record, shares = vault
    bad = copy.deepcopy(record)
    bad["n"] = 6
    with pytest.raises(cc.VaultError):
        cc.unlock_vault(bad, shares[:3])


def test_record_holds_no_secrets(vault):
    record, shares = vault
    blob = repr(record)
    for s in shares:
        assert s not in blob
    assert SECRET.decode() not in blob


@pytest.mark.parametrize("k,n", [(1, 5), (6, 5), (3, 300)])
def test_invalid_parameters(k, n):
    with pytest.raises(ValueError):
        cc.create_vault(SECRET, k, n)
