"""
Edge-case tests for core/ (spec Week 4: "empty fields, oversized inputs,
malformed entries"). Run with: pytest tests/test_core_edge_cases.py -v
"""

import os
import pytest

from core.vault import (
    Vault, Entry, WeakPasswordError, WrongPasswordError, VaultLockedError,
)
from core.crypto_engine import encrypt_entry, decrypt_entry, DecryptionError, zero_bytes
from core.kdf import derive_vault_key, generate_salt
from core.storage import VaultStorage
from core.crypto_config import AESGCM_PARAMS


VALID_PW = "Edge-Case-Test-Pass-42!"


@pytest.fixture
def vault(tmp_path):
    v = Vault(str(tmp_path / "vault.db"))
    v.create(VALID_PW)
    yield v
    v.close()


# ---- empty fields ----

def test_entry_with_empty_username_and_notes(vault):
    """Username/notes are optional in practice — only site matters for lookups."""
    eid = vault.add_entry(Entry(site="s.com", username="", password="p", notes=""))
    e = vault.get_entry(eid)
    assert e.username == ""
    assert e.notes == ""


def test_entry_with_empty_site(vault):
    """core.Vault itself doesn't enforce non-empty site — that's a GUI-layer
    validation (gui/main_window.py checks this before calling add_entry).
    Confirms the core layer doesn't silently corrupt data either way."""
    eid = vault.add_entry(Entry(site="", username="u", password="p"))
    e = vault.get_entry(eid)
    assert e.site == ""


def test_entry_with_empty_password(vault):
    """An empty password is a bad practice but not something the crypto
    layer should choke on — AES-GCM happily encrypts zero-length plaintext."""
    eid = vault.add_entry(Entry(site="s.com", username="u", password=""))
    e = vault.get_entry(eid)
    assert e.password == ""


def test_create_with_empty_master_password(tmp_path):
    v = Vault(str(tmp_path / "v.db"))
    with pytest.raises(WeakPasswordError):
        v.create("")


def test_master_password_exactly_at_length_boundary(tmp_path):
    """Boundary test: exactly min_length (12) chars, still needs to pass
    zxcvbn strength too, so use a genuinely non-guessable 12-char string."""
    v = Vault(str(tmp_path / "v.db"))
    boundary_pw = "Xk9#mQ2!vLp8"  # 12 chars, high entropy
    assert len(boundary_pw) == 12
    v.create(boundary_pw)  # should not raise
    assert v.is_unlocked


def test_master_password_one_under_boundary(tmp_path):
    v = Vault(str(tmp_path / "v.db"))
    with pytest.raises(WeakPasswordError):
        v.create("Xk9#mQ2!vLp")  # 11 chars


# ---- oversized inputs ----

def test_oversized_password_field(vault):
    """A 1MB password — unusual, but must round-trip correctly, not
    silently truncate or crash."""
    huge_password = "P@ssw0rd-" * 120_000  # ~1.08 MB
    eid = vault.add_entry(Entry(site="big.com", username="u", password=huge_password))
    e = vault.get_entry(eid)
    assert e.password == huge_password


def test_oversized_notes_field(vault):
    huge_notes = "x" * 5_000_000  # 5 MB
    eid = vault.add_entry(Entry(site="s.com", username="u", password="p", notes=huge_notes))
    e = vault.get_entry(eid)
    assert e.notes == huge_notes


def test_unicode_and_special_characters(vault):
    """Emoji, CJK, RTL text, null-adjacent characters — must not break
    JSON encoding or AES-GCM."""
    tricky = "パスワード🔒 <script>alert(1)</script> \u200b\u0000-ish ' OR 1=1 --"
    eid = vault.add_entry(Entry(site="tricky.com", username=tricky, password=tricky, notes=tricky))
    e = vault.get_entry(eid)
    assert e.username == tricky
    assert e.password == tricky
    assert e.notes == tricky


def test_sql_injection_style_input_is_inert(vault):
    """Storage layer uses parameterized queries — a SQL-injection-shaped
    string is just a string, and multiple entries must be unaffected."""
    injection = "'; DROP TABLE entries; --"
    vault.add_entry(Entry(site=injection, username="u", password="p"))
    vault.add_entry(Entry(site="normal.com", username="u2", password="p2"))
    entries = vault.list_entries()
    assert len(entries) == 2  # table wasn't dropped, both entries survive


# ---- malformed entries / tampering ----

def test_get_nonexistent_entry_raises_keyerror(vault):
    with pytest.raises(KeyError):
        vault.get_entry(99999)


def test_update_nonexistent_entry_raises_keyerror(vault):
    with pytest.raises(KeyError):
        vault.update_entry(99999, Entry(site="s", username="u", password="p"))


def test_delete_nonexistent_entry_raises_keyerror(vault):
    with pytest.raises(KeyError):
        vault.delete_entry(99999)


def test_tampered_ciphertext_is_detected(vault):
    """Directly corrupt one byte of stored ciphertext — must raise
    DecryptionError, not return garbage or crash uncontrolled."""
    eid = vault.add_entry(Entry(site="s.com", username="u", password="p"))
    row = vault.storage.get_entry(eid)
    _id, nonce, ciphertext = row
    corrupted = bytearray(ciphertext)
    corrupted[0] ^= 0xFF
    vault.storage.update_entry(eid, nonce, bytes(corrupted))

    with pytest.raises(DecryptionError):
        vault.get_entry(eid)


def test_tampered_nonce_is_detected(vault):
    eid = vault.add_entry(Entry(site="s.com", username="u", password="p"))
    row = vault.storage.get_entry(eid)
    _id, nonce, ciphertext = row
    corrupted_nonce = bytearray(nonce)
    corrupted_nonce[0] ^= 0xFF
    vault.storage.update_entry(eid, bytes(corrupted_nonce), ciphertext)

    with pytest.raises(DecryptionError):
        vault.get_entry(eid)


def test_wrong_nonce_length_raises_valueerror():
    key = os.urandom(AESGCM_PARAMS.key_len)
    wrong_nonce = os.urandom(4)  # should be 12
    with pytest.raises(ValueError):
        decrypt_entry(wrong_nonce, b"whatever", key)


def test_wrong_key_length_raises_valueerror():
    with pytest.raises(ValueError):
        encrypt_entry(b"data", os.urandom(16))  # should be 32


def test_operations_on_locked_vault_raise(vault):
    vault.lock()
    with pytest.raises(VaultLockedError):
        vault.list_entries()
    with pytest.raises(VaultLockedError):
        vault.add_entry(Entry(site="s", username="u", password="p"))


def test_double_create_raises(tmp_path):
    path = str(tmp_path / "v.db")
    v1 = Vault(path)
    v1.create(VALID_PW)
    v2 = Vault(path)
    with pytest.raises(RuntimeError):
        v2.create(VALID_PW)


def test_unlock_before_create_raises(tmp_path):
    v = Vault(str(tmp_path / "v.db"))
    with pytest.raises(RuntimeError):
        v.unlock(VALID_PW)


def test_zero_bytes_actually_zeroes():
    buf = bytearray(b"secret-data-1234")
    zero_bytes(buf)
    assert buf == bytearray(len(buf))


def test_salt_reuse_produces_same_key_deterministic():
    """Same password + salt must always derive the same key — required
    for unlock to work across process restarts."""
    salt = generate_salt()
    k1 = derive_vault_key(VALID_PW, salt)
    k2 = derive_vault_key(VALID_PW, salt)
    assert k1 == k2


def test_different_salt_produces_different_key():
    s1, s2 = generate_salt(), generate_salt()
    assert s1 != s2  # astronomically unlikely to collide
    k1 = derive_vault_key(VALID_PW, s1)
    k2 = derive_vault_key(VALID_PW, s2)
    assert k1 != k2
