"""
Local storage layer. SQLite file holds ONLY:
  - vault metadata (salt, crypto_config_version) in plaintext (not secret)
  - per-entry: id, nonce, ciphertext (AES-GCM blob) — never plaintext

No network libraries are imported anywhere in this module or its
importers, satisfying spec §6 "core vault code should require no network
libraries to run."
"""

import os
import sqlite3
import time
from pathlib import Path

from core.crypto_config import CRYPTO_CONFIG_VERSION

SCHEMA = """
CREATE TABLE IF NOT EXISTS vault_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),  -- singleton row
    salt BLOB NOT NULL,
    crypto_config_version INTEGER NOT NULL,
    created_at REAL NOT NULL,
    verifier_nonce BLOB NOT NULL,
    verifier_ciphertext BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nonce BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
"""


class VaultStorage:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        self._tighten_file_permissions()

    def _tighten_file_permissions(self) -> None:
        """
        Fix for a gap raised by external review: nothing previously
        ensured vault.db itself was only readable by its owner on disk
        — it inherited whatever the process's umask happened to
        produce at creation time. Force owner-only (0600) permissions
        every time the storage layer opens the file, not just at
        creation, so a vault created under a looser umask (or copied in
        from somewhere else) gets tightened automatically too.

        Best-effort: wrapped in try/except because some platforms/
        filesystems (Windows, FAT-family filesystems) don't support
        POSIX permission bits the same way, and a failure here shouldn't
        prevent the vault from opening — consistent with this project's
        existing best-effort memory-hygiene posture
        (core/vault.py's use of zero_bytes).
        """
        try:
            os.chmod(self.db_path, 0o600)
        except OSError:
            pass

    # ---- vault lifecycle ----

    def is_initialized(self) -> bool:
        row = self._conn.execute("SELECT 1 FROM vault_meta WHERE id = 1").fetchone()
        return row is not None

    def init_vault(self, salt: bytes, verifier_nonce: bytes, verifier_ciphertext: bytes) -> None:
        if self.is_initialized():
            raise RuntimeError("Vault already initialized at this path.")
        self._conn.execute(
            "INSERT INTO vault_meta "
            "(id, salt, crypto_config_version, created_at, verifier_nonce, verifier_ciphertext) "
            "VALUES (1, ?, ?, ?, ?, ?)",
            (salt, CRYPTO_CONFIG_VERSION, time.time(), verifier_nonce, verifier_ciphertext),
        )
        self._conn.commit()
        self._tighten_file_permissions()

    def get_salt(self) -> bytes:
        row = self._conn.execute("SELECT salt FROM vault_meta WHERE id = 1").fetchone()
        if row is None:
            raise RuntimeError("Vault not initialized.")
        return row[0]

    def get_crypto_version(self) -> int:
        """
        The crypto_config_version that was current when THIS vault was
        created. Callers deriving the vault key must look up the Argon2
        params for this specific version (core.kdf.get_argon2_params) —
        never assume it matches the software's current default. This is
        the fix for the crypto-agility versioning gap: the field was
        previously written at creation time but never read back.
        """
        row = self._conn.execute(
            "SELECT crypto_config_version FROM vault_meta WHERE id = 1"
        ).fetchone()
        if row is None:
            raise RuntimeError("Vault not initialized.")
        return row[0]

    def get_verifier(self) -> tuple[bytes, bytes]:
        """Returns (nonce, ciphertext) of the password-verification canary,
        independent of whether any real entries exist yet."""
        row = self._conn.execute(
            "SELECT verifier_nonce, verifier_ciphertext FROM vault_meta WHERE id = 1"
        ).fetchone()
        if row is None:
            raise RuntimeError("Vault not initialized.")
        return row[0], row[1]

    def set_verifier_and_version(self, verifier_nonce: bytes, verifier_ciphertext: bytes,
                                  crypto_config_version: int) -> None:
        """
        Used only by the crypto-parameter migration path
        (core.vault.Vault.rekey_to_current_params). Updates the stored
        verifier canary and version in place.

        Does NOT touch the salt — Argon2's salt doesn't need to change
        just because the cost parameters did — and does NOT touch any
        entry rows; the caller is responsible for re-encrypting every
        entry under the new key BEFORE calling this, so that a crash
        mid-migration leaves the vault fully openable under the OLD
        version rather than half-migrated and unreadable.
        """
        if not self.is_initialized():
            raise RuntimeError("Vault not initialized.")
        self._conn.execute(
            "UPDATE vault_meta SET verifier_nonce = ?, verifier_ciphertext = ?, "
            "crypto_config_version = ? WHERE id = 1",
            (verifier_nonce, verifier_ciphertext, crypto_config_version),
        )
        self._conn.commit()

    # ---- entry CRUD (storage layer only knows about opaque ciphertext) ----

    def add_entry(self, nonce: bytes, ciphertext: bytes) -> int:
        now = time.time()
        cur = self._conn.execute(
            "INSERT INTO entries (nonce, ciphertext, created_at, updated_at) "
            "VALUES (?, ?, ?, ?)",
            (nonce, ciphertext, now, now),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_entry(self, entry_id: int):
        row = self._conn.execute(
            "SELECT id, nonce, ciphertext FROM entries WHERE id = ?", (entry_id,)
        ).fetchone()
        return row  # None if not found

    def list_entries(self):
        return self._conn.execute(
            "SELECT id, nonce, ciphertext FROM entries ORDER BY id"
        ).fetchall()

    def update_entry(self, entry_id: int, nonce: bytes, ciphertext: bytes) -> bool:
        cur = self._conn.execute(
            "UPDATE entries SET nonce = ?, ciphertext = ?, updated_at = ? WHERE id = ?",
            (nonce, ciphertext, time.time(), entry_id),
        )
        self._conn.commit()
        return cur.rowcount > 0

    def delete_entry(self, entry_id: int) -> bool:
        cur = self._conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
        self._conn.commit()
        return cur.rowcount > 0

    def close(self):
        self._conn.close()