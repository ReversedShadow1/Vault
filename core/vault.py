"""
Vault manager — the public API the GUI/CLI talks to.

Owns the in-memory vault key for the duration of an unlocked session and
nothing else. No network imports here (spec §6 module boundary).
"""

import json
import time
from dataclasses import dataclass, field

from zxcvbn import zxcvbn

from core.crypto_config import PASSWORD_POLICY, ARGON2_PARAMS, CRYPTO_CONFIG_VERSION
from core.kdf import derive_vault_key, generate_salt, get_argon2_params
from core.crypto_engine import encrypt_entry, decrypt_entry, zero_bytes, DecryptionError
from core.storage import VaultStorage


class WeakPasswordError(Exception):
    pass


class VaultLockedError(Exception):
    pass


class WrongPasswordError(Exception):
    pass


# Fixed known-plaintext used only to verify the master password on unlock.
# Encrypted under the vault key at creation time and stored alongside the
# salt, independent of whether the vault has any real entries yet — this
# is what lets unlock() detect a wrong password even on a brand-new,
# empty vault, rather than only on the next successful/failed entry read.
_VERIFIER_PLAINTEXT = b"pq-vault-verifier-v1"


@dataclass
class Entry:
    site: str
    username: str
    password: str
    notes: str = ""
    entry_id: int | None = None


def check_master_password_strength(password: str, user_inputs: list[str] | None = None) -> None:
    """Raises WeakPasswordError if the password doesn't meet policy (spec 5.1)."""
    if len(password) < PASSWORD_POLICY.min_length:
        raise WeakPasswordError(
            f"Master password must be at least {PASSWORD_POLICY.min_length} characters."
        )
    result = zxcvbn(password, user_inputs=user_inputs or [])
    if result["score"] < PASSWORD_POLICY.min_zxcvbn_score:
        feedback = result.get("feedback", {})
        warning = feedback.get("warning") or "Password is too weak/guessable."
        raise WeakPasswordError(f"{warning} (zxcvbn score {result['score']}/4)")


class Vault:
    """
    Represents one open (or openable) vault backed by a single SQLite file.

    Usage:
        vault = Vault(db_path)
        vault.create(master_password)      # first time only
        vault.unlock(master_password)      # subsequent opens
        ... vault.add_entry(...), vault.list_entries(), ...
        vault.lock()
    """

    def __init__(self, db_path: str):
        self.storage = VaultStorage(db_path)
        self._vault_key: bytes | None = None
        self.last_activity: float = time.time()

    # ---- lifecycle ----

    def create(self, master_password: str) -> None:
        if self.storage.is_initialized():
            raise RuntimeError("Vault already exists at this path — use unlock() instead.")
        check_master_password_strength(master_password)
        salt = generate_salt(ARGON2_PARAMS)
        # New vaults always use the CURRENT parameter set — storage.init_vault
        # records CRYPTO_CONFIG_VERSION alongside it so a future unlock knows
        # exactly which params to use, even after ARGON2_PARAMS_BY_VERSION
        # gains newer entries.
        vault_key = derive_vault_key(master_password, salt, ARGON2_PARAMS)
        verifier_nonce, verifier_ciphertext = encrypt_entry(_VERIFIER_PLAINTEXT, vault_key)
        self.storage.init_vault(salt, verifier_nonce, verifier_ciphertext)
        self._vault_key = vault_key
        self._touch()

    def unlock(self, master_password: str) -> None:
        if not self.storage.is_initialized():
            raise RuntimeError("No vault found at this path — use create() instead.")
        salt = self.storage.get_salt()

        # CRYPTO-AGILITY FIX: derive using the Argon2 params that were
        # current for THIS vault's own stored version — never whatever
        # ARGON2_PARAMS currently resolves to. Previously this always used
        # the live default, so bumping ARGON2_PARAMS_BY_VERSION's latest
        # entry would silently make every existing vault unopenable
        # (verifier mismatch, indistinguishable from a wrong password).
        stored_version = self.storage.get_crypto_version()
        params = get_argon2_params(stored_version)
        candidate_key = derive_vault_key(master_password, salt, params)

        # Verify against the stored canary, not against real entries —
        # this works correctly even on a vault with zero entries.
        verifier_nonce, verifier_ciphertext = self.storage.get_verifier()
        try:
            plaintext = decrypt_entry(verifier_nonce, verifier_ciphertext, candidate_key)
            if plaintext != _VERIFIER_PLAINTEXT:
                raise WrongPasswordError("Incorrect master password.")
        except DecryptionError:
            raise WrongPasswordError("Incorrect master password.")

        self._vault_key = candidate_key
        self._touch()

    def lock(self) -> None:
        if self._vault_key is not None:
            key_buf = bytearray(self._vault_key)
            zero_bytes(key_buf)
            self._vault_key = None

    @property
    def is_unlocked(self) -> bool:
        return self._vault_key is not None

    def needs_crypto_migration(self) -> bool:
        """
        True if this vault was created under an older crypto_config_version
        than the one this software currently uses for new vaults. Doesn't
        change anything by itself — call rekey_to_current_params() (while
        unlocked) to actually migrate. Safe to call whether or not the
        vault is currently unlocked.
        """
        return self.storage.get_crypto_version() != CRYPTO_CONFIG_VERSION

    def rekey_to_current_params(self, master_password: str) -> None:
        """
        Re-derives the vault key under the CURRENT crypto_config_version's
        Argon2id parameters, and re-encrypts the verifier canary and every
        entry under the new key. This is the migration path for the
        crypto-agility versioning gap: without it, once ARGON2_PARAMS_BY_VERSION
        gains a newer entry, existing vaults would remain readable under
        their original parameters forever but never get to benefit from
        the stronger ones.

        Requires the vault to already be unlocked, AND the master password
        to be supplied again — this method independently re-derives the
        key from (password, salt, stored version's params) and checks it
        matches the currently-cached key, rather than trusting that
        self._vault_key was reached via a verified unlock() call. This
        guards against a caller invoking this by mistake on a vault that
        was unlocked some other way.

        Order of operations matters: every entry is re-encrypted and
        written under the new key BEFORE the stored verifier/version is
        updated, so a crash or power loss mid-migration leaves the vault
        fully openable under its OLD version rather than half-migrated
        and unreadable under either.
        """
        if self._vault_key is None:
            raise VaultLockedError("Vault must be unlocked before migrating.")

        salt = self.storage.get_salt()
        stored_version = self.storage.get_crypto_version()
        old_params = get_argon2_params(stored_version)
        check_key = derive_vault_key(master_password, salt, old_params)
        if check_key != self._vault_key:
            raise WrongPasswordError(
                "Master password does not match the currently unlocked vault."
            )

        if stored_version == CRYPTO_CONFIG_VERSION:
            return  # Already current — nothing to migrate.

        new_key = derive_vault_key(master_password, salt, ARGON2_PARAMS)

        # Re-encrypt every entry under the new key first. Keep the results
        # in memory until all of them succeed, then write them all —
        # avoids leaving some entries under the old key and some under the
        # new one if decryption of a later entry unexpectedly fails.
        re_encrypted = []
        for entry_id, nonce, ciphertext in self.storage.list_entries():
            plaintext = decrypt_entry(nonce, ciphertext, self._vault_key)
            new_nonce, new_ciphertext = encrypt_entry(plaintext, new_key)
            re_encrypted.append((entry_id, new_nonce, new_ciphertext))

        for entry_id, new_nonce, new_ciphertext in re_encrypted:
            self.storage.update_entry(entry_id, new_nonce, new_ciphertext)

        new_verifier_nonce, new_verifier_ciphertext = encrypt_entry(_VERIFIER_PLAINTEXT, new_key)
        self.storage.set_verifier_and_version(
            new_verifier_nonce, new_verifier_ciphertext, CRYPTO_CONFIG_VERSION
        )

        old_key_buf = bytearray(self._vault_key)
        zero_bytes(old_key_buf)
        self._vault_key = new_key
        self._touch()

    def _touch(self):
        self.last_activity = time.time()

    def _require_unlocked(self) -> bytes:
        if self._vault_key is None:
            raise VaultLockedError("Vault is locked. Call unlock() first.")
        self._touch()
        return self._vault_key

    def check_idle_timeout(self, timeout_seconds: int) -> bool:
        """Call periodically from the GUI event loop; auto-locks if idle too long."""
        if self.is_unlocked and (time.time() - self.last_activity) > timeout_seconds:
            self.lock()
            return True
        return False

    # ---- CRUD ----

    def add_entry(self, entry: Entry) -> int:
        key = self._require_unlocked()
        payload = json.dumps({
            "site": entry.site,
            "username": entry.username,
            "password": entry.password,
            "notes": entry.notes,
        }).encode("utf-8")
        nonce, ciphertext = encrypt_entry(payload, key)
        entry_id = self.storage.add_entry(nonce, ciphertext)
        return entry_id

    def get_entry(self, entry_id: int) -> Entry:
        key = self._require_unlocked()
        row = self.storage.get_entry(entry_id)
        if row is None:
            raise KeyError(f"No entry with id {entry_id}")
        _id, nonce, ciphertext = row
        plaintext = decrypt_entry(nonce, ciphertext, key)
        data = json.loads(plaintext.decode("utf-8"))
        return Entry(entry_id=_id, **data)

    def list_entries(self) -> list[Entry]:
        key = self._require_unlocked()
        results = []
        for _id, nonce, ciphertext in self.storage.list_entries():
            plaintext = decrypt_entry(nonce, ciphertext, key)
            data = json.loads(plaintext.decode("utf-8"))
            results.append(Entry(entry_id=_id, **data))
        return results

    def update_entry(self, entry_id: int, entry: Entry) -> None:
        key = self._require_unlocked()
        payload = json.dumps({
            "site": entry.site,
            "username": entry.username,
            "password": entry.password,
            "notes": entry.notes,
        }).encode("utf-8")
        nonce, ciphertext = encrypt_entry(payload, key)
        if not self.storage.update_entry(entry_id, nonce, ciphertext):
            raise KeyError(f"No entry with id {entry_id}")

    def delete_entry(self, entry_id: int) -> None:
        self._require_unlocked()
        if not self.storage.delete_entry(entry_id):
            raise KeyError(f"No entry with id {entry_id}")

    # ---- backup / sync support ----
    #
    # Sync is entirely optional and lives in sync/ (spec §5.2). This
    # method is the one piece of surface area core/ exposes for it: it
    # produces a single AES-256-GCM-wrapped blob of the whole vault
    # file, still under the vault key. sync/client.py wraps THIS blob
    # again under a fresh session key for the network hop — the vault
    # key itself never leaves this process.

    def export_backup_blob(self) -> tuple[bytes, bytes]:
        """Returns (nonce, ciphertext): the entire vault file, encrypted
        under the vault key. Useful as an opaque backup unit — smaller
        per-entry re-encryption isn't needed since entries are already
        individually encrypted; this just wraps the whole file once
        more so a stolen backup blob is unreadable without the vault key."""
        import pathlib
        key = self._require_unlocked()
        raw_bytes = pathlib.Path(self.storage.db_path).read_bytes()
        return encrypt_entry(raw_bytes, key)

    def restore_backup_blob(self, nonce: bytes, ciphertext: bytes, output_path: str) -> None:
        """Decrypts a backup blob (produced by export_backup_blob, under
        THIS vault's key) and writes the resulting vault file to
        output_path. Does not overwrite the currently-open vault file —
        the caller decides whether/how to swap it in, since this vault's
        SQLite connection may still be open against the original path."""
        import pathlib
        key = self._require_unlocked()
        try:
            raw_bytes = decrypt_entry(nonce, ciphertext, key)
        except DecryptionError:
            raise DecryptionError(
                "Backup blob could not be decrypted with this vault's key — "
                "wrong vault, wrong password, or corrupted backup."
            )
        pathlib.Path(output_path).write_bytes(raw_bytes)

    def close(self):
        self.lock()
        self.storage.close()