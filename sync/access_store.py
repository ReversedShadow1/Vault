"""
Per-vault access control for the sync server.

Fix for "no authentication or authorization on the sync server
independent of the crypto handshake": completing the PQC handshake only
proves the two parties agree on a session key — it says nothing about
whether the calling client is actually allowed to push or pull a given
vault's backup blob. Before this module, any client that could reach the
server and complete a handshake could upload or download ANY vault_id.

Model: each vault_id must be explicitly registered on the server with a
high-entropy API key (see manage_access.py). The client presents that
key on /handshake/init. Unknown vault_ids are rejected outright — there
is deliberately NO auto-registration-on-first-use here. That's a
different trust model than the TOFU key pinning used for the server's
signing key (sync/client.py): TOFU defends against a passive attacker on
the first connection, but auto-registering an ACCESS GRANT on first
contact would let any attacker who reaches the server first simply claim
an arbitrary vault_id and lock the real owner out. Registration has to
be an explicit, out-of-band operator action.

API keys are stored as SHA-256 hashes, not in the clear, so a leak of
the access-store file alone does not hand over usable keys. Comparison
is constant-time (hmac.compare_digest) to avoid a timing side-channel,
and a lookup miss still performs a dummy comparison so the response time
doesn't itself reveal which vault_ids are registered.

Registration is normally done via manage_access.py, run as a SEPARATE
process from the running server — the same operational pattern as
appending a line to SSH's authorized_keys without restarting sshd. For
that to actually work, this store re-checks the file's modification time
on every lookup and reloads if it changed on disk, rather than trusting
whatever was loaded once at server startup.
"""

import hashlib
import hmac
import json
import os
import secrets
import threading

from core.file_permissions import check_owner_only_or_raise, enforce_owner_only


def _hash_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


class VaultAccessStore:
    """Thread-safe, file-backed store of vault_id -> hashed API key."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._data: dict[str, str] = {}
        self._mtime: float | None = None
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.path):
            self._data = {}
            self._mtime = None
            return

        # Raises only if this file is actually exposed AND the
        # filesystem is capable of enforcing tighter permissions in the
        # first place — see core/file_permissions.py for why that
        # second condition matters (e.g. WSL DrvFs mounts, FAT/exFAT).
        check_owner_only_or_raise(self.path, "Vault access store")

        with open(self.path, "r") as f:
            self._data = json.load(f)
        self._mtime = os.stat(self.path).st_mtime

    def _reload_if_changed(self) -> None:
        """
        Registrations and revocations are normally performed by running
        manage_access.py as a separate, short-lived process while the
        server keeps running. Without this check, the server's in-memory
        copy would only ever reflect whatever was on disk at process
        startup, and a fresh registration would silently have no effect
        until the server was restarted — which is exactly the failure
        mode this method exists to prevent. Must be called with
        self._lock already held.
        """
        try:
            current_mtime = os.stat(self.path).st_mtime
        except FileNotFoundError:
            current_mtime = None
        if current_mtime != self._mtime:
            self._load()

    def is_registered(self, vault_id: str) -> bool:
        with self._lock:
            self._reload_if_changed()
            return vault_id in self._data

    def register(self, vault_id: str, api_key: str | None = None, overwrite: bool = False) -> str:
        """
        Registers vault_id with a (newly generated, if not supplied)
        high-entropy API key and returns the PLAINTEXT key — this is the
        only moment it's ever available; only its hash is persisted.

        Raises if vault_id is already registered and overwrite=False, so
        a script or operator can't accidentally clobber (and silently
        invalidate) an existing client's key.
        """
        with self._lock:
            self._reload_if_changed()
            if vault_id in self._data and not overwrite:
                raise ValueError(
                    f"vault_id {vault_id!r} is already registered. Pass "
                    f"overwrite=True to intentionally rotate its key — "
                    f"this immediately invalidates the old one."
                )
            key = api_key or secrets.token_urlsafe(32)
            self._data[vault_id] = _hash_key(key)
            self._save()
            return key

    def revoke(self, vault_id: str) -> bool:
        with self._lock:
            self._reload_if_changed()
            if vault_id not in self._data:
                return False
            del self._data[vault_id]
            self._save()
            return True

    def verify(self, vault_id: str, api_key: str) -> bool:
        with self._lock:
            self._reload_if_changed()
            stored_hash = self._data.get(vault_id)
        if stored_hash is None:
            # Still hash the supplied key and do a dummy constant-time
            # compare so an unregistered vault_id takes roughly the same
            # time to reject as a registered one with a wrong key —
            # otherwise the response time itself would leak which
            # vault_ids exist on this server.
            hmac.compare_digest(_hash_key(api_key), _hash_key(""))
            return False
        return hmac.compare_digest(_hash_key(api_key), stored_hash)

    def _save(self) -> None:
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(self._data, f)
        enforce_owner_only(self.path)
        # Record the mtime WE just produced, so the next lookup in this
        # same process doesn't immediately re-read the file it just wrote.
        self._mtime = os.stat(self.path).st_mtime