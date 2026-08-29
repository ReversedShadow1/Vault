"""
At-rest storage for uploaded vault backup blobs.

Stores exactly what it receives after unwrapping the transport layer:
the vault's own AES-256-GCM ciphertext (per-entry, under the vault key).
This module never has access to the vault key and cannot decrypt what
it stores — it only ever sees ciphertext, both in transit (session-key
wrapped) and at rest (vault-key-encrypted).

One file per vault_id. Simple filesystem storage is appropriate for a
"lightweight self-hosted service" (spec §3) — this isn't a multi-tenant
cloud product.
"""

import json
import base64
import time
from pathlib import Path


class BlobStore:
    def __init__(self, storage_dir: str):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def _path_for(self, vault_id: str) -> Path:
        # vault_id is client-supplied; don't trust it as a raw path component.
        safe_id = "".join(c for c in vault_id if c.isalnum() or c in "-_")
        if not safe_id:
            raise ValueError("vault_id must contain at least one alphanumeric character")
        return self.storage_dir / f"{safe_id}.blob.json"

    def store(self, vault_id: str, ciphertext: bytes, nonce: bytes) -> None:
        path = self._path_for(vault_id)
        payload = {
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "updated_at": time.time(),
        }
        path.write_text(json.dumps(payload))

    def retrieve(self, vault_id: str) -> tuple[bytes, bytes] | None:
        """Returns (nonce, ciphertext) of the stored vault blob, or None
        if nothing has been uploaded for this vault_id yet."""
        path = self._path_for(vault_id)
        if not path.exists():
            return None
        payload = json.loads(path.read_text())
        return (
            base64.b64decode(payload["nonce"]),
            base64.b64decode(payload["ciphertext"]),
        )

    def exists(self, vault_id: str) -> bool:
        return self._path_for(vault_id).exists()
