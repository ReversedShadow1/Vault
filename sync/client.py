"""
Client-side sync module. This is the code that runs on the user's
machine when they hit "Sync Now" — imports httpx (network), which is
exactly why this lives in sync/ and not core/ (spec §6 module boundary:
core vault code requires no network libraries to run).
"""

import time
import base64

import httpx

from core.crypto_config import SYNC_PARAMS
from core.crypto_engine import encrypt_entry, decrypt_entry, DecryptionError
from sync import pqc_crypto


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(data: str) -> bytes:
    return base64.b64decode(data)


class ServerAuthError(Exception):
    """Raised when server authentication fails, is required but absent,
    or the response is inconsistent — treat all of these as a potential
    MITM and abort. Never fall back to an unauthenticated handshake
    silently."""
    pass


class SyncError(Exception):
    pass


class SyncClient:
    """
    Usage:
        client = SyncClient(
            base_url="http://127.0.0.1:8420",
            vault_id="my-vault-uuid",
            api_key="...",   # from `python -m sync.manage_access register my-vault-uuid`
        )
        client.upload_backup(vault_blob_nonce, vault_blob_ciphertext)
        nonce, ciphertext = client.download_backup()

    `api_key` is REQUIRED and proves to the server that this client is
    allowed to push/pull backups for `vault_id` at all — this is
    independent of, and in addition to, the PQC handshake's job of
    proving the two parties agree on a session key. Get one by running
    `python -m sync.manage_access register <vault_id>` against the
    server's storage directory and copying the printed key here.

    `pinned_server_sig_pub` is optional: if provided, the server's
    signature is verified against this specific key (SSH-host-key-style
    pinning) rather than trusting whatever key the server presents.
    Leave None to trust-on-first-use (and the caller should persist
    whatever key comes back the first time).

    `require_server_auth` controls what happens if a handshake response
    contains no signature at all. It defaults to True: SECURITY-CRITICAL
    behavior in this client is controlled by the caller's own
    configuration, never inferred from whatever the (possibly tampered)
    server response happens to contain. An active network attacker who
    strips the signature fields from a response cannot use that to
    disable authentication — the client still expects one and aborts.

    Only set require_server_auth=False if you are deliberately connecting
    to a server that has authentication disabled (e.g. local development
    with SyncServer(enable_server_auth=False)) and understand that the
    connection then has no defense against an active MITM.
    """

    def __init__(self, base_url: str, vault_id: str, api_key: str,
                 pinned_server_sig_pub: bytes | None = None,
                 http_client: httpx.Client | None = None,
                 require_server_auth: bool = True):
        if not api_key:
            raise ValueError(
                "api_key is required — register this vault_id on the "
                "server with `python -m sync.manage_access register "
                "<vault_id>` and pass the printed key here."
            )
        self.base_url = base_url.rstrip("/")
        self.vault_id = vault_id
        self.api_key = api_key
        self.pinned_server_sig_pub = pinned_server_sig_pub
        self._http = http_client or httpx.Client(base_url=self.base_url, timeout=10.0)
        self.last_seen_server_sig_pub: bytes | None = None

        if pinned_server_sig_pub is not None and not require_server_auth:
            # A pinned key only makes sense if authentication is required;
            # allowing this combination would let a caller accidentally
            # configure pinning that's silently never enforced.
            raise ValueError(
                "pinned_server_sig_pub was provided but require_server_auth=False — "
                "these are contradictory. A pinned key implies authentication is "
                "required. Refusing to construct an inconsistent client."
            )
        self.require_server_auth = require_server_auth

    def _handshake(self) -> bytes:
        """Runs handshake/init + handshake/complete, returns the
        derived session_key. Raises ServerAuthError if signature
        verification fails or is required-but-absent, SyncError for
        protocol-level failures (including a rejected/invalid api_key,
        which the server reports as a 403)."""
        now = time.time()
        init_resp = self._http.post("/handshake/init", json={
            "vault_id": self.vault_id,
            "api_key": self.api_key,
            "client_timestamp": now,
        })
        if init_resp.status_code == 403:
            raise SyncError(
                "handshake/init rejected: unknown vault_id or invalid api_key. "
                "Check that this vault_id was registered on the server "
                "(`python -m sync.manage_access register <vault_id>`) and "
                "that api_key matches what was printed."
            )
        if init_resp.status_code != 200:
            raise SyncError(f"handshake/init failed: {init_resp.status_code} {init_resp.text}")
        data = init_resp.json()

        session_id = unb64(data["session_id"])
        server_x25519_pub = unb64(data["server_x25519_pub"])
        server_kem_pub = unb64(data["server_kem_pub"])
        server_timestamp = data["server_timestamp"]

        if abs(time.time() - server_timestamp) > SYNC_PARAMS.clock_skew_tolerance_seconds:
            raise SyncError("Server timestamp outside acceptable clock skew.")

        # Whether authentication happens is decided by THIS client's own
        # configuration (self.require_server_auth), never purely by
        # whether the response happens to contain a signature. An
        # attacker who deletes the signature/server_sig_pub fields in
        # transit cannot use that to silently disable verification —
        # a client configured to require auth will abort instead.
        signature_b64 = data.get("signature")
        server_sig_pub_b64 = data.get("server_sig_pub")

        if bool(signature_b64) != bool(server_sig_pub_b64):
            # Partial presence is itself a tamper signal — a well-formed
            # response from an auth-enabled server always sends both, and
            # one from an auth-disabled server sends neither.
            raise ServerAuthError(
                "Handshake response has a signature without a signing key "
                "(or vice versa) — malformed or tampered response. Aborting."
            )

        server_authenticated = bool(signature_b64)

        if self.require_server_auth and not server_authenticated:
            raise ServerAuthError(
                "Server authentication is required (require_server_auth=True) "
                "but this handshake response contains no signature. Either the "
                "server has authentication disabled, or an attacker stripped "
                "the signature fields in transit. Aborting rather than "
                "silently proceeding unauthenticated."
            )

        if server_authenticated:
            signature = unb64(signature_b64)
            server_sig_pub = unb64(server_sig_pub_b64)
            transcript = session_id + server_x25519_pub + server_kem_pub + str(server_timestamp).encode()

            if self.pinned_server_sig_pub and server_sig_pub != self.pinned_server_sig_pub:
                raise ServerAuthError(
                    "Server presented a DIFFERENT signing key than the pinned one — "
                    "possible MITM or server was re-provisioned. Aborting."
                )
            verify_against = self.pinned_server_sig_pub or server_sig_pub
            if not pqc_crypto.verify(verify_against, transcript, signature):
                raise ServerAuthError("Server handshake signature failed verification. Aborting.")
            self.last_seen_server_sig_pub = server_sig_pub
        # else: server_authenticated is False and require_server_auth is
        # False too — caller has explicitly opted into an unauthenticated
        # handshake (e.g. talking to a dev server with auth disabled).

        client_x25519_priv, client_x25519_pub = pqc_crypto.generate_x25519_keypair()
        kem_ciphertext, kem_secret = pqc_crypto.kem_encapsulate(server_kem_pub)
        x25519_secret = pqc_crypto.x25519_shared_secret(client_x25519_priv, server_x25519_pub)
        session_key = pqc_crypto.derive_session_key(x25519_secret, kem_secret, session_id)

        complete_resp = self._http.post("/handshake/complete", json={
            "session_id": data["session_id"],
            "client_x25519_pub": b64(client_x25519_pub),
            "kem_ciphertext": b64(kem_ciphertext),
            "client_timestamp": time.time(),
        })
        if complete_resp.status_code != 200:
            raise SyncError(f"handshake/complete failed: {complete_resp.status_code} {complete_resp.text}")

        self._last_session_id = data["session_id"]
        return session_key

    def upload_backup(self, vault_nonce: bytes, vault_ciphertext: bytes) -> None:
        """
        vault_nonce/vault_ciphertext: the vault's OWN storage-layer
        ciphertext (e.g. the whole SQLite file's relevant bytes, or a
        serialized bundle) — already fully opaque under the vault key.
        This method wraps it once more under a fresh session key for
        the network hop.
        """
        session_key = self._handshake()

        if len(vault_nonce) > 255:
            raise SyncError("nonce too long for length-prefix framing")
        inner_blob = bytes([len(vault_nonce)]) + vault_nonce + vault_ciphertext
        outer_nonce, outer_ciphertext = encrypt_entry(inner_blob, session_key)

        resp = self._http.post("/sync/upload", json={
            "session_id": self._last_session_id,
            "nonce": b64(outer_nonce),
            "ciphertext": b64(outer_ciphertext),
        })
        if resp.status_code != 200:
            raise SyncError(f"upload failed: {resp.status_code} {resp.text}")

    def download_backup(self) -> tuple[bytes, bytes]:
        """Returns (vault_nonce, vault_ciphertext) — the vault's own
        ciphertext, unwrapped from this session's transport layer."""
        session_key = self._handshake()

        resp = self._http.get("/sync/download", params={"session_id": self._last_session_id})
        if resp.status_code != 200:
            raise SyncError(f"download failed: {resp.status_code} {resp.text}")
        data = resp.json()

        outer_nonce = unb64(data["nonce"])
        outer_ciphertext = unb64(data["ciphertext"])
        try:
            inner_blob = decrypt_entry(outer_nonce, outer_ciphertext, session_key)
        except DecryptionError:
            raise SyncError("Transport decryption failed on download — corrupted or tampered response.")

        inner_nonce_len = inner_blob[0]
        inner_nonce = inner_blob[1:1 + inner_nonce_len]
        inner_ciphertext = inner_blob[1 + inner_nonce_len:]
        return inner_nonce, inner_ciphertext

    def close(self):
        self._http.close()