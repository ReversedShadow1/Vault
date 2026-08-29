"""
Edge-case tests for sync/ (spec Week 4). Run with:
LD_LIBRARY_PATH=/root/_oqs/lib pytest tests/test_sync_edge_cases.py -v
"""

import base64
import os
import time

import pytest
from fastapi.testclient import TestClient

from sync.server import SyncServer, build_app
from sync.blob_store import BlobStore
from sync.session_store import SessionStore, SessionStatus


@pytest.fixture
def server_and_client(tmp_path):
    """
    NOTE: access_store_path is now mandatory on SyncServer (per-vault
    authorization is no longer optional — see sync/server.py). Every
    test that hits /handshake/init for a given vault_id must register
    that vault_id first and send the resulting api_key, or it will get
    403'd before it ever reaches the behavior under test.
    """
    access_path = str(tmp_path / "vault_access.json")
    state = SyncServer(
        str(tmp_path / "storage"),
        enable_server_auth=True,
        access_store_path=access_path,
        # These tests exercise handshake/session/upload logic, not
        # transport-layer security itself — TestClient's reported client
        # host is "testclient" (not loopback), so without this every
        # request here would 400 at RequireSecureTransportMiddleware
        # before ever reaching a route handler.
        allow_insecure_transport=True,
        # test_oversized_upload_payload sends ~10MB of raw plaintext,
        # which after AES-GCM's tag + base64's ~33% inflation lands
        # around ~13.3MB of actual JSON body — bump the cap so that
        # test exercises "does the server handle a big payload", not
        # "does the default cap reject it".
        max_request_bytes=20 * 1024 * 1024,
    )
    app = build_app(state)
    client = TestClient(app, base_url="http://testserver")
    # Register through the SERVER's own VaultAccessStore instance
    # (state.access), not a second one opened separately on the same
    # file. VaultAccessStore loads its data into memory once at
    # construction and doesn't re-read from disk on verify() — a
    # second instance's register() would write the hash to disk but
    # leave the server's in-memory copy (the one handshake_init
    # actually checks) unaware of it, causing a spurious 403.
    return state, client, state.access


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def register(access, vault_id: str) -> str:
    """Helper: register a vault_id and return its api_key."""
    return access.register(vault_id)


# ---- malformed / garbage input ----

def test_handshake_init_missing_vault_id(server_and_client):
    _, client, _ = server_and_client
    resp = client.post("/handshake/init", json={"client_timestamp": time.time()})
    assert resp.status_code == 422  # pydantic validation error — vault_id missing entirely


def test_handshake_init_empty_vault_id(server_and_client):
    """Empty string is a valid str, so pydantic accepts it. As long as
    it's registered like any other vault_id, it should be treated the
    same as any other vault — accepted at handshake/init, since that
    step doesn't touch storage yet."""
    _, client, access = server_and_client
    api_key = register(access, "")
    resp = client.post(
        "/handshake/init",
        json={"vault_id": "", "api_key": api_key, "client_timestamp": time.time()},
    )
    assert resp.status_code == 200


def test_handshake_complete_with_garbage_base64(server_and_client):
    _, client, _ = server_and_client
    resp = client.post("/handshake/complete", json={
        "session_id": "not-valid-base64!!!",
        "client_x25519_pub": "also-not-base64!!!",
        "kem_ciphertext": "still-not-base64",
        "client_timestamp": time.time(),
    })
    # Should fail cleanly (400/422/500 all acceptable-ish, but must NOT
    # silently succeed or leak a stack trace with secrets).
    assert resp.status_code in (400, 422, 500)


def test_handshake_complete_with_wrong_length_keys(server_and_client):
    """Valid base64, but wrong-length X25519 key / KEM ciphertext —
    must fail cleanly, not crash the server process."""
    state, client, access = server_and_client
    api_key_v1 = register(access, "v1")
    init = client.post("/handshake/init", json={
        "vault_id": "v1", "api_key": api_key_v1, "client_timestamp": time.time(),
    })
    assert init.status_code == 200
    session_id = init.json()["session_id"]

    resp = client.post("/handshake/complete", json={
        "session_id": session_id,
        "client_x25519_pub": b64(b"too-short"),
        "kem_ciphertext": b64(b"also-too-short"),
        "client_timestamp": time.time(),
    })
    assert resp.status_code in (400, 422, 500)

    # Server must still be alive and responsive after a malformed request.
    api_key_v2 = register(access, "v2")
    health_check = client.post("/handshake/init", json={
        "vault_id": "v2", "api_key": api_key_v2, "client_timestamp": time.time(),
    })
    assert health_check.status_code == 200


def test_upload_without_handshake(server_and_client):
    """Straight-to-upload with a made-up session_id — no prior handshake at all."""
    _, client, _ = server_and_client
    resp = client.post("/sync/upload", json={
        "session_id": b64(os.urandom(16)),
        "nonce": b64(os.urandom(12)),
        "ciphertext": b64(b"garbage"),
    })
    assert resp.status_code == 409


def test_download_for_vault_with_no_backup(server_and_client):
    """Complete a real handshake but the vault_id has never uploaded anything."""
    _, client, access = server_and_client
    api_key = register(access, "never-uploaded")
    init = client.post("/handshake/init", json={
        "vault_id": "never-uploaded", "api_key": api_key, "client_timestamp": time.time(),
    })
    assert init.status_code == 200
    data = init.json()

    from sync import pqc_crypto
    session_id = base64.b64decode(data["session_id"])
    server_x25519_pub = base64.b64decode(data["server_x25519_pub"])
    server_kem_pub = base64.b64decode(data["server_kem_pub"])

    client_priv, client_pub = pqc_crypto.generate_x25519_keypair()
    kem_ct, kem_secret = pqc_crypto.kem_encapsulate(server_kem_pub)
    x_secret = pqc_crypto.x25519_shared_secret(client_priv, server_x25519_pub)
    pqc_crypto.derive_session_key(x_secret, kem_secret, session_id)

    complete = client.post("/handshake/complete", json={
        "session_id": data["session_id"],
        "client_x25519_pub": b64(client_pub),
        "kem_ciphertext": b64(kem_ct),
        "client_timestamp": time.time(),
    })
    assert complete.status_code == 200

    download = client.get("/sync/download", params={"session_id": data["session_id"]})
    assert download.status_code == 404


# ---- oversized payloads ----

def test_oversized_upload_payload(server_and_client):
    """A very large (10MB) ciphertext blob — must not crash the server,
    even if it's rejected or slow."""
    state, client, access = server_and_client
    api_key = register(access, "big-upload")
    init = client.post("/handshake/init", json={
        "vault_id": "big-upload", "api_key": api_key, "client_timestamp": time.time(),
    })
    assert init.status_code == 200
    data = init.json()

    from sync import pqc_crypto
    session_id = base64.b64decode(data["session_id"])
    server_x25519_pub = base64.b64decode(data["server_x25519_pub"])
    server_kem_pub = base64.b64decode(data["server_kem_pub"])
    client_priv, client_pub = pqc_crypto.generate_x25519_keypair()
    kem_ct, kem_secret = pqc_crypto.kem_encapsulate(server_kem_pub)
    x_secret = pqc_crypto.x25519_shared_secret(client_priv, server_x25519_pub)
    session_key = pqc_crypto.derive_session_key(x_secret, kem_secret, session_id)

    client.post("/handshake/complete", json={
        "session_id": data["session_id"],
        "client_x25519_pub": b64(client_pub),
        "kem_ciphertext": b64(kem_ct),
        "client_timestamp": time.time(),
    })

    from core.crypto_engine import encrypt_entry
    huge_inner = bytes([12]) + os.urandom(12) + os.urandom(10_000_000)  # 10MB
    outer_nonce, outer_ct = encrypt_entry(huge_inner, session_key)

    resp = client.post("/sync/upload", json={
        "session_id": data["session_id"],
        "nonce": b64(outer_nonce),
        "ciphertext": b64(outer_ct),
    })
    assert resp.status_code == 200

    # Server survives and responds to a fresh request afterward.
    api_key_2 = register(access, "after-big-upload")
    followup = client.post("/handshake/init", json={
        "vault_id": "after-big-upload", "api_key": api_key_2, "client_timestamp": time.time(),
    })
    assert followup.status_code == 200


# ---- path traversal / injection in vault_id ----

def test_blob_store_rejects_fully_unsafe_vault_id(tmp_path):
    """A vault_id containing only path-traversal/separator characters
    sanitizes down to nothing, and should be rejected outright rather
    than silently writing to some fallback location."""
    store = BlobStore(str(tmp_path))
    with pytest.raises(ValueError):
        store._path_for("../../")  # sanitizes to empty string


def test_blob_store_sanitizes_traversal_with_valid_chars_mixed(tmp_path):
    """A vault_id like '../evil' should sanitize down to just 'evil',
    NOT escape the storage directory."""
    store = BlobStore(str(tmp_path))
    path = store._path_for("../../evil")
    assert store.storage_dir in path.parents
    assert ".." not in str(path.relative_to(store.storage_dir))


def test_blob_store_vault_id_with_null_byte(tmp_path):
    store = BlobStore(str(tmp_path))
    # Null bytes aren't alnum/-/_' so they're stripped; must not raise
    # OSError from an embedded null in the filename.
    path = store._path_for("vault\x00id")
    store.store("vault\x00id", b"ct", b"nonce")
    assert path.exists()


# ---- session store boundary conditions ----

def test_session_store_expired_session_treated_as_gone():
    store = SessionStore()
    sid = os.urandom(16)
    session = store.create_pending(sid, b"priv", b"kemsecret", "vault1")
    session.expires_at = time.time() - 1  # force-expire
    assert store.get(sid) is None


def test_session_store_consume_before_establish_fails():
    store = SessionStore()
    sid = os.urandom(16)
    store.create_pending(sid, b"priv", b"kemsecret", "vault1")
    assert store.consume(sid) is None  # still PENDING, not ESTABLISHED


def test_session_store_double_establish_fails():
    store = SessionStore()
    sid = os.urandom(16)
    store.create_pending(sid, b"priv", b"kemsecret", "vault1")
    assert store.establish(sid, b"key1") is True
    assert store.establish(sid, b"key2") is False  # already established


def test_session_store_sweep_expired():
    store = SessionStore()
    sid1, sid2 = os.urandom(16), os.urandom(16)
    s1 = store.create_pending(sid1, b"p", b"k", "v1")
    store.create_pending(sid2, b"p", b"k", "v2")
    s1.expires_at = time.time() - 1
    swept = store.sweep_expired()
    assert swept == 1