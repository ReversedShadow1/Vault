"""
Regression tests for the remediation pass documented in the final
report's "Honest Disclosure" section.

These are written to be dropped alongside tests/test_core_edge_cases.py
and tests/test_sync_edge_cases.py in the existing suite. They exist
specifically to close a process gap an external review pointed out: the
signature-stripping downgrade bug (fixed in sync/client.py) was found
by manual report-writing, not by the automated adversarial test suite —
even though "an adversary strips a field my security property depends
on" is exactly the kind of case a threat-model-driven suite should have
covered by construction. These tests make that scenario, and the other
fixes in the same remediation pass, explicit and permanent rather than
something that could regress silently.
"""

import os
import stat
import tempfile

import pytest
from fastapi.testclient import TestClient

from core.storage import VaultStorage
from sync.access_store import VaultAccessStore
from sync.client import SyncClient, ServerAuthError
from sync.server import SyncServer, build_app


# ---------------------------------------------------------------------
# Fix: signature-stripping downgrade attack (sync/client.py)
# ---------------------------------------------------------------------

def test_client_rejects_handshake_with_no_signature_by_default():
    """
    The exact case the external review said should have been in the
    suite from the start: a handshake response with no signature field
    at all (what an attacker stripping it in transit would produce, or
    equivalently a server with auth disabled) must be REJECTED by a
    default-constructed client, not silently accepted.
    """
    with tempfile.TemporaryDirectory() as tmp:
        access_path = os.path.join(tmp, "vault_access.json")
        access = VaultAccessStore(access_path)
        api_key = access.register("vault-1")

        server_state = SyncServer(
            storage_dir=tmp,
            enable_server_auth=False,  # server sends no signature at all
            access_store_path=access_path,
            allow_insecure_transport=True,  # keep this test focused on the auth fix
        )
        app = build_app(server_state)

        with TestClient(app) as test_client:
            client = SyncClient(
                base_url="http://testserver",
                vault_id="vault-1",
                api_key=api_key,
                http_client=test_client,
                # require_server_auth defaults to True — this is the point.
            )
            with pytest.raises(ServerAuthError):
                client._handshake()


def test_client_accepts_unauthenticated_handshake_only_when_explicitly_opted_in():
    """The same scenario as above succeeds ONLY when the caller
    explicitly passes require_server_auth=False — an intentional opt-in,
    not a default or an attacker-triggerable state."""
    with tempfile.TemporaryDirectory() as tmp:
        access_path = os.path.join(tmp, "vault_access.json")
        access = VaultAccessStore(access_path)
        api_key = access.register("vault-1")

        server_state = SyncServer(
            storage_dir=tmp,
            enable_server_auth=False,
            access_store_path=access_path,
            allow_insecure_transport=True,
        )
        app = build_app(server_state)

        with TestClient(app) as test_client:
            client = SyncClient(
                base_url="http://testserver",
                vault_id="vault-1",
                api_key=api_key,
                http_client=test_client,
                require_server_auth=False,
            )
            session_key = client._handshake()
            assert isinstance(session_key, (bytes, bytearray))
            assert len(session_key) == 32


# ---------------------------------------------------------------------
# Fix: no authentication/authorization on the sync server
# ---------------------------------------------------------------------

def test_server_rejects_unregistered_vault_id():
    with tempfile.TemporaryDirectory() as tmp:
        access_path = os.path.join(tmp, "vault_access.json")
        server_state = SyncServer(
            storage_dir=tmp,
            enable_server_auth=True,
            sig_key_path=os.path.join(tmp, "sig.json"),
            access_store_path=access_path,
            allow_insecure_transport=True,
        )
        app = build_app(server_state)

        with TestClient(app) as test_client:
            resp = test_client.post("/handshake/init", json={
                "vault_id": "never-registered",
                "api_key": "whatever",
                "client_timestamp": __import__("time").time(),
            })
            assert resp.status_code == 403


def test_server_rejects_wrong_api_key_for_registered_vault():
    with tempfile.TemporaryDirectory() as tmp:
        access_path = os.path.join(tmp, "vault_access.json")
        access = VaultAccessStore(access_path)
        access.register("vault-1", api_key="correct-key")

        server_state = SyncServer(
            storage_dir=tmp,
            enable_server_auth=True,
            sig_key_path=os.path.join(tmp, "sig.json"),
            access_store_path=access_path,
            allow_insecure_transport=True,
        )
        app = build_app(server_state)

        with TestClient(app) as test_client:
            resp = test_client.post("/handshake/init", json={
                "vault_id": "vault-1",
                "api_key": "wrong-key",
                "client_timestamp": __import__("time").time(),
            })
            assert resp.status_code == 403


def test_server_accepts_correct_vault_id_and_api_key():
    with tempfile.TemporaryDirectory() as tmp:
        access_path = os.path.join(tmp, "vault_access.json")
        access = VaultAccessStore(access_path)
        api_key = access.register("vault-1")

        server_state = SyncServer(
            storage_dir=tmp,
            enable_server_auth=True,
            sig_key_path=os.path.join(tmp, "sig.json"),
            access_store_path=access_path,
            allow_insecure_transport=True,
        )
        app = build_app(server_state)

        with TestClient(app) as test_client:
            resp = test_client.post("/handshake/init", json={
                "vault_id": "vault-1",
                "api_key": api_key,
                "client_timestamp": __import__("time").time(),
            })
            assert resp.status_code == 200


def test_access_store_revoke_removes_access():
    with tempfile.TemporaryDirectory() as tmp:
        access_path = os.path.join(tmp, "vault_access.json")
        access = VaultAccessStore(access_path)
        api_key = access.register("vault-1")
        assert access.verify("vault-1", api_key)

        assert access.revoke("vault-1") is True
        assert not access.verify("vault-1", api_key)
        assert access.revoke("vault-1") is False  # already gone


# ---------------------------------------------------------------------
# Fix: no transport-layer security independent of the handshake
# ---------------------------------------------------------------------

def test_server_rejects_plaintext_from_non_loopback_by_default():
    with tempfile.TemporaryDirectory() as tmp:
        access_path = os.path.join(tmp, "vault_access.json")
        server_state = SyncServer(
            storage_dir=tmp,
            enable_server_auth=True,
            sig_key_path=os.path.join(tmp, "sig.json"),
            access_store_path=access_path,
            allow_insecure_transport=False,  # the default; explicit here for clarity
        )
        app = build_app(server_state)

        # Starlette's TestClient reports the client host as "testclient"
        # by default, which is deliberately NOT in LOOPBACK_HOSTS — this
        # exercises the "non-local, no TLS evidence" rejection path.
        with TestClient(app) as test_client:
            resp = test_client.post("/handshake/init", json={
                "vault_id": "vault-1",
                "api_key": "whatever",
                "client_timestamp": __import__("time").time(),
            })
            assert resp.status_code == 400


def test_server_allows_request_with_trusted_forwarded_proto_header():
    with tempfile.TemporaryDirectory() as tmp:
        access_path = os.path.join(tmp, "vault_access.json")
        access = VaultAccessStore(access_path)
        api_key = access.register("vault-1")

        server_state = SyncServer(
            storage_dir=tmp,
            enable_server_auth=True,
            sig_key_path=os.path.join(tmp, "sig.json"),
            access_store_path=access_path,
            allow_insecure_transport=False,
        )
        app = build_app(server_state)

        with TestClient(app) as test_client:
            resp = test_client.post(
                "/handshake/init",
                json={
                    "vault_id": "vault-1",
                    "api_key": api_key,
                    "client_timestamp": __import__("time").time(),
                },
                headers={"X-Forwarded-Proto": "https"},
            )
            assert resp.status_code == 200


# ---------------------------------------------------------------------
# Fix: vault.db file permissions
# ---------------------------------------------------------------------

@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits don't apply on Windows")
def test_vault_db_file_is_owner_only_permissions():
    with tempfile.TemporaryDirectory() as tmp:
        db_path = os.path.join(tmp, "vault.db")
        # Simulate a loose umask by creating the file world-readable first.
        open(db_path, "a").close()
        os.chmod(db_path, 0o644)

        storage = VaultStorage(db_path)
        try:
            mode = stat.S_IMODE(os.stat(db_path).st_mode)
            assert mode == 0o600
        finally:
            storage.close()