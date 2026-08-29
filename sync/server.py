"""
Minimal self-hosted sync server (spec §3, §5.2).

Stores/relays encrypted blobs only — every request handler here either
touches transport-layer ciphertext (session-key wrapped) or at-rest
ciphertext (vault-key wrapped, from BlobStore). Nothing here ever sees
the vault key or plaintext vault contents.

Run directly (recommended — enforces the transport-security guard below):
    python -m sync.server
Or via uvicorn (the guard only applies inside main(), see below):
    uvicorn sync.server:app --host 127.0.0.1 --port 8420
"""

import base64
import threading
import time
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from starlette.responses import JSONResponse

from core.crypto_config import SYNC_PARAMS
from core.crypto_engine import encrypt_entry, decrypt_entry, DecryptionError
from sync import pqc_crypto
from sync.access_store import VaultAccessStore
from sync.session_store import SessionStore, SessionStatus
from sync.blob_store import BlobStore


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(data: str) -> bytes:
    return base64.b64decode(data)


class HandshakeInitRequest(BaseModel):
    vault_id: str
    api_key: str
    client_timestamp: float


class HandshakeInitResponse(BaseModel):
    session_id: str
    server_x25519_pub: str
    server_kem_pub: str
    server_timestamp: float
    signature: str | None = None
    server_sig_pub: str | None = None  # for first-time pinning


class HandshakeCompleteRequest(BaseModel):
    session_id: str
    client_x25519_pub: str
    kem_ciphertext: str
    client_timestamp: float


class UploadRequest(BaseModel):
    session_id: str
    nonce: str
    ciphertext: str


class DownloadResponse(BaseModel):
    nonce: str
    ciphertext: str


# ---------------------------------------------------------------------
# Request-size cap
# ---------------------------------------------------------------------
#
# Checked against ACTUAL bytes received via the ASGI receive() channel,
# not just the Content-Length header — a client could lie about or omit
# that header while still streaming an oversized body. Rejects with 413
# before the body is fully buffered, so an oversized request can't be
# used to exhaust server memory.

class _RequestEntityTooLarge(Exception):
    pass


class MaxBodySizeMiddleware:
    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _RequestEntityTooLarge()
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _RequestEntityTooLarge:
            response = JSONResponse(
                {"detail": f"Request body exceeds the {self.max_bytes}-byte limit."},
                status_code=413,
            )
            await response(scope, receive, send)


# ---------------------------------------------------------------------
# Transport-layer security enforcement
# ---------------------------------------------------------------------
#
# Fix for "no transport-layer security independent of the handshake",
# flagged by external review as the report's actual headline risk. This
# code cannot conjure a valid TLS certificate out of nothing — that
# still requires the operator to supply one (or a reverse proxy that
# does). What it CAN do, and now does: refuse to silently serve real
# network traffic in plaintext. Default posture is fail-closed.
#
# A request is allowed through if EITHER:
#   - it comes from a loopback client address (local dev), OR
#   - it was actually received over TLS by this process, OR
#   - a reverse proxy in front of this process set X-Forwarded-Proto: https
#     (only trustworthy if this server is NEVER reachable directly,
#     which is the standard caveat for X-Forwarded-* headers generally).
# Otherwise it gets a hard 400 rather than being served in the clear.

class RequireSecureTransportMiddleware:
    LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}

    def __init__(self, app, allow_insecure: bool = False):
        self.app = app
        self.allow_insecure = allow_insecure

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or self.allow_insecure:
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or [])
        forwarded_proto = headers.get(b"x-forwarded-proto", b"").decode("latin-1").lower()
        client = scope.get("client")
        client_host = client[0] if client else None
        is_loopback = client_host in self.LOOPBACK_HOSTS
        is_https = scope.get("scheme") == "https" or forwarded_proto == "https"

        if is_loopback or is_https:
            await self.app(scope, receive, send)
            return

        response = JSONResponse(
            {
                "detail": (
                    "Refusing a plaintext request from a non-local address. "
                    "Serve this server behind TLS (directly via "
                    "PQVAULT_SYNC_TLS_CERT/PQVAULT_SYNC_TLS_KEY, or via a "
                    "reverse proxy setting X-Forwarded-Proto: https), or "
                    "connect from localhost for local development."
                )
            },
            status_code=400,
        )
        await response(scope, receive, send)


# ---------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------
#
# Simple in-memory, per-process, fixed-window limiter keyed by source
# IP, applied to /handshake/init specifically — that endpoint creates
# server-side session state and spends CPU generating ephemeral
# keypairs per request, so it's the one where uncapped request volume
# translates directly into uncapped resource use. It also blunts brute
# forcing of the per-vault api_key introduced above.
#
# Same documented limitation as SessionStore: in-memory and per-process,
# so it does not by itself protect a multi-instance/load-balanced
# deployment — that needs a shared store or reverse-proxy enforcement.

class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: float):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            hits = self._hits.setdefault(key, [])
            cutoff = now - self.window_seconds
            while hits and hits[0] < cutoff:
                hits.pop(0)
            if len(hits) >= self.max_requests:
                return False
            hits.append(now)
            return True

    def sweep(self) -> int:
        """Drop tracking entries for keys with no hits inside the current
        window, so memory doesn't grow unboundedly with the number of
        distinct source IPs seen over the server's lifetime."""
        now = time.time()
        cutoff = now - self.window_seconds
        with self._lock:
            dead = [k for k, hits in self._hits.items() if not hits or hits[-1] < cutoff]
            for k in dead:
                del self._hits[k]
        return len(dead)


def _load_or_create_sig_keypair(sig_key_path: str | None) -> tuple[bytes | None, bytes | None]:
    """
    Loads a persisted ML-DSA-65 signing keypair from sig_key_path if one
    exists, otherwise generates a fresh keypair and persists it there (if
    a path was given) so future restarts reuse the SAME key — this is
    what makes client-side TOFU pinning meaningful across restarts.

    sig_key_path=None falls back to the old ephemeral-per-process
    behavior; intended only for tests or throwaway local runs. A real
    deployment should always pass a real path (the default `app` further
    down in this file does).
    """
    if sig_key_path is None:
        return pqc_crypto.generate_sig_keypair()

    existing = pqc_crypto.load_sig_keypair(sig_key_path)
    if existing is not None:
        return existing

    secret_key, public_key = pqc_crypto.generate_sig_keypair()
    pqc_crypto.save_sig_keypair(secret_key, public_key, sig_key_path)
    return secret_key, public_key


class SyncServer:
    """
    Wraps server state (sessions, blobs, signing key, access control,
    rate limiter) so it's constructible with chosen storage/settings —
    makes the FastAPI app testable without touching real filesystem
    paths or global state.
    """

    def __init__(self, storage_dir: str, enable_server_auth: bool = True,
                 sig_key_path: str | None = None,
                 access_store_path: str | None = None,
                 max_request_bytes: int = 10 * 1024 * 1024,
                 handshake_rate_limit_max: int = 30,
                 handshake_rate_limit_window_seconds: float = 60.0,
                 sweep_interval_seconds: float = 30.0,
                 allow_insecure_transport: bool = False):
        self.sessions = SessionStore()
        self.blobs = BlobStore(storage_dir)
        self.enable_server_auth = enable_server_auth
        self.max_request_bytes = max_request_bytes
        self.sweep_interval_seconds = sweep_interval_seconds
        self.allow_insecure_transport = allow_insecure_transport

        if enable_server_auth:
            self.sig_secret_key, self.sig_public_key = _load_or_create_sig_keypair(sig_key_path)
        else:
            self.sig_secret_key, self.sig_public_key = None, None

        # access_store_path=None (e.g. in tests) means "no vault may be
        # registered" is impossible to satisfy, so tests must always
        # pass a real path — there is deliberately no "authorization
        # disabled" escape hatch analogous to enable_server_auth=False,
        # because unlike server authentication (which protects against
        # MITM), authorization protects against ANY unregistered client
        # reading/writing ANY vault, which should never be optional.
        if access_store_path is None:
            raise ValueError(
                "access_store_path is required — per-vault authorization "
                "is not optional. Pass a real path (e.g. inside "
                "storage_dir) even for local development/tests."
            )
        self.access = VaultAccessStore(access_store_path)

        self.handshake_rate_limiter = RateLimiter(
            max_requests=handshake_rate_limit_max,
            window_seconds=handshake_rate_limit_window_seconds,
        )

        self._sweep_thread: threading.Thread | None = None
        self._sweep_stop_event = threading.Event()

    def start_background_sweep(self) -> None:
        """Runs sessions.sweep_expired() and the rate limiter's sweep()
        periodically from a daemon thread, started/stopped via the
        FastAPI lifespan below. Previously SessionStore.sweep_expired()
        was tested but never actually called by the running server."""
        if self._sweep_thread is not None:
            return
        self._sweep_stop_event.clear()

        def _loop():
            while not self._sweep_stop_event.wait(self.sweep_interval_seconds):
                self.sessions.sweep_expired()
                self.handshake_rate_limiter.sweep()

        self._sweep_thread = threading.Thread(target=_loop, daemon=True, name="pqvault-sync-sweep")
        self._sweep_thread.start()

    def stop_background_sweep(self) -> None:
        if self._sweep_thread is None:
            return
        self._sweep_stop_event.set()
        self._sweep_thread.join(timeout=5)
        self._sweep_thread = None


def build_app(server_state: SyncServer) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        server_state.start_background_sweep()
        yield
        server_state.stop_background_sweep()

    app = FastAPI(title="PQ Vault Sync Server", lifespan=lifespan)
    app.add_middleware(MaxBodySizeMiddleware, max_bytes=server_state.max_request_bytes)
    app.add_middleware(
        RequireSecureTransportMiddleware,
        allow_insecure=server_state.allow_insecure_transport,
    )

    @app.post("/handshake/init", response_model=HandshakeInitResponse)
    def handshake_init(req: HandshakeInitRequest, request: Request):
        client_ip = request.client.host if request.client else "unknown"
        if not server_state.handshake_rate_limiter.allow(client_ip):
            raise HTTPException(429, "Too many handshake attempts from this address — slow down.")

        # Authorization check BEFORE any session state is created or any
        # ephemeral keypairs are generated — an unauthorized caller
        # shouldn't be able to spend server resources at all, not just
        # be blocked from the eventual upload/download.
        if not server_state.access.verify(req.vault_id, req.api_key):
            raise HTTPException(403, "Unknown vault_id or invalid api_key.")

        now = time.time()
        if abs(now - req.client_timestamp) > SYNC_PARAMS.clock_skew_tolerance_seconds:
            raise HTTPException(400, "Client timestamp outside acceptable clock skew.")

        session_id = pqc_crypto.generate_session_id()
        x25519_priv, x25519_pub = pqc_crypto.generate_x25519_keypair()
        kem_secret, kem_pub = pqc_crypto.generate_kem_keypair()

        server_state.sessions.create_pending(session_id, x25519_priv, kem_secret, req.vault_id)

        signature = None
        sig_pub_out = None
        if server_state.enable_server_auth:
            transcript = session_id + x25519_pub + kem_pub + str(now).encode()
            signature = pqc_crypto.sign(server_state.sig_secret_key, transcript)
            sig_pub_out = b64(server_state.sig_public_key)

        return HandshakeInitResponse(
            session_id=b64(session_id),
            server_x25519_pub=b64(x25519_pub),
            server_kem_pub=b64(kem_pub),
            server_timestamp=now,
            signature=b64(signature) if signature else None,
            server_sig_pub=sig_pub_out,
        )

    @app.post("/handshake/complete")
    def handshake_complete(req: HandshakeCompleteRequest):
        now = time.time()
        if abs(now - req.client_timestamp) > SYNC_PARAMS.clock_skew_tolerance_seconds:
            raise HTTPException(400, "Client timestamp outside acceptable clock skew.")

        try:
            session_id = unb64(req.session_id)
            client_x25519_pub = unb64(req.client_x25519_pub)
            kem_ciphertext = unb64(req.kem_ciphertext)
        except (ValueError, TypeError):
            raise HTTPException(400, "Malformed base64 in handshake fields.")

        session = server_state.sessions.get(session_id)
        if session is None:
            raise HTTPException(404, "Unknown or expired session.")
        if session.status != SessionStatus.PENDING:
            # Covers replay of a handshake_complete that already succeeded.
            raise HTTPException(409, "Session is not awaiting completion.")

        # Wrong-length keys, corrupted KEM ciphertext, etc. surface as
        # ValueError from the underlying crypto libraries — treat all of
        # them as a client error, not a server fault. Never let malformed
        # client input crash a request handler unhandled: besides being
        # bad practice, an unhandled exception can leak internals via the
        # default error response.
        try:
            x25519_secret = pqc_crypto.x25519_shared_secret(session.server_x25519_priv, client_x25519_pub)
            kem_secret = pqc_crypto.kem_decapsulate(session.server_kem_secret, kem_ciphertext)
        except (ValueError, RuntimeError):
            raise HTTPException(400, "Malformed handshake key material.")

        session_key = pqc_crypto.derive_session_key(x25519_secret, kem_secret, session_id)

        ok = server_state.sessions.establish(session_id, session_key)
        if not ok:
            raise HTTPException(409, "Session could not be established (expired or already used).")

        return {"status": "established"}

    @app.post("/sync/upload")
    def sync_upload(req: UploadRequest):
        try:
            session_id = unb64(req.session_id)
            nonce = unb64(req.nonce)
            ciphertext = unb64(req.ciphertext)
        except (ValueError, TypeError):
            raise HTTPException(400, "Malformed base64 in upload fields.")

        session = server_state.sessions.consume(session_id)
        if session is None:
            raise HTTPException(409, "No valid established session (expired, unknown, or already used).")

        try:
            inner_blob = decrypt_entry(nonce, ciphertext, session.session_key)
        except (DecryptionError, ValueError):
            raise HTTPException(400, "Transport decryption failed — corrupted or tampered upload.")

        # inner_blob is itself the vault's own ciphertext (vault-key
        # encrypted) — we store it as-is, never touching its contents.
        # We split it back into (nonce, ciphertext) using a length-prefix
        # framing established by the client (see sync/client.py).
        if len(inner_blob) < 1:
            raise HTTPException(400, "Malformed inner backup blob.")
        inner_nonce_len = inner_blob[0]
        if len(inner_blob) < 1 + inner_nonce_len:
            raise HTTPException(400, "Malformed inner backup blob framing.")
        inner_nonce = inner_blob[1:1 + inner_nonce_len]
        inner_ciphertext = inner_blob[1 + inner_nonce_len:]

        server_state.blobs.store(session.vault_id, inner_ciphertext, inner_nonce)
        return {"status": "stored"}

    @app.get("/sync/download", response_model=DownloadResponse)
    def sync_download(session_id: str):
        try:
            sid = unb64(session_id)
        except (ValueError, TypeError):
            raise HTTPException(400, "Malformed base64 session_id.")

        session = server_state.sessions.consume(sid)
        if session is None:
            raise HTTPException(409, "No valid established session (expired, unknown, or already used).")

        stored = server_state.blobs.retrieve(session.vault_id)
        if stored is None:
            raise HTTPException(404, "No backup found for this vault.")
        inner_nonce, inner_ciphertext = stored

        # Re-frame with the same length-prefix scheme before wrapping
        # under the (fresh, this-session-only) session key.
        inner_blob = bytes([len(inner_nonce)]) + inner_nonce + inner_ciphertext
        outer_nonce, outer_ciphertext = encrypt_entry(inner_blob, session.session_key)

        return DownloadResponse(nonce=b64(outer_nonce), ciphertext=b64(outer_ciphertext))

    return app


# ---------------------------------------------------------------------
# Default app instance / entrypoint
# ---------------------------------------------------------------------

_default_storage_dir = os.environ.get("PQVAULT_SYNC_STORAGE", "./sync_storage")
os.makedirs(_default_storage_dir, exist_ok=True)

_default_sig_key_path = os.environ.get(
    "PQVAULT_SYNC_SIG_KEY",
    os.path.join(_default_storage_dir, "server_sig_key.json"),
)
_default_access_store_path = os.environ.get(
    "PQVAULT_SYNC_ACCESS_STORE",
    os.path.join(_default_storage_dir, "vault_access.json"),
)
_default_allow_insecure_transport = os.environ.get(
    "PQVAULT_ALLOW_INSECURE_TRANSPORT", ""
).strip().lower() in ("1", "true", "yes")

_default_state = SyncServer(
    _default_storage_dir,
    enable_server_auth=True,
    sig_key_path=_default_sig_key_path,
    access_store_path=_default_access_store_path,
    allow_insecure_transport=_default_allow_insecure_transport,
)
app = build_app(_default_state)


def main():
    """
    Convenience entrypoint: `python -m sync.server`. Prefer this over
    invoking uvicorn directly, since it enforces the transport-security
    guard below BEFORE binding to a non-local address — running
    `uvicorn sync.server:app --host 0.0.0.0` directly bypasses this
    check the same way manually disabling any other safety check would.

    Supports terminating TLS itself (PQVAULT_SYNC_TLS_CERT /
    PQVAULT_SYNC_TLS_KEY) for the simplest single-binary self-hosted
    case. A reverse proxy in front of a plain HTTP uvicorn is equally
    valid and is what RequireSecureTransportMiddleware's
    X-Forwarded-Proto trust model is designed for; this project doesn't
    mandate either approach.
    """
    import uvicorn

    host = os.environ.get("PQVAULT_SYNC_HOST", "127.0.0.1")
    port = int(os.environ.get("PQVAULT_SYNC_PORT", "8420"))
    cert = os.environ.get("PQVAULT_SYNC_TLS_CERT")
    key = os.environ.get("PQVAULT_SYNC_TLS_KEY")

    ssl_kwargs = {}
    if cert and key:
        ssl_kwargs = {"ssl_certfile": cert, "ssl_keyfile": key}
    elif host not in RequireSecureTransportMiddleware.LOOPBACK_HOSTS and not _default_allow_insecure_transport:
        raise RuntimeError(
            f"Refusing to bind to non-local host {host!r} without TLS "
            f"configured (set PQVAULT_SYNC_TLS_CERT and PQVAULT_SYNC_TLS_KEY "
            f"to terminate TLS here directly, or put a reverse proxy in "
            f"front and set PQVAULT_ALLOW_INSECURE_TRANSPORT=1 to trust its "
            f"X-Forwarded-Proto header instead)."
        )

    uvicorn.run(app, host=host, port=port, **ssl_kwargs)


if __name__ == "__main__":
    main()