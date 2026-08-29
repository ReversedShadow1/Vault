"""
Server-side session tracking for the sync handshake.

Sessions live in memory only (fine for a lightweight self-hosted
service per spec §3 — a restart just means in-flight handshakes are
lost, which is the correct failure mode for something this short-lived).

Enforces:
  - single-use session_id (primary replay defense)
  - handshake completion window
  - transfer window after establishment
"""

import time
import threading
from dataclasses import dataclass, field
from enum import Enum

from core.crypto_config import SYNC_PARAMS


class SessionStatus(Enum):
    PENDING = "pending"          # handshake_init sent, awaiting handshake_complete
    ESTABLISHED = "established"  # session_key derived, awaiting one upload/download
    CONSUMED = "consumed"        # already used for a transfer — cannot be reused


@dataclass
class ServerSession:
    session_id: bytes
    server_x25519_priv: bytes
    server_kem_secret: bytes
    vault_id: str
    status: SessionStatus
    created_at: float
    expires_at: float
    session_key: bytes | None = None


class SessionStore:
    """Thread-safe in-memory session store."""

    def __init__(self):
        self._sessions: dict[bytes, ServerSession] = {}
        self._lock = threading.Lock()

    def create_pending(self, session_id: bytes, x25519_priv: bytes, kem_secret: bytes, vault_id: str) -> ServerSession:
        now = time.time()
        session = ServerSession(
            session_id=session_id,
            server_x25519_priv=x25519_priv,
            server_kem_secret=kem_secret,
            vault_id=vault_id,
            status=SessionStatus.PENDING,
            created_at=now,
            expires_at=now + SYNC_PARAMS.handshake_window_seconds,
        )
        with self._lock:
            self._sessions[session_id] = session
        return session

    def get(self, session_id: bytes) -> ServerSession | None:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            if time.time() > session.expires_at:
                # Expired — treat as gone. Don't silently resurrect it.
                del self._sessions[session_id]
                return None
            return session

    def establish(self, session_id: bytes, session_key: bytes) -> bool:
        """Transitions PENDING -> ESTABLISHED. Returns False if the
        session doesn't exist, is expired, or isn't in PENDING state
        (e.g. a duplicate/replayed handshake_complete)."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or time.time() > session.expires_at:
                return False
            if session.status != SessionStatus.PENDING:
                return False
            session.status = SessionStatus.ESTABLISHED
            session.session_key = session_key
            session.expires_at = time.time() + SYNC_PARAMS.transfer_window_seconds
            return True

    def consume(self, session_id: bytes) -> ServerSession | None:
        """Transitions ESTABLISHED -> CONSUMED and returns the session
        for use, or None if not available (already consumed, expired,
        never established — i.e. any replay attempt)."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or time.time() > session.expires_at:
                return None
            if session.status != SessionStatus.ESTABLISHED:
                return None
            session.status = SessionStatus.CONSUMED
            return session

    def sweep_expired(self):
        """Call periodically to bound memory growth from abandoned handshakes."""
        now = time.time()
        with self._lock:
            expired = [sid for sid, s in self._sessions.items() if now > s.expires_at]
            for sid in expired:
                del self._sessions[sid]
        return len(expired)
