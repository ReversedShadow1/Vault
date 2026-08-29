"""
Crypto primitives for the sync handshake. This is the ONLY place in the
codebase where asymmetric/PQC crypto lives — matches spec §2's rationale
that PQC is meaningful exclusively at key-exchange/signature boundaries.

Everything here comes from audited libraries:
  - X25519: `cryptography` (hazmat.primitives.asymmetric.x25519)
  - HKDF:   `cryptography` (hazmat.primitives.kdf.hkdf)
  - ML-KEM-768 / ML-DSA-65: `liboqs-python` (wraps liboqs C library)

No lattice math, no curve arithmetic, no signature scheme logic is
implemented here — this module only orchestrates calls into those
libraries per the design in docs/sync_protocol_design.md.
"""

import base64
import json
import os
import oqs
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from core.crypto_config import SYNC_PARAMS
from core.file_permissions import check_owner_only_or_raise, enforce_owner_only


# ---- X25519 ----

def generate_x25519_keypair() -> tuple[bytes, bytes]:
    """Returns (private_key_bytes, public_key_bytes), both raw 32-byte."""
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat, PublicFormat, NoEncryption,
    )
    priv = X25519PrivateKey.generate()
    pub = priv.public_key()
    priv_bytes = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_bytes = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return priv_bytes, pub_bytes


def x25519_shared_secret(private_key_bytes: bytes, peer_public_key_bytes: bytes) -> bytes:
    priv = X25519PrivateKey.from_private_bytes(private_key_bytes)
    peer_pub = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
    return priv.exchange(peer_pub)


# ---- ML-KEM-768 ----

def generate_kem_keypair() -> tuple[bytes, bytes]:
    """
    Returns (secret_key_bytes, public_key_bytes).

    liboqs's KeyEncapsulation object normally holds the secret key
    internally and only exposes it via export_secret_key() — we export
    it immediately so the caller can persist it (e.g. in the session
    store) independent of the object's lifetime, and re-instantiate a
    KeyEncapsulation with secret_key=... later to decapsulate.
    """
    with oqs.KeyEncapsulation(SYNC_PARAMS.kem_alg) as kem:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
    return secret_key, public_key


def kem_encapsulate(public_key_bytes: bytes) -> tuple[bytes, bytes]:
    """Returns (ciphertext, shared_secret). Caller: the party WITHOUT the
    private key (the client, encapsulating against the server's KEM pubkey)."""
    with oqs.KeyEncapsulation(SYNC_PARAMS.kem_alg) as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key_bytes)
    return ciphertext, shared_secret


def kem_decapsulate(secret_key_bytes: bytes, ciphertext: bytes) -> bytes:
    """Caller: the party WITH the private key (the server)."""
    with oqs.KeyEncapsulation(SYNC_PARAMS.kem_alg, secret_key=secret_key_bytes) as kem:
        return kem.decap_secret(ciphertext)


# ---- ML-DSA-65 (optional server authentication) ----

def generate_sig_keypair() -> tuple[bytes, bytes]:
    """Returns (secret_key_bytes, public_key_bytes)."""
    with oqs.Signature(SYNC_PARAMS.sig_alg) as sig:
        public_key = sig.generate_keypair()
        secret_key = sig.export_secret_key()
    return secret_key, public_key


def sign(secret_key_bytes: bytes, message: bytes) -> bytes:
    with oqs.Signature(SYNC_PARAMS.sig_alg, secret_key=secret_key_bytes) as sig:
        return sig.sign(message)


def verify(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    with oqs.Signature(SYNC_PARAMS.sig_alg) as sig:
        return sig.verify(message, signature, public_key_bytes)


# ---- Signing key persistence ----
#
# Fix for "server signing key is not persisted": previously the server
# generated a fresh ML-DSA-65 keypair on every process start, which
# silently broke client-side TOFU pinning (sync/client.py) on every
# restart — a returning client would see a "different" signing key and
# either have to re-pin blindly or abort. These two functions let the
# server reuse the same keypair across restarts, the same way an SSH
# server persists its host key.

def save_sig_keypair(secret_key: bytes, public_key: bytes, path: str) -> None:
    """
    Persists the server's ML-DSA-65 signing keypair to disk with
    owner-only permissions where the filesystem supports it — this file
    is as sensitive as the secret key itself.
    """
    payload = {
        "sig_alg": SYNC_PARAMS.sig_alg,
        "secret_key": base64.b64encode(secret_key).decode("ascii"),
        "public_key": base64.b64encode(public_key).decode("ascii"),
    }
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f)
        enforce_owner_only(path)
    except BaseException:
        # Best-effort cleanup of a partially-written key file — better to
        # leave nothing on disk than a truncated/corrupt secret key.
        try:
            os.remove(path)
        except OSError:
            pass
        raise


def load_sig_keypair(path: str) -> tuple[bytes, bytes] | None:
    """
    Returns (secret_key, public_key) if a persisted signing keypair
    exists at `path`, else None (caller should generate and save a new
    one). Refuses to load — raising rather than silently proceeding — if
    the file is readable/writable by anyone other than the owner AND the
    containing filesystem is actually capable of enforcing that (see
    core/file_permissions.py — this is skipped on filesystems such as
    WSL DrvFs mounts that can't enforce per-file permissions at all). Also
    refuses to load a file generated for a different signature algorithm
    than the one currently configured in SYNC_PARAMS.sig_alg.
    """
    if not os.path.exists(path):
        return None

    check_owner_only_or_raise(path, "Signing key file")

    with open(path, "r") as f:
        payload = json.load(f)

    if payload.get("sig_alg") != SYNC_PARAMS.sig_alg:
        raise ValueError(
            f"Signing key file {path!r} was generated for "
            f"{payload.get('sig_alg')!r} but this server is currently "
            f"configured for {SYNC_PARAMS.sig_alg!r}. Refusing to load a "
            f"mismatched key — delete the file to regenerate under the "
            f"current algorithm, or fix SYNC_PARAMS.sig_alg."
        )

    secret_key = base64.b64decode(payload["secret_key"])
    public_key = base64.b64decode(payload["public_key"])
    return secret_key, public_key


# ---- Hybrid key combination ----

def derive_session_key(x25519_secret: bytes, kem_secret: bytes, session_id: bytes) -> bytes:
    """
    Combine the classical and post-quantum shared secrets into one
    AES-256-GCM session key via HKDF-SHA256.

    Concatenating both secrets before HKDF is the standard hybrid-KEM
    construction: the result is secure as long as AT LEAST ONE of the
    two input secrets is strong, which is the entire point of doing
    hybrid key exchange (see docs/sync_protocol_design.md).

    The HKDF `info` parameter is built from SYNC_PARAMS.protocol_version
    directly (a single int, not a hand-written string constant that has
    to be kept in sync with it by hand) plus the per-handshake
    session_id, so different protocol versions and different sessions
    can never derive colliding key material from the same input secrets.
    """
    ikm = x25519_secret + kem_secret
    info = f"pq-vault-sync-v{SYNC_PARAMS.protocol_version}|".encode("ascii") + session_id
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=SYNC_PARAMS.session_key_len,
        salt=None,
        info=info,
    )
    return hkdf.derive(ikm)


def generate_session_id() -> bytes:
    return os.urandom(SYNC_PARAMS.session_id_len)