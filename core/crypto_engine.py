"""
AES-256-GCM encrypt/decrypt for individual vault entries.

Spec requirements (5.1):
- unique nonce per encryption operation
- authenticated (GCM gives us confidentiality + integrity)
- no plaintext ever written to disk

We use `cryptography`'s AESGCM primitive directly — audited library,
no custom cipher-mode logic.
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from core.crypto_config import AESGCM_PARAMS


class DecryptionError(Exception):
    """Raised when ciphertext fails authentication (tampered, wrong key, corrupt)."""
    pass


def encrypt_entry(plaintext: bytes, key: bytes, associated_data: bytes = b"") -> tuple[bytes, bytes]:
    """
    Encrypt one entry's plaintext under the vault key.

    Returns (nonce, ciphertext). Caller stores both — nonce is not secret,
    but MUST be unique per encryption under the same key (we generate it
    fresh with os.urandom every call, per spec requirement).

    associated_data (AAD) can bind metadata (e.g. entry ID) into the
    authentication tag without encrypting it — optional, defaults to empty.
    """
    if len(key) != AESGCM_PARAMS.key_len:
        raise ValueError(f"key must be {AESGCM_PARAMS.key_len} bytes")

    nonce = os.urandom(AESGCM_PARAMS.nonce_len)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce, ciphertext


def decrypt_entry(nonce: bytes, ciphertext: bytes, key: bytes, associated_data: bytes = b"") -> bytes:
    """
    Decrypt and authenticate one entry. Raises DecryptionError on any
    tampering, wrong key, or corruption — callers must not treat a failed
    decrypt as "empty" or silently continue.
    """
    if len(key) != AESGCM_PARAMS.key_len:
        raise ValueError(f"key must be {AESGCM_PARAMS.key_len} bytes")
    if len(nonce) != AESGCM_PARAMS.nonce_len:
        raise ValueError(f"nonce must be {AESGCM_PARAMS.nonce_len} bytes")

    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
    except InvalidTag:
        raise DecryptionError(
            "Authentication failed: ciphertext is corrupted, tampered with, "
            "or was encrypted under a different key."
        )


def zero_bytes(buf: bytearray) -> None:
    """
    Best-effort zeroing of a mutable byte buffer.

    Caveat (document this in the threat model): Python's memory model
    does not guarantee secrets aren't copied elsewhere (str immutability,
    garbage collector, swap). This reduces exposure window but is not a
    hard guarantee. For anything security-critical beyond this vault,
    consider a language with explicit memory control.
    """
    for i in range(len(buf)):
        buf[i] = 0
