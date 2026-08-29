"""
Master password -> vault key, via Argon2id.

We use the low-level argon2.low_level.hash_secret_raw API (not the
high-level PasswordHasher) because we need raw key bytes to feed into
AES-256-GCM, not a PHC-formatted string for verification-only use.

Never hand-roll the KDF math itself — argon2-cffi wraps the reference
Argon2 C implementation. This module only handles parameterization and
salt management.

IMPORTANT (crypto-agility fix): derive_vault_key() takes an explicit
`params` argument rather than silently reading the module-level current
ARGON2_PARAMS. Callers that are unlocking an EXISTING vault must look up
that vault's own stored crypto_config_version via get_argon2_params()
and pass those params in — never the current default — or a future
change to ARGON2_PARAMS_BY_VERSION's latest entry will silently make
every previously-created vault unopenable. See core/vault.py.
"""

import os
from argon2.low_level import hash_secret_raw, Type

from core.crypto_config import ARGON2_PARAMS, ARGON2_PARAMS_BY_VERSION, Argon2Params


def get_argon2_params(version: int) -> Argon2Params:
    """
    Look up the Argon2id parameter set that was in effect for a given
    crypto_config_version.

    Raises ValueError for an unrecognized version rather than silently
    falling back to current params — an unlock() that guessed wrong here
    would derive the wrong key and report "wrong password" for a vault
    that's actually fine, which is a much worse failure mode than a loud,
    explicit error.
    """
    try:
        return ARGON2_PARAMS_BY_VERSION[version]
    except KeyError:
        raise ValueError(
            f"Unknown crypto_config_version {version}. This vault was "
            f"created by a version of this software whose Argon2 "
            f"parameters aren't recorded in ARGON2_PARAMS_BY_VERSION here "
            f"— refusing to guess at parameters rather than risk deriving "
            f"the wrong key silently."
        )


def generate_salt(params: Argon2Params = ARGON2_PARAMS) -> bytes:
    """Cryptographically random salt, unique per vault."""
    return os.urandom(params.salt_len)


def derive_vault_key(master_password: str, salt: bytes, params: Argon2Params = ARGON2_PARAMS) -> bytes:
    """
    Derive a 256-bit vault key from the master password + salt, using the
    given Argon2id parameter set.

    Same (password, salt, params) always yields the same key — this is
    required so an existing vault can be unlocked. Never reuse a salt
    across different vaults/users.

    `params` defaults to the CURRENT config, which is correct for
    creating a new vault. When unlocking an EXISTING vault, callers must
    pass the params for that vault's own stored crypto_config_version
    (via get_argon2_params(stored_version)) rather than relying on this
    default.
    """
    if not isinstance(master_password, str) or master_password == "":  # nosec B105 — empty-string check, not a hardcoded credential
        raise ValueError("master_password must be a non-empty string")
    if len(salt) != params.salt_len:
        raise ValueError(
            f"salt must be {params.salt_len} bytes, got {len(salt)}"
        )

    password_bytes = master_password.encode("utf-8")
    try:
        key = hash_secret_raw(
            secret=password_bytes,
            salt=salt,
            time_cost=params.time_cost,
            memory_cost=params.memory_cost,
            parallelism=params.parallelism,
            hash_len=params.hash_len,
            type=Type.ID,  # Argon2id: hybrid, resistant to both GPU and side-channel attacks
        )
        return key
    finally:
        # Best-effort: overwrite the local bytes reference. CPython doesn't
        # guarantee immediate deallocation, but we avoid keeping the
        # plaintext password around any longer than necessary.
        password_bytes = b"\x00" * len(password_bytes)