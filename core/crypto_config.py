"""
Central crypto configuration.

Spec §6 (non-functional requirements) calls for "crypto-agility": algorithm
choices and KDF parameters must live in ONE place, not be hardcoded across
the codebase, so they can be swapped later without hunting through files.

Every module that touches crypto imports its parameters from here.
Nothing in core/ or sync/ should hardcode a cost parameter, key size,
or algorithm name outside this file.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Argon2Params:
    # OWASP-recommended baseline for Argon2id (2024+ guidance).
    # time_cost/memory_cost are intentionally conservative defaults;
    # tune per target hardware and document the choice in the threat model.
    time_cost: int = 3          # iterations
    memory_cost: int = 65536    # KiB (64 MiB)
    parallelism: int = 4        # lanes
    hash_len: int = 32          # bytes -> 256-bit vault key
    salt_len: int = 16          # bytes


@dataclass(frozen=True)
class AESGCMParams:
    key_len: int = 32       # 256-bit key
    nonce_len: int = 12     # 96-bit nonce, GCM standard


@dataclass(frozen=True)
class PasswordPolicyParams:
    min_zxcvbn_score: int = 3   # 0-4 scale; require "strong"
    min_length: int = 12


@dataclass(frozen=True)
class SyncParams:
    kem_alg: str = "ML-KEM-768"
    sig_alg: str = "ML-DSA-65"
    session_key_len: int = 32          # bytes -> AES-256-GCM key
    # Explicit protocol version, bound into the HKDF `info` parameter by
    # sync/pqc_crypto.py's derive_session_key(). Previously this was a
    # hand-written "v1" baked into a separate hkdf_info_prefix constant
    # (two things that had to be kept in sync by hand); now there is a
    # single source of truth. Bump this — and ONLY this — to version the
    # handshake's key-derivation context in a future protocol change.
    protocol_version: int = 1
    handshake_window_seconds: int = 60
    transfer_window_seconds: int = 120
    clock_skew_tolerance_seconds: int = 30
    session_id_len: int = 16           # bytes, 128-bit


PASSWORD_POLICY = PasswordPolicyParams()
SYNC_PARAMS = SyncParams()
AESGCM_PARAMS = AESGCMParams()

# ---------------------------------------------------------------------
# Argon2id parameter versioning
# ---------------------------------------------------------------------
#
# Every vault records the crypto_config_version that was current at the
# moment it was created (core/storage.py, vault_meta.crypto_config_version).
# unlock() MUST derive keys using the params that were current for THAT
# vault's version — never whatever ARGON2_PARAMS currently resolves to —
# or every existing vault silently becomes unopenable the moment this
# file's defaults change. See core/kdf.py get_argon2_params() and
# core/vault.py unlock() / rekey_to_current_params().
#
# RULE: this dict is APPEND-ONLY. Never edit or delete an existing
# version's entry — that retroactively breaks every vault created under
# it, and the failure mode (verifier mismatch) is indistinguishable from
# the user having typed the wrong password. To change parameters, add a
# NEW integer key and bump CRYPTO_CONFIG_VERSION to point at it.
ARGON2_PARAMS_BY_VERSION: dict[int, Argon2Params] = {
    1: Argon2Params(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16),
}

# Version used for NEW vaults created from this point forward.
CRYPTO_CONFIG_VERSION = 1

# Convenience alias for "the current version's params" — used by
# generate_salt()'s default and by Vault.create(). Anything that needs a
# SPECIFIC (possibly older) version's params should go through
# core.kdf.get_argon2_params(version) instead of this alias.
ARGON2_PARAMS = ARGON2_PARAMS_BY_VERSION[CRYPTO_CONFIG_VERSION]