# Post-Quantum Password Vault

A desktop password manager with an **offline-first, zero-network-attack-surface core vault**, and a separate, opt-in **sync module** that backs up your vault over a hybrid classical + post-quantum encrypted channel.

> Built as a 1-month internship project. The full design rationale — every algorithm choice, the alternatives that were rejected and why, and the limitations that remain — is written up in [`docs/final-report.pdf`](docs/final-report.pdf) (or `pq-vault-final-report.tex` if you'd rather build it yourself). This README covers what you need to actually run the thing.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Getting Started](#getting-started)
- [Using the App](#using-the-app)
- [Setting Up Sync (Optional)](#setting-up-sync-optional)
- [Configuration Reference](#configuration-reference)
- [Testing & Verification](#testing--verification)
- [Project Structure](#project-structure)
- [Security Model, Summarized](#security-model-summarized)
- [Known Limitations](#known-limitations)
- [Roadmap](#roadmap)
- [License](#license)

## Overview

Password reuse and weak passwords — not sophisticated cryptanalysis — are the leading cause of account compromise. This project's job is to make **one** strong master password sufficient to protect many independent credentials, stored locally in an encrypted SQLite vault, with an optional way to back that vault up to a self-hosted server over a network you don't fully trust.

The core design discipline here isn't "use post-quantum cryptography everywhere" — it's *deciding precisely where post-quantum cryptography actually matters* (network key exchange, which is retroactively breakable by a future quantum computer) and leaving everything else (local AES-256-GCM storage) alone, because Grover's algorithm's quadratic speedup against AES-256 doesn't come close to threatening it in practice. See the full report for the complete threat-model reasoning.

## Features

**Core vault (offline, no network code path at all):**
- Argon2id key derivation (memory-hard, GPU/ASIC-resistant), with per-vault parameter versioning so future cost-parameter increases don't break existing vaults
- AES-256-GCM authenticated encryption for every entry
- SQLite storage with enforced owner-only file permissions
- Auto-lock on idle, clipboard auto-clear, built-in password generator
- A test verifies zero networking libraries are ever imported by the core vault or GUI — the "no network code path" claim is checked, not just asserted

**Sync module (opt-in, off by default):**
- Hybrid X25519 + ML-KEM-768 key exchange, combined via HKDF-SHA256, so the session key stays secure as long as *either* the classical or the post-quantum half holds
- Optional ML-DSA-65 server authentication with trust-on-first-use client pinning, enforced fail-closed by the client regardless of what a (possibly tampered) handshake response contains
- Per-vault API-key authorization, independent of the crypto handshake — a sound key exchange alone doesn't mean a client is allowed to read or write a given vault
- Fail-closed transport security: the server refuses to serve plaintext traffic to non-local clients unless TLS is actually in effect (terminated directly or via a trusted reverse proxy)
- Per-IP rate limiting and request size caps on the sync server
- In-app vault registration and restore-to-live-session UX in the GUI — no separate terminal required for day-to-day use

## Architecture

```
┌─────────────────────────── Local machine (no remote attack surface) ───────────────────────────┐
│                                                                                                   │
│   User master password                                                                          │
│         │                                                                                        │
│         ▼                                                                                        │
│  ┌───────────────────┐        export/restore         ┌────────────────────┐                    │
│  │   Core Vault       │ ◄────── backup blob ────────► │   Sync Module       │──────┐             │
│  │  (offline, zero    │        (vault-key wrapped)    │  (opt-in, off by    │      │             │
│  │  network libs)     │                                │  default)           │      │  hybrid     │
│  │                     │                                │                     │      │  handshake  │
│  │  Argon2id → key     │                                │  X25519 + ML-KEM-768│      │  + auth +   │
│  │  AES-256-GCM/entry  │                                │  → HKDF → session   │      │  TLS-only   │
│  │  SQLite storage     │                                │  key; ML-DSA-65     │      │             │
│  └─────────┬───────────┘                                │  server auth;       │      │             │
│            │                                             │  per-vault API key  │      │             │
│            ▼                                             └──────────┬──────────┘      │             │
│   vault.db (0600 perms,                                             │                 │             │
│   nothing plaintext, ever)                                          │                 ▼             │
│                                                                       └──────────► NETWORK ─────────► Sync Server
└───────────────────────────────────────────────────────────────────────────────────────────────────┘
```

The core vault has **no network code path** — the sync module is the only component that ever crosses the local/network trust boundary, and only when explicitly enabled. Within the sync module, **key agreement**, **authorization**, and **transport security** are three separate, independently-enforced layers, not one assumed to imply the others.

## Getting Started

### Prerequisites

- Python 3.12+
- `cmake`, `ninja-build`, `build-essential`, `libssl-dev` (to build `liboqs`)
- A Qt-capable display for the GUI (or `QT_QPA_PLATFORM=offscreen` for headless testing)

### Install

```bash
git clone <this-repo-url>
cd pq-vault-complete

python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

### Build `liboqs` (ML-KEM-768 + ML-DSA-65)

```bash
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=$HOME/_oqs \
  -DBUILD_SHARED_LIBS=ON \
  -DOQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_ml_dsa_65" \
  -DOQS_BUILD_ONLY_LIB=ON ..
ninja && ninja install
export LD_LIBRARY_PATH=$HOME/_oqs/lib:$LD_LIBRARY_PATH
```

Add the `export LD_LIBRARY_PATH` line to your shell profile so it persists across sessions.

> **WSL users:** if your project lives on a Windows drive mounted as `/mnt/c`, `/mnt/e`, etc. (DrvFs), be aware that filesystem does not enforce real per-file permissions — the app detects this automatically and won't hard-fail because of it, but understand that owner-only file protection genuinely isn't happening on that mount. See [Known Limitations](#known-limitations).

## Using the App

```bash
python3 gui/app.py
```

On first launch, click **Create New Vault…**, choose a location, and set a master password (a strength meter enforces a reasonable minimum). On subsequent launches, **Open Existing Vault…** lets you pick any vault file, or just launch the app again — it remembers and auto-detects the default `vault.db` in the working directory.

From the main window: **Add Entry**, **Edit**, **Delete**, **Copy Password** (clipboard auto-clears after a configurable delay), **Settings** (idle timeout, clipboard timing), **Lock Now**.

## Setting Up Sync (Optional)

Sync is entirely opt-in. Skip this section if you only want a local vault.

### 1. Run the sync server

```bash
python -m sync.server
```

By default this binds to `127.0.0.1:8420` and stores its state (blobs, the persisted signing key, the authorization store) under `./sync_storage`. Running it this way (rather than invoking `uvicorn` directly) is recommended, since it enforces the transport-security guard described below *before* binding to a non-local address.

To expose it beyond localhost, either terminate TLS directly:

```bash
export PQVAULT_SYNC_TLS_CERT=/path/to/cert.pem
export PQVAULT_SYNC_TLS_KEY=/path/to/key.pem
export PQVAULT_SYNC_HOST=0.0.0.0
python -m sync.server
```

...or put a reverse proxy in front that terminates TLS and forwards `X-Forwarded-Proto: https`, then set `PQVAULT_ALLOW_INSECURE_TRANSPORT=1` so the server trusts that header (only do this if the server is genuinely unreachable except through that proxy).

### 2. Register your vault for sync access

Every vault must be explicitly registered before the server will talk to it — there's no auto-registration, since that would let anyone who reaches the server first claim a vault ID for themselves.

**From a terminal:**

```bash
python -m sync.manage_access register <vault_id> --storage-dir ./sync_storage
```

This prints an API key — copy it now, it's shown exactly once.

**Or from inside the app:** open **☁ Sync**, fill in a Vault ID, point "Server storage directory" at the same directory the server uses, and click **Register / Rotate API Key**. This works whenever the app can reach that directory on the local filesystem (typically: client and server on the same machine) — it calls the identical underlying function the CLI does, so the trust model is unchanged.

### 3. Configure sync in the app

In the **☁ Sync** dialog: enter the server URL, the Vault ID you registered, and the API key. Check **Enable sync**, then **⬆ Backup now** or **⬇ Restore from backup…**. The first successful handshake pins the server's signing key (trust-on-first-use); if the server is ever reprovisioned, use **Forget pinned server key** to re-pin.

Restoring a backup asks if you want to switch the current window into the restored vault immediately (after re-entering your master password) rather than just telling you a file path and leaving you to find it.

## Configuration Reference

| Environment Variable | Default | Purpose |
|---|---|---|
| `PQVAULT_SYNC_STORAGE` | `./sync_storage` | Base directory for blobs, signing key, access store |
| `PQVAULT_SYNC_HOST` | `127.0.0.1` | Bind address (`python -m sync.server` only) |
| `PQVAULT_SYNC_PORT` | `8420` | Bind port |
| `PQVAULT_SYNC_TLS_CERT` / `PQVAULT_SYNC_TLS_KEY` | unset | Terminate TLS directly in this process |
| `PQVAULT_SYNC_SIG_KEY` | `<storage>/server_sig_key.json` | Persisted ML-DSA-65 signing key path |
| `PQVAULT_SYNC_ACCESS_STORE` | `<storage>/vault_access.json` | Per-vault authorization store path |
| `PQVAULT_ALLOW_INSECURE_TRANSPORT` | unset | Trust a reverse proxy's `X-Forwarded-Proto` header / allow plaintext non-local traffic |

## Testing & Verification

```bash
python3 -m pytest tests/ -v          # core + sync edge cases, security/regression coverage
bandit -r core gui sync cli.py       # static analysis
pip-audit -r requirements.txt        # dependency CVE scan
python3 benchmarks/handshake_benchmark.py   # classical vs. hybrid handshake cost
```

The test suite includes targeted adversarial cases: tampered ciphertext, malformed protocol messages, a handshake response with the server signature stripped (must be rejected by a default-configured client), unauthorized/unregistered access attempts, plaintext requests from non-local addresses, and vault file permission enforcement.

## Project Structure

```
core/         Vault, crypto, storage — zero network dependencies (verified by test)
gui/          PyQt6 application (unlock screen, main window, entry/sync dialogs)
sync/         Hybrid handshake, FastAPI server, sync client
              access_store.py   — per-vault authorization
              manage_access.py  — authorization CLI
              pqc_crypto.py     — X25519 / ML-KEM-768 / ML-DSA-65 primitives
              client.py         — SyncClient (fail-closed server auth by default)
              server.py         — FastAPI app, transport security, rate limiting
tests/        pytest suite: core + sync edge cases, security/regression coverage
benchmarks/   Classical-vs-hybrid handshake benchmark + results
docs/         Threat model, protocol design, PQC setup, trace capture, final report
```

## Security Model, Summarized

- **Local storage:** Argon2id (version-tracked per vault) → AES-256-GCM per entry. Post-quantum cryptography is deliberately *not* used here — Grover's algorithm only halves AES-256's effective security margin, leaving ~128-bit security, which remains comfortably infeasible to brute-force.
- **Sync key agreement:** X25519 + ML-KEM-768 hybrid, secure as long as either half holds. ML-DSA-65 signs the handshake for server authentication; TOFU pinning on the client side.
- **Sync authorization:** independent of key agreement — a per-vault, explicitly-registered, hashed API key, checked before any cryptographic work is done for a handshake.
- **Sync transport:** independent of both of the above — the server refuses non-local plaintext traffic by default, regardless of whether the handshake and authorization checks would otherwise succeed.

Full rationale, alternatives considered, and rejected designs (including why QKD/BB84 was ruled out and why PQC wasn't applied to local storage) are in the [final report](docs/final-report.pdf).

## Known Limitations

These are documented in full, with rationale, in the final report's Limitations section. Summarized:

- Local storage metadata (entry count, timestamps) isn't hidden by entry-level encryption.
- Memory zeroing is best-effort, not a hard guarantee (a CPython limitation, not specific to this project).
- File-permission enforcement depends on the host filesystem actually supporting POSIX permission bits — it's a no-op (detected and skipped, not silently claimed) on filesystems like WSL DrvFs mounts or FAT/exFAT.
- The session store, rate limiter, and authorization store are single-process and in-memory or single-file; a load-balanced multi-instance deployment needs a shared backing store.
- This project can support TLS termination but cannot provision a certificate on your behalf — you still need a real cert or a trusted reverse proxy.
- API key rotation and revocation are manual (CLI or in-app), with no expiry policy or audit log yet.
- No formal, machine-checked protocol verification (e.g. Tamarin/ProVerif) — validated against a written threat model with targeted adversarial testing instead.
- No multi-factor unlock for the master password; it remains the single root of trust, by design.

## Roadmap

- Key rotation, expiry, and audit logging for per-vault authorization
- Mutual TLS between reverse proxy and sync server as a stricter alternative to trusting a forwarded-protocol header
- Shared backing store (e.g. Redis) for multi-instance deployments
- Formal protocol verification
- Optional multi-factor unlock
- Migrate the handshake to TLS 1.3 hybrid PQC via OpenSSL 3.x + `oqs-provider`