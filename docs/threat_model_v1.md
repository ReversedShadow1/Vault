# Threat Model v1 — Post-Quantum Password Vault

**Status:** v1 (Week 1). Will be revisited and expanded to v2 in Week 4 once
the sync module, replay protection, and benchmark results exist.

---

## 1. Assets

| Asset | Where it lives | Sensitivity |
|---|---|---|
| Master password | Only in memory, transiently, during KDF derivation. Never stored, never logged. | Critical — root of trust for everything else |
| Vault key (derived) | In memory only, for the duration of an unlocked session (`Vault._vault_key`) | Critical — decrypts every entry |
| Stored entries (site/username/password/notes) | AES-256-GCM ciphertext in the local SQLite file | Critical — the actual secrets being protected |
| Argon2id salt | Plaintext in SQLite `vault_meta` table | Low — not secret by design, but must be unique per vault and never reused |
| Sync session keys (Week 3+) | In memory only, for the duration of one sync session | High — compromise exposes one sync/backup transfer, not the whole vault |
| Vault backup blob in transit (Week 3+) | Network, encrypted under the hybrid session key | High — this is the "harvest now, decrypt later" target |

---

## 2. Trust boundaries

```
┌─────────────────────────── Local machine ───────────────────────────┐
│                                                                        │
│   ┌──────────────┐        ┌────────────────────┐                     │
│   │  User (types  │──────▶│   Core vault module │  ← no network       │
│   │  master pw)   │       │  (offline, trusted) │    libraries        │
│   └──────────────┘        └──────────┬──────────┘    importable here  │
│                                       │ SQLite file                    │
│                                       │ (ciphertext only)               │
│                                       ▼                                │
│                              [ vault.db on disk ]                      │
│                                                                        │
│   ┌────────────────────┐                                              │
│   │   Sync module        │  ← the ONLY networked component            │
│   │  (opt-in, off by      │                                            │
│   │   default)             │                                            │
│   └──────────┬─────────┘                                              │
└──────────────┼─────────────────────────────────────────────────────────┘
               │  network (trust boundary crossing)
               ▼
      ┌──────────────────┐
      │  Sync server        │  ← untrusted-by-design: stores/relays
      │  (self-hosted)      │     encrypted blobs only, never sees
      └──────────────────┘     plaintext vault data or the vault key
```

Two boundaries matter here:

1. **User ↔ core vault** — the master password crosses from the user's head
   into process memory. This is unavoidable and is the root trust
   assumption of the whole system.
2. **Local machine ↔ network** — crossed *only* by the sync module, and
   only when the user has explicitly opted in. The core vault never
   crosses this boundary.

---

## 3. Attack surface inventory

### Core vault module — no remote attack surface, by design
- Imports no networking libraries (verified: `socket`, `requests`,
  `httpx`, etc. do not appear anywhere under `core/`).
- The only inputs are local: master password (keyboard), the SQLite
  file on disk, and GUI events.
- Remaining local attack surface: a malicious or malformed vault file
  (e.g. hand-edited SQLite rows) could be fed to the decrypt path. This
  is mitigated by AES-GCM's authentication tag — any tampering causes a
  `DecryptionError` rather than silently returning corrupted plaintext.
  SQLite itself is a mature, widely-audited parser, but malformed
  database files are still a nonzero attack surface (see §5 out of
  scope: supply-chain / dependency trust).

### Sync module — the sole network-facing component (Week 3+)
- Client ↔ server handshake (X25519 + ML-KEM-768) is the primary
  network attack surface: a MITM could attempt to downgrade, replay, or
  tamper with handshake messages.
- Mitigations planned: hybrid KEM (breaking either primitive alone
  isn't enough), replay protection via timestamp/nonce, session
  expiry, optional ML-DSA signatures for server authentication.
- The sync server itself is a target: if compromised, an attacker gets
  encrypted blobs only (server never receives the vault key or
  plaintext), but could still deny service, corrupt/withhold backups,
  or attempt to serve a malicious "server" identity to the client
  (mitigated by ML-DSA auth, when enabled).

---

## 4. Why PQC is scoped to the sync handshake, not local storage

This is a deliberate scoping decision, not an oversight, and it's worth
stating the cryptographic reasoning explicitly:

- **Grover vs. Shor.** A cryptographically relevant quantum computer
  breaks *asymmetric* cryptography (RSA, ECC, Diffie-Hellman) via
  Shor's algorithm — that's a full break, not a weakening. Symmetric
  ciphers like AES are only affected by Grover's algorithm, which
  provides a quadratic (not exponential) speedup. AES-256's 256-bit
  keyspace under Grover still gives an effective ~128-bit security
  margin — considered safe for the foreseeable future. This is exactly
  why NIST's PQC effort standardizes replacements for key exchange and
  signatures (ML-KEM, ML-DSA), not for AES.
- **Where asymmetric crypto actually appears in this system:** nowhere
  in the core vault. Master-password-based key derivation (Argon2id) and
  entry encryption (AES-256-GCM) are both symmetric. The *only* place
  public-key cryptography is used is the sync handshake — client and
  server establishing a shared session key over an untrusted network.
  That is the one place a quantum computer would actually help an
  attacker.
- **"Harvest now, decrypt later."** This is the concrete, present-day
  reason to prioritize PQC in the handshake specifically: an adversary
  who can record encrypted network traffic today (e.g. a passive
  observer on the path to a self-hosted sync server) can store the
  classical-only key exchange and decrypt it retroactively once a
  sufficiently powerful quantum computer exists. Local, offline vault
  storage has no equivalent exposure — there's no ciphertext in transit
  for anyone to "harvest" in the first place; an attacker would need to
  already have the encrypted vault file *and* eventually a quantum
  computer *and* still contend with AES-256's Grover-adjusted margin.
  The sync handshake is the urgent target; local storage is not.
- **Why hybrid (X25519 + ML-KEM-768), not PQC alone.** ML-KEM is newer
  and has had less real-world cryptanalytic scrutiny than X25519.
  Combining both via HKDF means the scheme only breaks if *both*
  primitives break — matching current NIST guidance and the approach
  already shipped by Chrome and Signal. We are not betting the whole
  system on the less battle-tested primitive.

---

## 5. BB84 / QKD — considered and rejected

Quantum Key Distribution (BB84 and variants) was considered as an
alternative to PQC for the sync handshake and rejected for this
project. BB84 requires specialized photonic hardware (single-photon
sources/detectors) and a dedicated physical channel (fiber or
free-space line-of-sight) between the two communicating parties — it
cannot run over commodity internet infrastructure or ordinary consumer
hardware. That makes it fundamentally infeasible for a software-only,
one-month internship project aimed at a self-hosted sync server reached
over a normal network connection. PQC (ML-KEM, ML-DSA) achieves the
same quantum-resistance goal in pure software, running on any CPU,
which is the correct tool for this problem. QKD is noted here as
explicitly out of scope rather than silently omitted.

---

## 6. Explicitly out of scope

- **Compromised OS / keylogger on the user's machine.** If the endpoint
  itself is compromised, the master password can be captured at entry
  regardless of vault design. Out of scope for this project; standard
  endpoint security practices apply.
- **Physical device theft while the vault is unlocked.** An unlocked
  vault with an attacker holding the device is a lost cause by
  definition; auto-lock (idle timeout) reduces the exposure window but
  does not eliminate it.
- **Supply-chain attacks on dependencies** (`cryptography`,
  `argon2-cffi`, `liboqs`, PyPI compromise, etc.). Noted as future
  work — e.g. dependency pinning (already done via `requirements.txt`)
  and `pip-audit` in Week 4 are partial mitigations, not a full
  supply-chain security program.
- **Side-channel attacks** (timing, power analysis, cache attacks)
  against the underlying crypto library implementations. We rely on
  the audited libraries' own hardening here rather than adding our own
  countermeasures — reimplementing constant-time primitives ourselves
  would violate the "never hand-roll cryptography" principle.
- **Malicious or coerced sync server.** The protocol design (§3) limits
  a fully malicious server to denial-of-service and blob
  withholding/corruption, not plaintext disclosure — but a
  sophisticated targeted attack against a specific user's self-hosted
  server is not fully modeled in v1.

---

## 7. Open questions for v2 (Week 4)

- Formal review of the replay-protection design once implemented
  (nonce/timestamp window, clock skew tolerance).
- Whether ML-DSA signing should be mandatory rather than optional,
  given the marginal cost.
- Results from `bandit` / `pip-audit` folded back into this document.
- Any findings from the Wireshark trace of the real handshake.
