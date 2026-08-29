# Threat Model v2 (Final) — Post-Quantum Password Vault

**Status:** v2, Week 4. Supersedes `threat_model_v1.md`, which covered
only the core vault (Week 1, before the sync module existed). This
version folds in the sync/handshake design, the static-analysis and
edge-case testing results, and the benchmark data. Sections 1-6 restate
v1 where unchanged; new material is marked **[v2]**.

---

## 1. Assets (unchanged from v1, now includes sync-specific items)

| Asset | Where it lives | Sensitivity |
|---|---|---|
| Master password | In memory only, transiently, during KDF derivation | Critical |
| Vault key (derived) | In memory only, for the unlocked session | Critical |
| Stored entries | AES-256-GCM ciphertext, local SQLite | Critical |
| Argon2id salt | Plaintext, `vault_meta` table | Low (not secret by design) |
| **[v2]** Password verifier canary | AES-256-GCM ciphertext, `vault_meta` table | Low — its plaintext is a fixed constant, not secret; only its *correct decryption* is meaningful |
| Sync session keys | In memory only, per-session, single-use | High — compromise exposes one transfer, not the vault |
| Vault backup blob in transit | Network, session-key wrapped | High — the harvest-now-decrypt-later target |
| **[v2]** Vault backup blob at rest (server) | Server filesystem, `sync/blob_store.py` | Still fully vault-key-encrypted even at rest — server compromise alone does not disclose vault contents |
| **[v2]** Server's long-term ML-DSA-65 signing key | Server memory only (regenerated per process start in this implementation) | High — compromise enables handshake impersonation, mitigated by client-side key pinning |

## 2. Trust boundaries — unchanged from v1

See `threat_model_v1.md` §2 for the diagram; it holds as designed and
implemented. **[v2] confirmed by testing**: `test_core_edge_cases.py`
and manual import inspection verify that `core/` and `gui/` (excluding
the sync dialog's on-click handler) load zero network libraries —
the module boundary is real, not just documented.

## 3. Attack surface inventory — updated with Week 3/4 findings

### Core vault — unchanged, no remote attack surface.

### Sync module **[v2 — now implemented and tested, not just designed]**

Concrete findings from implementing and adversarially testing the
handshake (see `tests/test_sync_edge_cases.py`):

- **Replay attacks**: tested directly. A captured `handshake_complete`
  or `sync/upload` request replayed verbatim is rejected (`409`) via
  the single-use `session_id` state machine
  (`PENDING → ESTABLISHED → CONSUMED`). Verified for both endpoints.
- **MITM / server impersonation**: tested directly. Client-side
  trust-on-first-use key pinning means a server presenting a different
  ML-DSA-65 signing key than previously pinned is rejected before any
  data is sent (`ServerAuthError`), not silently accepted.
- **Malformed input crashing the server**: found and fixed during
  edge-case testing. The initial implementation let malformed base64
  or wrong-length key material raise unhandled exceptions in
  `handshake_complete`. Fixed by validating and catching at the
  boundary, returning clean `400`s. This was a real robustness gap,
  not a hypothetical one — caught by `test_handshake_complete_with_garbage_base64`
  and `test_handshake_complete_with_wrong_length_keys`.
- **Path traversal via `vault_id`**: tested directly.
  `BlobStore._path_for` sanitizes to alphanumeric/`-`/`_` only;
  confirmed a traversal-only input (`"../../"`) is rejected rather than
  silently writing to an unintended location, and confirmed a mixed
  input (`"../../evil"`) sanitizes down to a safe filename contained
  within the storage directory.
- **Oversized payloads**: tested directly with a 10MB upload — server
  handled it without crashing (see `test_oversized_upload_payload`). No
  request-size limit is currently enforced at the application layer;
  see §6 (out of scope / future work) — a production deployment behind
  a real reverse proxy would typically enforce this at that layer.
- **Static analysis**: `bandit` found 8 Low-severity findings across
  the whole codebase, all reviewed and either justified (test-script
  asserts, an intentional best-effort exception swallow in the
  clipboard clear timer) or confirmed as false positives (empty-string
  comparisons flagged as "hardcoded passwords"). Zero Medium/High
  findings. `pip-audit` found real CVEs in the initially-pinned
  `cryptography`/`starlette` versions; fixed by upgrading pins
  (see `requirements.txt`) — re-verified clean.

## 4. Why PQC is scoped to the sync handshake, not local storage

Unchanged from v1 — see `threat_model_v1.md` §4 for the full
Grover-vs-Shor / harvest-now-decrypt-later argument. **[v2]**: the
benchmark (`docs/benchmark_results.md`) now provides concrete numbers
supporting the design choice: the hybrid handshake's overhead (~0.1ms
compute, ~2.3KB one-time payload) is negligible for this project's
actual workload, so there's no performance argument for narrowing PQC's
scope further or for skipping it.

## 5. BB84 / QKD — unchanged from v1

See `threat_model_v1.md` §5.

## 6. Explicitly out of scope — updated

Carried over from v1 (compromised OS/keylogger, physical device theft
while unlocked, side-channel attacks against library internals), plus:

- **[v2] Application-layer request size limits on the sync server.**
  The 10MB-upload test passed, but nothing currently caps upload size
  — a malicious or buggy client could send an arbitrarily large
  payload. For a "lightweight self-hosted service" used by one person
  syncing their own vault, this is a low-priority gap; a production
  multi-user deployment would need this addressed, likely at the
  reverse-proxy layer (nginx `client_max_body_size` or equivalent)
  rather than in application code.
- **[v2] Server signing key persistence.** In the current
  implementation, the server's ML-DSA-65 signing key is regenerated
  every process restart (`SyncServer.__init__` in `sync/server.py`).
  This means client-side key pinning breaks on every server restart —
  functionally safe (the client detects the "different key" and
  refuses, rather than silently trusting a new key), but inconvenient.
  A real deployment should persist the signing key to disk. Documented
  here rather than fixed because it's a deployment/operations concern,
  not a security flaw — the fail-safe behavior (refuse rather than
  silently trust) is the security-relevant property, and that already
  works correctly.
- **[v2] Rate limiting on the sync server.** No protection against a
  client hammering `/handshake/init` to exhaust server memory with
  pending sessions (bounded eventually by `SessionStore.sweep_expired`,
  but that must be called periodically — nothing currently schedules
  it automatically). Fine for a single-user self-hosted tool; would
  need addressing for anything more exposed.
- **Formal / automated cryptographic protocol verification** (e.g.
  ProVerif, Tamarin) of the handshake design. The protocol was designed
  by hand against a written threat model and stress-tested with
  targeted adversarial unit tests, which is appropriate rigor for a
  one-month project, but is not the same guarantee a formal model would
  provide.

## 7. Summary of what changed between v1 and v2

| Item | v1 | v2 |
|---|---|---|
| Sync module | Designed, not built | Built, tested against 6 categories of attack |
| Static analysis | Not yet run | `bandit` + `pip-audit` clean, findings documented |
| Edge cases | Not yet tested | 37 tests across core + sync, 2 real bugs found and fixed |
| Performance data | None | Benchmark shows hybrid overhead is negligible for this workload |
| Wire-level verification | Design only | Real tcpdump capture confirms the negotiation matches the design on an actual socket |
