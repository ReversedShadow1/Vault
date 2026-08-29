# Demo Script

A walkthrough for presenting this project live, ~10-15 minutes.

## 1. Offline vault walkthrough (~4 min)

```bash
cd pq-vault
export LD_LIBRARY_PATH=/root/_oqs/lib   # only needed once PQC/sync is touched
python3 gui/app.py
```

- Create a new vault with a master password. Point out the live zxcvbn
  strength meter — try a weak password first, watch it get rejected.
- Add 2-3 entries. Use the password generator on one of them — show the
  length/character-class options.
- Point out the strength meter on the entry dialog too.
- Copy a password to clipboard — mention the auto-clear countdown
  (`Settings` to show the configurable timeout).
- Lock the vault manually, then unlock it again with the correct
  password — and once with a **wrong** password, to show the clean
  rejection.
- **Talking point:** open Task Manager / `lsof -i` (or just state it)
  to note this process has made zero network connections so far. The
  core vault genuinely cannot leak anything over a network because it
  has no code path that could.

## 2. Enable sync (~5 min)

- Click **☁ Sync**. Point out it's off by default — explicit opt-in.
- Start the sync server in a second terminal:
  ```bash
  export LD_LIBRARY_PATH=/root/_oqs/lib
  export PQVAULT_SYNC_STORAGE=./sync_storage
  python3 -m uvicorn sync.server:app --host 127.0.0.1 --port 8420
  ```
- Enter the server URL and a vault ID, hit **Backup now**.
- Point out the status log: "Pinned server signing key
  (trust-on-first-use)" — explain this is the same trust model as SSH
  host-key pinning, and that a future mismatched key would hard-abort
  rather than silently proceed.
- Add one more entry to the vault, then **Backup now** again — point
  out in the server terminal log that this is a *second*, independent
  handshake (fresh session key), not a reused connection.

## 3. Show the handshake trace (~3 min)

Either re-run the capture live, or open the pre-captured one:

```bash
# Pre-captured (recommended for a live demo — no sudo/tcpdump dependency):
cat docs/trace_capture/README.md
# or open docs/trace_capture/handshake_capture.pcap in Wireshark,
# filter tcp.port == 8420, right-click a POST /handshake/init -> Follow -> HTTP Stream
```

- Point out the `server_kem_pub` field is 1184 bytes (base64-decoded)
  — that's the ML-KEM-768 public key. Contrast with `server_x25519_pub`
  at 32 bytes. This is the concrete, undeniable evidence that the
  hybrid negotiation is real and not just described in code comments.
- Point out two separate `session_id` values across the capture,
  each with entirely different key material — proof session keys are
  never reused.

## 4. Discuss crypto-agility (~2 min)

Open `core/crypto_config.py` and `sync/pqc_crypto.py` side by side:

- All KDF parameters, AES key/nonce sizes, and PQC algorithm names live
  in one file (`crypto_config.py`). Changing `ML-KEM-768` to a future
  algorithm — if one is ever deprecated or a stronger one standardized
  — is a one-line change, not a codebase-wide hunt.
- Point out the `CRYPTO_CONFIG_VERSION` stored in the vault's metadata
  table — the seed of a future migration path if parameters ever need
  to change for existing vaults.

## Optional: benchmark + report

If there's time, open `benchmarks/results/handshake_benchmark.png` and
`docs/benchmark_results.md` — the headline point is that the hybrid
handshake's overhead is a fraction of a millisecond and a couple of
kilobytes, which is effectively free for how infrequently this runs.

## Fallback if live demo isn't possible

Everything above has already been run and captured once:
`docs/trace_capture/`, `benchmarks/results/`, and the test suite output
(`pytest tests/ -v`) are all real, saved artifacts from an actual run —
none of this needs to work live to be credible.
