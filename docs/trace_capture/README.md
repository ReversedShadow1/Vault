# Captured Handshake Trace

**Files in this directory:**
- `handshake_capture.pcap` — raw tcpdump capture, loopback interface, port 8420 (open in Wireshark)
- `server_access_log.log` — uvicorn's real request log for this session
- `client_output.log` — the client-side script's output

## How this was captured

This is a **real network capture**, not a simulation:

```bash
tcpdump -i lo -w trace.pcap "tcp port 8420" &
python3 -m uvicorn sync.server:app --host 127.0.0.1 --port 8420 &
# ...then a real SyncClient talked to http://127.0.0.1:8420 over an actual TCP socket
```

54 packets were captured. This matters because everywhere else in this
project's testing, the client and server talk over FastAPI's in-process
ASGI test transport (fast, but no real socket, no real HTTP framing).
This capture goes over an actual loopback TCP connection with real
uvicorn HTTP handling, so what's in the pcap is what a real deployment
would put on the wire.

## What happened

The server log for this capture:

```
INFO:  127.0.0.1:40840 - "GET /docs HTTP/1.1" 200 OK
INFO:  127.0.0.1:40846 - "POST /handshake/init HTTP/1.1" 200 OK
INFO:  127.0.0.1:40846 - "POST /handshake/complete HTTP/1.1" 200 OK
INFO:  127.0.0.1:40846 - "POST /sync/upload HTTP/1.1" 200 OK
INFO:  127.0.0.1:40846 - "POST /handshake/init HTTP/1.1" 200 OK
INFO:  127.0.0.1:40846 - "POST /handshake/complete HTTP/1.1" 200 OK
INFO:  127.0.0.1:40846 - "GET /sync/download HTTP/1.1" 200 OK
```

Two full handshakes, exactly as designed: one to authorize the upload,
a **second, independent** one to authorize the download — each gets its
own session key, per the "each transfer gets its own session key; none
are reused" rule in `docs/sync_protocol_design.md`.

## Field-level contents (extracted from the pcap)

Parsing the JSON bodies out of the raw capture and measuring the
decoded (non-base64) byte length of each field:

**`POST /handshake/init` response (upload session):**

| Field | Decoded size | Matches spec? |
|---|---|---|
| `session_id` | 16 bytes | ✓ 128-bit, per `SYNC_PARAMS.session_id_len` |
| `server_x25519_pub` | 32 bytes | ✓ X25519 raw public key |
| `server_kem_pub` | **1184 bytes** | ✓ ML-KEM-768 public key (NIST spec size) |
| `signature` | 3309 bytes | ✓ ML-DSA-65 signature |
| `server_sig_pub` | 1952 bytes | ✓ ML-DSA-65 public key |

**`POST /handshake/complete` request (upload session):**

| Field | Decoded size | Matches spec? |
|---|---|---|
| `client_x25519_pub` | 32 bytes | ✓ X25519 raw public key |
| `kem_ciphertext` | **1088 bytes** | ✓ ML-KEM-768 ciphertext (NIST spec size) |

**`POST /sync/upload` request:**

| Field | Decoded size |
|---|---|
| `nonce` | 12 bytes (AES-GCM standard) |
| `ciphertext` | 16,429 bytes (the outer session-key-wrapped vault backup blob) |

The second handshake (`session_id = QJPQ6g+qxNAIOxghDr5/RA==`, for the
download) shows the **same field sizes but completely different key
material** than the first (`session_id = kSXXoL38i1JUHtnuuFMcJw==`) —
confirming each handshake generates fresh ephemeral keys rather than
reusing anything.

## What this demonstrates

1. **The hybrid negotiation is really happening on the wire** — not
   just in unit tests. The 1184-byte ML-KEM-768 public key and
   1088-byte ciphertext are unmistakable in the capture; you can't get
   those sizes from X25519 alone (32 bytes).
2. **Nothing sensitive is visible.** The `ciphertext` field in
   `/sync/upload` is 16,429 bytes of AES-256-GCM output — opaque
   without the session key, which itself is never transmitted (it's
   derived independently on each side from the KEM/DH secrets). Anyone
   capturing this traffic sees key material and ciphertext, never the
   vault key or plaintext vault contents.
3. **Two independent sessions, two independent key sets** — visible
   directly by comparing the two `handshake/init` responses in the
   capture.

## Reproducing this capture

```bash
export LD_LIBRARY_PATH=/root/_oqs/lib
sudo tcpdump -i lo -w trace.pcap "tcp port 8420" &
python3 -m uvicorn sync.server:app --host 127.0.0.1 --port 8420 &
sleep 2
python3 -c "
from core.vault import Vault, Entry
from sync.client import SyncClient
vault = Vault('/tmp/demo.db')
vault.create('Some-Strong-Password-99!')
vault.add_entry(Entry(site='demo.com', username='alice', password='hunter2xyz'))
nonce, ciphertext = vault.export_backup_blob()
client = SyncClient(base_url='http://127.0.0.1:8420', vault_id='demo')
client.upload_backup(nonce, ciphertext)
client.download_backup()
"
```

Open `handshake_capture.pcap` in Wireshark to inspect interactively —
filter on `tcp.port == 8420` and follow the HTTP stream for each
request to see the JSON bodies directly.
