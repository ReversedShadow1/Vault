# Sync Protocol Design (Week 3)

Written before implementation so the wire format and key-derivation steps
are settled up front — this is the part that's expensive to redesign after
the fact.

## Design decision: what "session key" actually protects

The session key (from the hybrid handshake) protects the **network hop**,
not data at rest on the server. This matters because the server is one of
the two parties in the key exchange — it necessarily learns the session
key as a byproduct of participating in the handshake. That's fine: the
vault backup payload handed to the sync layer is *already* AES-256-GCM
ciphertext under the vault key (every entry is individually encrypted;
the server never sees the vault key or plaintext regardless of the sync
layer). The session key's job is specifically to defeat a passive network
observer doing "harvest now, decrypt later" against the handshake and
transfer — not to hide data from the server, which was never possible
anyway without giving the server the vault key (which we never do).

Concretely:
- **Upload:** client wraps the vault ciphertext blob under the session
  key (fresh hybrid KEX) → server unwraps the outer layer using the
  session key it also derived → stores the *inner* blob (still fully
  vault-key-encrypted) at rest. The outer wrapping is discarded after
  each transfer, not stored.
- **Download:** client starts a *new* handshake (new session key) →
  server re-wraps the stored inner blob under the fresh session key →
  client unwraps. Each transfer gets its own session key; none are
  reused across transfers.

## Handshake sequence

```
Client                                          Server
  |                                                |
  |----------- POST /handshake/init -------------->|
  |                                                 |  generate ephemeral:
  |                                                 |    X25519 keypair
  |                                                 |    ML-KEM-768 keypair
  |                                                 |  session_id = random 128-bit
  |                                                 |  store session (status=pending,
  |                                                 |    expires in HANDSHAKE_WINDOW_S)
  |<--- session_id, server_x25519_pub,              |
  |     server_kem_pub, server_timestamp,           |
  |     [ML-DSA sig over the above] ----------------|
  |                                                 |
  |  verify ML-DSA sig (if enabled)                 |
  |  generate ephemeral X25519 keypair              |
  |  x25519_secret = DH(client_priv, server_pub)    |
  |  kem_ct, kem_secret = encapsulate(server_kem_pub)|
  |  session_key = HKDF(x25519_secret || kem_secret, |
  |                      info=session_id)            |
  |                                                 |
  |--- POST /handshake/complete: session_id,        |
  |    client_x25519_pub, kem_ciphertext,           |
  |    client_timestamp -------------------------->|
  |                                                 |  check: session exists,
  |                                                 |    status==pending, not expired,
  |                                                 |    |client_timestamp - now| < skew
  |                                                 |  x25519_secret = DH(server_priv,
  |                                                 |                      client_pub)
  |                                                 |  kem_secret = decapsulate(
  |                                                 |     server_kem_secret, kem_ciphertext)
  |                                                 |  session_key = HKDF(same as client)
  |                                                 |  status = established,
  |                                                 |    expiry extended by TRANSFER_WINDOW_S
  |<------------------- 200 OK ---------------------|
  |                                                 |
  |  AES-256-GCM encrypt vault blob under            |
  |    session_key                                  |
  |--- POST /sync/upload: session_id, nonce,         |
  |    ciphertext -------------------------------->|
  |                                                 |  check status==established,
  |                                                 |    not expired
  |                                                 |  decrypt outer layer w/ session_key
  |                                                 |  store inner blob at rest
  |                                                 |  status = consumed (single use)
  |<------------------- 200 OK ---------------------|
```

Download follows the same handshake, then `GET /sync/download` in place
of the upload step — server re-wraps the stored blob under the new
session key.

## Key derivation

```
session_key = HKDF-SHA256(
    input_key_material = x25519_shared_secret || ml_kem_shared_secret,
    salt = None,
    info = b"pq-vault-sync-v1|" + session_id,
    length = 32,   # AES-256-GCM key
)
```

Concatenating both secrets before HKDF (rather than XOR or two separate
HKDF calls combined) is the standard hybrid-KEM construction — it's
secure as long as *either* input secret is strong, which is the whole
point of doing hybrid in the first place.

## Replay protection & session expiry

- `session_id` is single-use: once a session reaches `established` and
  is then consumed by an upload/download, further use of the same
  `session_id` is rejected. This is the primary replay defense — a
  captured `/sync/upload` request cannot be replayed because the
  session it depends on is already consumed.
- `HANDSHAKE_WINDOW_S` (default 60s): a `handshake_complete` must arrive
  within this window of `handshake_init`, or the session is expired and
  rejected.
- `TRANSFER_WINDOW_S` (default 120s): once established, the
  upload/download must happen within this window.
- Client timestamp in `handshake_complete` is checked against server
  time with a clock-skew tolerance (`CLOCK_SKEW_TOLERANCE_S`, default
  30s) — this is a secondary check; the primary defense is the
  single-use session_id, not the timestamp.

## Server authentication (optional, per spec 5.2)

If enabled, the server holds a long-term ML-DSA-65 keypair. The
`handshake_init` response is signed over
`session_id || server_x25519_pub || server_kem_pub || timestamp`. The
client is expected to have the server's public key pinned out-of-band
(e.g. shown once on first connection, like SSH host key pinning) —
full PKI is out of scope for this project.
