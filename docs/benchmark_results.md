# Benchmark: Classical vs. Hybrid PQC Handshake

Raw data: `benchmarks/results/benchmark_raw_data.json`
Chart: `benchmarks/results/handshake_benchmark.png`
Reproduce: `LD_LIBRARY_PATH=/root/_oqs/lib python3 benchmarks/handshake_benchmark.py`

## What's being compared

- **Classical-only**: X25519 key exchange alone — what this project's
  handshake would look like *without* the ML-KEM-768 addition. This
  variant only exists for this benchmark; it is never an option in the
  real protocol (`sync/server.py` / `sync/client.py` are hybrid-only).
- **Hybrid**: X25519 + ML-KEM-768, combined via HKDF — the actual
  protocol used by this project.

Both variants were run 200 times each, measuring the full compute cost
on both sides (keygen + exchange), on this project's development
machine (1 vCPU, containerized — the machine used throughout this
project, not representative production server hardware).

## Results

| Metric | Classical (X25519 only) | Hybrid (X25519 + ML-KEM-768) | Overhead |
|---|---|---|---|
| Median latency | 0.30 ms | 0.41 ms | +0.11 ms (+36%) |
| Mean latency | 0.38 ms | 0.46 ms | +0.08 ms (+20%) |
| Payload (key material) | 64 bytes | 2,336 bytes | +2,272 bytes (+3550%) |

## Interpretation

- **Latency overhead is negligible in absolute terms.** Both variants
  complete in well under a millisecond on median; the ~0.1ms difference
  is not something a user would ever notice, and it's dwarfed by normal
  network round-trip time to any real server (typically 10-100+ ms even
  on a fast connection). The *relative* percentage overhead looks large
  only because both numbers are tiny to begin with.
- **The classical run has a heavier tail** (one outlier hit ~10ms,
  visible in the box plot) while the hybrid run's worst case (~2.2ms)
  is actually tighter. This is almost certainly OS/scheduler noise on a
  shared, single-core sandbox rather than a property of either
  algorithm — worth re-running on dedicated hardware before drawing any
  conclusion about tail latency, but it does show hybrid isn't
  systematically worse on the tail either.
- **Payload overhead is real and worth stating plainly**: ML-KEM-768's
  public key (1184 bytes) and ciphertext (1088 bytes) dominate the
  handshake size — a ~36x increase over X25519's 32-byte keys. In
  absolute terms this is still small (2.3 KB total, once, per
  handshake) — trivial for a sync operation that also transfers an
  entire vault backup, but it would matter more in a context with many
  short-lived handshakes or highly bandwidth-constrained links (e.g.
  IoT, satellite links) — not a concern for this project's use case
  (occasional manual/scheduled backup sync).

## Bottom line

For this project's actual workload — an infrequent, user-initiated
backup sync — the hybrid handshake's cost (a fraction of a millisecond
of compute, ~2.3KB of one-time key material) is effectively free
relative to the cost of transferring the vault backup itself and is
clearly worth paying for the quantum-resistance guarantee described in
the threat model.
