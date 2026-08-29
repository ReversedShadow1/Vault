#!/usr/bin/env python3
"""
Week 4 deliverable: classical-only vs. hybrid PQC handshake benchmark.

Measures:
  1. Latency — wall-clock time to run the full key-exchange computation
     on both sides (keygen + exchange), classical-only vs. hybrid.
  2. Payload size — bytes of key material that cross the network in
     each handshake variant.

"Classical-only" here means X25519-only key exchange — i.e. what this
project's handshake would look like WITHOUT the ML-KEM-768 addition.
It exists only for this benchmark; it is not an option anywhere in the
actual sync protocol (which is hybrid-only, per the design rationale in
docs/sync_protocol_design.md).

Run: LD_LIBRARY_PATH=/root/_oqs/lib python3 benchmarks/handshake_benchmark.py
"""

import time
import statistics
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sync import pqc_crypto

N_ITERATIONS = 200


def run_classical_only_handshake():
    """X25519-only key exchange, both sides, timed as one round."""
    session_id = pqc_crypto.generate_session_id()

    server_priv, server_pub = pqc_crypto.generate_x25519_keypair()
    client_priv, client_pub = pqc_crypto.generate_x25519_keypair()

    client_secret = pqc_crypto.x25519_shared_secret(client_priv, server_pub)
    server_secret = pqc_crypto.x25519_shared_secret(server_priv, client_pub)
    assert client_secret == server_secret

    # HKDF over the X25519 secret alone (no KEM secret to concatenate)
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from core.crypto_config import SYNC_PARAMS

    hkdf = HKDF(algorithm=hashes.SHA256(), length=SYNC_PARAMS.session_key_len,
                salt=None, info=SYNC_PARAMS.hkdf_info_prefix + session_id)
    session_key = hkdf.derive(client_secret)

    payload_bytes = len(server_pub) + len(client_pub)  # what crosses the network
    return session_key, payload_bytes


def run_hybrid_handshake():
    """X25519 + ML-KEM-768 hybrid, both sides, timed as one round —
    this is the actual protocol used by sync/server.py and sync/client.py."""
    session_id = pqc_crypto.generate_session_id()

    server_x25519_priv, server_x25519_pub = pqc_crypto.generate_x25519_keypair()
    server_kem_secret, server_kem_pub = pqc_crypto.generate_kem_keypair()

    client_x25519_priv, client_x25519_pub = pqc_crypto.generate_x25519_keypair()
    kem_ciphertext, client_kem_secret = pqc_crypto.kem_encapsulate(server_kem_pub)

    client_x25519_secret = pqc_crypto.x25519_shared_secret(client_x25519_priv, server_x25519_pub)
    server_x25519_secret = pqc_crypto.x25519_shared_secret(server_x25519_priv, client_x25519_pub)
    assert client_x25519_secret == server_x25519_secret

    server_kem_secret_decap = pqc_crypto.kem_decapsulate(server_kem_secret, kem_ciphertext)
    assert server_kem_secret_decap == client_kem_secret

    client_session_key = pqc_crypto.derive_session_key(client_x25519_secret, client_kem_secret, session_id)
    server_session_key = pqc_crypto.derive_session_key(server_x25519_secret, server_kem_secret_decap, session_id)
    assert client_session_key == server_session_key

    payload_bytes = (
        len(server_x25519_pub) + len(client_x25519_pub) +
        len(server_kem_pub) + len(kem_ciphertext)
    )
    return client_session_key, payload_bytes


def time_n_runs(fn, n):
    times_ms = []
    payload_size = None
    for _ in range(n):
        start = time.perf_counter()
        _, payload_size = fn()
        elapsed_ms = (time.perf_counter() - start) * 1000
        times_ms.append(elapsed_ms)
    return times_ms, payload_size


def main():
    print(f"Running {N_ITERATIONS} iterations of each handshake variant...")

    print("\n=== Classical-only (X25519) ===")
    classical_times, classical_payload = time_n_runs(run_classical_only_handshake, N_ITERATIONS)
    print(f"Payload: {classical_payload} bytes")
    print(f"Latency (ms): mean={statistics.mean(classical_times):.3f} "
          f"median={statistics.median(classical_times):.3f} "
          f"stdev={statistics.stdev(classical_times):.3f} "
          f"min={min(classical_times):.3f} max={max(classical_times):.3f}")

    print("\n=== Hybrid (X25519 + ML-KEM-768) ===")
    hybrid_times, hybrid_payload = time_n_runs(run_hybrid_handshake, N_ITERATIONS)
    print(f"Payload: {hybrid_payload} bytes")
    print(f"Latency (ms): mean={statistics.mean(hybrid_times):.3f} "
          f"median={statistics.median(hybrid_times):.3f} "
          f"stdev={statistics.stdev(hybrid_times):.3f} "
          f"min={min(hybrid_times):.3f} max={max(hybrid_times):.3f}")

    print("\n=== Overhead ===")
    latency_overhead_pct = (statistics.mean(hybrid_times) / statistics.mean(classical_times) - 1) * 100
    payload_overhead_pct = (hybrid_payload / classical_payload - 1) * 100
    latency_overhead_ms = statistics.mean(hybrid_times) - statistics.mean(classical_times)
    print(f"Latency overhead: +{latency_overhead_ms:.3f} ms ({latency_overhead_pct:.1f}%)")
    print(f"Payload overhead: +{hybrid_payload - classical_payload} bytes ({payload_overhead_pct:.1f}%)")

    return {
        "classical_times_ms": classical_times,
        "hybrid_times_ms": hybrid_times,
        "classical_payload_bytes": classical_payload,
        "hybrid_payload_bytes": hybrid_payload,
    }


def save_chart_and_data(results: dict, output_dir: str):
    import json
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    os.makedirs(output_dir, exist_ok=True)

    with open(os.path.join(output_dir, "benchmark_raw_data.json"), "w") as f:
        json.dump(results, f, indent=2)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))

    # --- Latency chart: box plot to show distribution, not just mean ---
    ax1.boxplot(
        [results["classical_times_ms"], results["hybrid_times_ms"]],
        tick_labels=["Classical\n(X25519 only)", "Hybrid\n(X25519 + ML-KEM-768)"],
        showfliers=True,
    )
    ax1.set_ylabel("Handshake compute time (ms)")
    ax1.set_title(f"Handshake latency\n({N_ITERATIONS} iterations each)")
    ax1.grid(axis="y", alpha=0.3)

    # --- Payload size chart ---
    labels = ["Classical\n(X25519 only)", "Hybrid\n(X25519 + ML-KEM-768)"]
    values = [results["classical_payload_bytes"], results["hybrid_payload_bytes"]]
    bars = ax2.bar(labels, values, color=["#4a90d9", "#d97a4a"])
    ax2.set_ylabel("Key-material bytes over the network")
    ax2.set_title("Handshake payload size")
    ax2.grid(axis="y", alpha=0.3)
    for bar, val in zip(bars, values):
        ax2.text(bar.get_x() + bar.get_width() / 2, val, f"{val} B",
                  ha="center", va="bottom", fontsize=9)

    fig.tight_layout()
    chart_path = os.path.join(output_dir, "handshake_benchmark.png")
    fig.savefig(chart_path, dpi=150)
    print(f"\nChart saved to: {chart_path}")
    print(f"Raw data saved to: {os.path.join(output_dir, 'benchmark_raw_data.json')}")


if __name__ == "__main__":
    results = main()
    save_chart_and_data(results, output_dir=os.path.join(os.path.dirname(__file__), "results"))
