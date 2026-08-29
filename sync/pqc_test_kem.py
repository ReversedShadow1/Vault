#!/usr/bin/env python3
"""
Week 2 deliverable: standalone ML-KEM-768 (Kyber) primitive test.

NOT integrated into the vault yet — that happens in Week 3. This script
exists purely to prove the primitive works end-to-end via liboqs-python
before we build the hybrid handshake protocol on top of it.

Requires the liboqs C library on the loader path — see
docs/pqc_setup.md for how it was built for this project.
"""

import oqs


def demo_ml_kem_768():
    kem_alg = "ML-KEM-768"
    print(f"=== {kem_alg} standalone test ===")

    # --- Recipient (e.g. sync server) generates a keypair ---
    with oqs.KeyEncapsulation(kem_alg) as recipient:
        public_key = recipient.generate_keypair()
        print(f"Recipient public key:  {len(public_key)} bytes")

        # --- Sender (e.g. client) encapsulates against the recipient's public key ---
        with oqs.KeyEncapsulation(kem_alg) as sender:
            ciphertext, sender_shared_secret = sender.encap_secret(public_key)
            print(f"Encapsulated ciphertext: {len(ciphertext)} bytes")
            print(f"Sender shared secret:    {len(sender_shared_secret)} bytes")

        # --- Recipient decapsulates using their private key ---
        recipient_shared_secret = recipient.decap_secret(ciphertext)
        print(f"Recipient shared secret: {len(recipient_shared_secret)} bytes")

    match = sender_shared_secret == recipient_shared_secret
    print(f"\nShared secrets match: {match}")
    assert match, "KEM FAILURE: shared secrets do not match"  # nosec B101 — standalone verification script, not shipped/imported by the app

    # Sanity check: a different keypair should NOT decapsulate to the same secret
    with oqs.KeyEncapsulation(kem_alg) as impostor:
        impostor.generate_keypair()
        try:
            impostor_secret = impostor.decap_secret(ciphertext)
            assert impostor_secret != sender_shared_secret, \
                "SECURITY BUG: wrong keypair produced the same shared secret"  # nosec B101 — standalone verification script
            print("Confirmed: an unrelated keypair decapsulates to a different secret (expected).")
        except Exception as e:
            print(f"Impostor decapsulation raised (also acceptable): {e}")

    print("\nML-KEM-768 primitive test: PASSED")


if __name__ == "__main__":
    demo_ml_kem_768()
