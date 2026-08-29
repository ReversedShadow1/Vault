#!/usr/bin/env python3
"""
Week 2 deliverable: standalone ML-DSA-65 (Dilithium3) primitive test.

NOT integrated into the vault yet — that happens in Week 3, where this
signs the sync handshake for server authentication (optional, per spec 5.2).
"""

import oqs


def demo_ml_dsa_65():
    sig_alg = "ML-DSA-65"
    print(f"=== {sig_alg} standalone test ===")

    message = b"pq-vault sync handshake transcript placeholder"

    with oqs.Signature(sig_alg) as signer:
        public_key = signer.generate_keypair()
        print(f"Public key: {len(public_key)} bytes")

        signature = signer.sign(message)
        print(f"Signature:  {len(signature)} bytes")

    # Verification uses a fresh Signature object with just the algorithm name —
    # mirrors how a real verifier (e.g. the client checking the server's
    # signature) would only ever have the public key, not the private state.
    with oqs.Signature(sig_alg) as verifier:
        valid = verifier.verify(message, signature, public_key)
        print(f"\nSignature valid for original message: {valid}")
        assert valid, "SIGNATURE FAILURE: valid signature rejected"  # nosec B101 — standalone verification script, not shipped/imported by the app

        # Tamper check: flipping one byte of the message must invalidate the signature
        tampered_message = message[:-1] + bytes([message[-1] ^ 0x01])
        tampered_valid = verifier.verify(tampered_message, signature, public_key)
        print(f"Signature valid for tampered message: {tampered_valid}")
        assert not tampered_valid, "SECURITY BUG: tampered message passed verification"  # nosec B101

        # Wrong-key check
        with oqs.Signature(sig_alg) as other:
            other_public_key = other.generate_keypair()
        wrong_key_valid = verifier.verify(message, signature, other_public_key)
        print(f"Signature valid under a different public key: {wrong_key_valid}")
        assert wrong_key_valid is False, "SECURITY BUG: signature verified under wrong key"  # nosec B101

    print("\nML-DSA-65 primitive test: PASSED")


if __name__ == "__main__":
    demo_ml_dsa_65()
