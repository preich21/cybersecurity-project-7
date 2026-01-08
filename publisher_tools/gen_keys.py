#!/usr/bin/env python3
"""
Key Generation Tool for Secure Update System
Generates Ed25519 keypair for signing update manifests.

Run once to generate keys:
    python3 gen_keys.py

Keep the private key SECRET and OFFLINE.
Embed the public key in your application code.
"""

import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def generate_keypair():
    """Generate Ed25519 keypair and display as base64."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    priv_b64 = base64.b64encode(priv_bytes).decode()
    pub_b64 = base64.b64encode(pub_bytes).decode()

    print("=" * 70)
    print("Ed25519 Keypair Generated")
    print("=" * 70)
    print()
    print("PRIVATE KEY (keep secret, store offline):")
    print(priv_b64)
    print()
    print("PUBLIC KEY (embed in application code):")
    print(pub_b64)
    print()
    print("=" * 70)
    print("IMPORTANT:")
    print("1. Save the PRIVATE KEY to a secure location (e.g., .private_key)")
    print("2. Add .private_key to .gitignore")
    print("3. Copy the PUBLIC KEY to PINNED_PUBKEY_B64 in your app")
    print("=" * 70)


if __name__ == "__main__":
    generate_keypair()

# Made with Bob
