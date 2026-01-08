#!/usr/bin/env python3
"""
Update Publisher Tool
Creates signed manifest for secure update distribution.

Usage:
    python3 publish_update.py --version 1.0.1 --payload fake-update.txt --url https://example.com/releases/fake-update.txt --private-key <base64_key>

Or set environment variables:
    PRIVATE_KEY_B64=<your_key>
    python3 publish_update.py --version 1.0.1 --payload fake-update.txt --url https://example.com/releases/fake-update.txt
"""

import argparse
import base64
import hashlib
import json
import os
import sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def sign_manifest(manifest_data: dict, private_key_b64: str) -> str:
    """Sign the manifest and return base64 signature."""
    # Canonical JSON for signing (sorted keys, no whitespace)
    msg = json.dumps(manifest_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    
    # Load private key
    priv_bytes = base64.b64decode(private_key_b64)
    priv = Ed25519PrivateKey.from_private_bytes(priv_bytes)
    
    # Sign
    sig = priv.sign(msg)
    return base64.b64encode(sig).decode("utf-8")


def create_manifest(version: str, payload_path: Path, payload_url: str, private_key_b64: str) -> dict:
    """Create and sign a manifest for the given payload."""
    if not payload_path.exists():
        raise FileNotFoundError(f"Payload file not found: {payload_path}")
    
    # Read payload and compute hash
    payload_bytes = payload_path.read_bytes()
    sha256_hash = hashlib.sha256(payload_bytes).hexdigest()
    size = len(payload_bytes)
    
    # Create unsigned manifest
    unsigned = {
        "version": version,
        "payload_url": payload_url,
        "sha256": sha256_hash,
        "size": size,
    }
    
    # Sign it
    signature = sign_manifest(unsigned, private_key_b64)
    
    # Complete manifest
    manifest = dict(unsigned)
    manifest["signature"] = signature
    
    return manifest


def main():
    parser = argparse.ArgumentParser(description="Create signed update manifest")
    parser.add_argument("--version", required=True, help="Version string (e.g., 1.0.1)")
    parser.add_argument("--payload", required=True, help="Path to payload file")
    parser.add_argument("--url", required=True, help="Public URL where payload will be hosted")
    parser.add_argument("--private-key", help="Base64 private key (or set PRIVATE_KEY_B64 env var)")
    parser.add_argument("--output", default="manifest.json", help="Output manifest file (default: manifest.json)")
    
    args = parser.parse_args()
    
    # Get private key
    private_key_b64 = args.private_key or os.getenv("PRIVATE_KEY_B64")
    if not private_key_b64:
        print("ERROR: Private key required. Use --private-key or set PRIVATE_KEY_B64 env var.", file=sys.stderr)
        sys.exit(1)
    
    payload_path = Path(args.payload)
    
    try:
        manifest = create_manifest(args.version, payload_path, args.url, private_key_b64)
        
        # Write manifest
        output_path = Path(args.output)
        output_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        
        print("=" * 70)
        print("✓ Manifest created successfully")
        print("=" * 70)
        print(f"Version:      {manifest['version']}")
        print(f"Payload:      {payload_path}")
        print(f"SHA256:       {manifest['sha256']}")
        print(f"Size:         {manifest['size']} bytes")
        print(f"Payload URL:  {manifest['payload_url']}")
        print(f"Output:       {output_path}")
        print("=" * 70)
        print()
        print("Next steps:")
        print(f"1. Upload {payload_path} to {manifest['payload_url']}")
        print(f"2. Upload {output_path} to your manifest URL")
        print("=" * 70)
        
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

# Made with Bob
