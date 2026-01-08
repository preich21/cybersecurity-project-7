#!/usr/bin/env python3
"""
Feature-based secure update system for demonstrating attack vectors.

This module allows you to enable/disable specific security features to show
how different attack vectors work and how each security control mitigates them.

Security features that can be toggled:
- use_https: Require HTTPS instead of HTTP
- verify_checksum: Verify SHA256 hash of downloaded content
- verify_signature: Cryptographically verify update authenticity
- check_size_limit: Enforce maximum update size
- prevent_rollback: Block downgrades to older versions
- use_timeouts: Set request timeouts
- atomic_writes: Use atomic file operations

Educational demo - shows the impact of each security control.
"""

import base64
import hashlib
import json
import logging
import os
import tempfile
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

logger = logging.getLogger("secure_update")

UPDATE_MANIFEST_URL = "http://raw.githubusercontent.com/preich21/cybersecurity-project-7/refs/heads/fix/cli/demo_files/manifest.json"
UPDATE_URL = "http://raw.githubusercontent.com/preich21/cybersecurity-project-7/refs/heads/fix/cli/demo_files/fake-update.txt"

# Security constraints
MAX_UPDATE_BYTES = 5 * 1024 * 1024  # 5MB
REQUEST_TIMEOUT = 30

# Local file paths
LOCAL_UPDATE_FILE = "update_payload.txt"
LOCAL_VERSION_FILE = ".installed_version"

# Ed25519 public key (32 bytes, base64-encoded)
PINNED_PUBKEY_B64 = "SN278Y1/+T1KZJbtFbeVVaj+6kG82PSt4Y28l1Hk4es="


@dataclass
class UpdateConfig:
    """Configuration for which security features to enable."""
    use_https: bool = True
    verify_checksum: bool = True
    verify_signature: bool = True
    check_size_limit: bool = True
    prevent_rollback: bool = True
    use_timeouts: bool = True
    atomic_writes: bool = True
    allow_redirects: bool = False
    
    def describe(self) -> str:
        """Return a human-readable description of enabled features."""
        enabled = []
        if self.use_https:
            enabled.append("HTTPS")
        else:
            enabled.append("HTTP")
        if self.verify_checksum:
            enabled.append("checksum")
        if self.verify_signature:
            enabled.append("signature")
        if self.check_size_limit:
            enabled.append("size limits")
        if self.prevent_rollback:
            enabled.append("anti-rollback")
        if self.use_timeouts:
            enabled.append("timeouts")
        if self.atomic_writes:
            enabled.append("atomic writes")
        
        return ", ".join(enabled) if enabled else "NO SECURITY"


@dataclass(frozen=True)
class UpdateManifest:
    """Update manifest containing version info and payload metadata."""
    version: str
    payload_url: str
    sha256: str
    size: int
    signature_b64: Optional[str] = None


def _load_installed_version() -> str:
    """Read the currently installed version from disk."""
    if not os.path.exists(LOCAL_VERSION_FILE):
        return "0.0.0"
    
    try:
        with open(LOCAL_VERSION_FILE, "r", encoding="utf-8") as f:
            version = f.read().strip()
            return version if version else "0.0.0"
    except Exception as e:
        logger.warning(f"Could not read version file: {e}")
        return "0.0.0"


def _save_installed_version(version: str) -> None:
    """Persist the installed version to prevent rollback attacks."""
    try:
        with open(LOCAL_VERSION_FILE, "w", encoding="utf-8") as f:
            f.write(version)
        logger.info(f"Saved installed version: {version}")
    except Exception as e:
        logger.error(f"Failed to save version: {e}")


def _is_newer_version(candidate: str, current: str) -> bool:
    """Compare semantic version strings. Returns True if candidate > current."""
    def parse_version(v: str):
        try:
            return [int(x) for x in v.split(".") if x.isdigit()]
        except (ValueError, AttributeError):
            return [0]
    
    return parse_version(candidate) > parse_version(current)


def _canonical_manifest_bytes(manifest: UpdateManifest) -> bytes:
    """
    Create canonical JSON for signature verification.
    
    Deterministic serialization ensures signer and verifier produce
    identical byte sequences.
    """
    unsigned = {
        "version": manifest.version,
        "payload_url": manifest.payload_url,
        "sha256": manifest.sha256,
        "size": manifest.size,
    }
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")


def fetch_manifest(manifest_url: str, config: UpdateConfig) -> Optional[UpdateManifest]:
    """Download and parse the update manifest."""
    logger.info(f"Fetching manifest from: {manifest_url}")
    
    # Check HTTPS requirement
    if config.use_https and not manifest_url.startswith("https://"):
        raise ValueError("Manifest URL must use HTTPS")
    elif not config.use_https and not manifest_url.startswith("http"):
        raise ValueError("Invalid URL scheme")
    
    timeout = REQUEST_TIMEOUT if config.use_timeouts else None
    
    resp = requests.get(
        manifest_url,
        timeout=timeout,
        allow_redirects=config.allow_redirects,
        verify=True,  # Always verify SSL when using HTTPS
    )
    resp.raise_for_status()
    
    data = resp.json()
    
    # Required fields depend on whether we're verifying signatures
    required_fields = {"version", "payload_url", "sha256", "size"}
    if config.verify_signature:
        required_fields.add("signature")
    
    missing = required_fields - set(data.keys())
    if missing:
        raise ValueError(f"Manifest missing required fields: {missing}")
    
    return UpdateManifest(
        version=str(data["version"]),
        payload_url=str(data["payload_url"]),
        sha256=str(data["sha256"]).lower(),
        size=int(data["size"]),
        signature_b64=str(data.get("signature", "")),
    )


def verify_manifest_signature(manifest: UpdateManifest, public_key_b64: str) -> None:
    """
    Verify Ed25519 signature on the manifest using pinned public key.
    
    This is the critical security check. The signature proves:
    1. The manifest was created by someone with the private key
    2. The manifest hasn't been modified since signing
    
    Raises InvalidSignature if verification fails.
    """
    if not manifest.signature_b64:
        raise ValueError("Manifest has no signature")
    
    logger.info("Verifying manifest signature...")
    
    try:
        public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        signature = base64.b64decode(manifest.signature_b64)
        message = _canonical_manifest_bytes(manifest)
        
        public_key.verify(signature, message)
        logger.info("Signature valid - manifest is authentic")
    except InvalidSignature:
        logger.error("SIGNATURE INVALID - Possible MITM or compromised server!")
        raise
    except Exception as e:
        logger.error(f"Signature verification failed: {e}")
        raise


def _validate_payload_url(payload_url: str, require_https: bool) -> None:
    """Ensure payload URL is well-formed."""
    parsed = urlparse(payload_url)
    
    if require_https and parsed.scheme != "https":
        raise ValueError("Payload URL must use HTTPS")
    
    if not parsed.netloc:
        raise ValueError("Payload URL missing hostname")


def download_and_verify_payload(manifest: UpdateManifest, config: UpdateConfig) -> str:
    """
    Download update payload with streaming and verify integrity.
    
    Security measures applied based on config:
    - Stream download to handle large files efficiently
    - Enforce size limits (if enabled)
    - Verify SHA256 hash (if enabled)
    - Use atomic file operations (if enabled)
    - Prevent redirects (if enabled)
    
    Returns path to the verified payload file.
    """
    _validate_payload_url(manifest.payload_url, config.use_https)
    
    logger.info(f"Downloading payload from: {manifest.payload_url}")
    if config.verify_checksum:
        logger.info(f"Expected size: {manifest.size} bytes, SHA256: {manifest.sha256}")
    
    hasher = hashlib.sha256() if config.verify_checksum else None
    bytes_downloaded = 0
    
    timeout = REQUEST_TIMEOUT if config.use_timeouts else None
    
    with requests.get(
        manifest.payload_url,
        stream=True,
        timeout=timeout,
        allow_redirects=config.allow_redirects,
        verify=True,  # Always verify SSL when using HTTPS
    ) as response:
        response.raise_for_status()
        
        # Check Content-Length if size limits are enabled
        if config.check_size_limit:
            content_length = response.headers.get("Content-Length")
            if content_length:
                try:
                    declared_size = int(content_length)
                    if declared_size != manifest.size:
                        logger.warning(
                            f"Content-Length ({declared_size}) doesn't match "
                            f"manifest size ({manifest.size})"
                        )
                    if declared_size > MAX_UPDATE_BYTES:
                        raise ValueError(
                            f"Update too large: {declared_size} bytes "
                            f"(max: {MAX_UPDATE_BYTES})"
                        )
                except ValueError as e:
                    logger.warning(f"Content-Length validation: {e}")
        
        # Use atomic writes or direct write based on config
        if config.atomic_writes:
            fd, temp_path = tempfile.mkstemp(prefix="update_", suffix=".tmp")
            target_path = LOCAL_UPDATE_FILE
        else:
            # Write directly to target
            temp_path = LOCAL_UPDATE_FILE
            fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
            target_path = None
        
        try:
            with os.fdopen(fd, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if not chunk:
                        continue
                    
                    bytes_downloaded += len(chunk)
                    
                    if config.check_size_limit and bytes_downloaded > MAX_UPDATE_BYTES:
                        raise ValueError(
                            f"Update exceeds size limit: {MAX_UPDATE_BYTES} bytes"
                        )
                    
                    if hasher:
                        hasher.update(chunk)
                    f.write(chunk)
                
                f.flush()
                os.fsync(f.fileno())
            
            # Verify size if checking is enabled
            if config.check_size_limit and bytes_downloaded != manifest.size:
                raise ValueError(
                    f"Size mismatch: expected {manifest.size}, "
                    f"got {bytes_downloaded}"
                )
            
            # Verify hash if enabled
            if config.verify_checksum and hasher:
                actual_hash = hasher.hexdigest().lower()
                if actual_hash != manifest.sha256:
                    raise ValueError(
                        f"SHA256 mismatch: expected {manifest.sha256}, "
                        f"got {actual_hash}"
                    )
                logger.info(f"Checksum verified: {actual_hash}")
            
            logger.info(f"Payload downloaded: {bytes_downloaded} bytes")
            
            # Atomic replace if enabled
            if config.atomic_writes and target_path:
                os.replace(temp_path, target_path)
                return target_path
            else:
                return temp_path
        except Exception:
            # Clean up temp file on error (only if using atomic writes)
            if config.atomic_writes and temp_path != LOCAL_UPDATE_FILE:
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
            raise


def check_for_update(
    manifest_url: str = UPDATE_MANIFEST_URL,
    public_key_b64: str = PINNED_PUBKEY_B64,
    config: Optional[UpdateConfig] = None,
    demo_mode: bool = False
) -> bool:
    """
    Automatic mode selection based on security features:
    - If signature verification is DISABLED: Use direct URL mode (evolutionary demo)
    - If signature verification is ENABLED: Use manifest mode (full security)
    
    Args:
        manifest_url: URL to the update manifest (used only if verify_signature=True)
        public_key_b64: Base64-encoded Ed25519 public key for signature verification
        config: UpdateConfig specifying which security features to enable
        demo_mode: Enable verbose demo output
    
    Returns:
        True if update was downloaded successfully, False otherwise
    """
    if config is None:
        config = UpdateConfig()  # All security features enabled by default
    
    logger.info(f"🔐 Update check with features: {config.describe()}")
    
    # AUTOMATIC MODE SELECTION
    if not config.verify_signature:
        # Direct URL mode (Levels 0-2: No signature verification)
        logger.info("📦 Using DIRECT URL mode (no signature verification)")
        
        checksum_url = None
        if config.verify_checksum:
            checksum_url = UPDATE_URL + ".sha256"
            logger.info(f"   Will fetch checksum from: {checksum_url}")
        
        return direct_url_update(
            update_url=UPDATE_URL,
            checksum_url=checksum_url,
            config=config
        )
    
    # Manifest mode (Level 3: Full security with signatures)
    logger.info("📋 Using MANIFEST mode (signature verification enabled)")
    
    if public_key_b64 == "REPLACE_ME_WITH_YOUR_PUBLIC_KEY_BASE64":
        logger.error("❌ Public key not configured! Run publisher_tools/gen_keys.py first.")
        return False
    
    try:
        current_version = _load_installed_version()
        logger.info(f"Current version: {current_version}")
        
        manifest = fetch_manifest(manifest_url, config)
        if manifest is None:
            logger.error("Failed to fetch manifest")
            return False
        
        logger.info(f"Manifest version: {manifest.version}")
        
        if demo_mode:
            print(f"\n{'='*70}")
            print("DEMO MODE: Manifest Details")
            print(f"{'='*70}")
            print(f"Version:      {manifest.version}")
            print(f"Payload URL:  {manifest.payload_url}")
            print(f"SHA256:       {manifest.sha256}")
            print(f"Size:         {manifest.size} bytes")
            if manifest.signature_b64:
                print(f"Signature:    {manifest.signature_b64[:32]}...")
            print(f"Security:     {config.describe()}")
            print(f"{'='*70}\n")
        
        # Signature verification
        try:
            verify_manifest_signature(manifest, public_key_b64)
            if demo_mode:
                print("✅ SIGNATURE VERIFIED - Update is authentic!\n")
        except (InvalidSignature, ValueError) as e:
            if demo_mode:
                print("❌ SIGNATURE INVALID - Update rejected!\n")
                print("This proves the attacker cannot forge updates even if they")
                print("control the network or server - they don't have the private key!\n")
            raise RuntimeError(f"Manifest signature invalid: {e}")
        
        # Anti-rollback check (if enabled)
        if config.prevent_rollback:
            if not _is_newer_version(manifest.version, current_version):
                logger.info(
                    f"No newer version available "
                    f"(current: {current_version}, remote: {manifest.version})"
                )
                return False
        else:
            logger.warning("⚠️  Rollback protection DISABLED - downgrades allowed!")
        
        logger.info(f"Downloading version: {manifest.version}")
        
        payload_path = download_and_verify_payload(manifest, config)
        
        if config.prevent_rollback:
            _save_installed_version(manifest.version)
        
        logger.info(f"✅ Update {manifest.version} ready to apply: {payload_path}")
        return True
    except Exception as e:
        logger.exception(f"Update failed: {e}")
        return False


def apply_update(file_path: str) -> None:
    """
    Apply the downloaded update.
    
    In a real system, this would:
    - Verify the update one more time
    - Back up current version
    - Apply patches or replace binaries
    - Restart the application
    
    For this demo, we just read and log the content.
    """
    if not file_path or not os.path.exists(file_path):
        logger.error("No update file to apply")
        return
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        
        logger.info(f"Applying update from {file_path}")
        logger.debug(f"Update content preview:\n{content[:200]}")
        logger.info("Update applied successfully (simulated)")
    except Exception as e:
        logger.exception(f"Failed to apply update: {e}")


# Convenience functions for common security configurations
def insecure_update(update_url: str) -> bool:
    """
    Completely insecure update - all security features disabled.
    Demonstrates baseline vulnerability.
    """
    config = UpdateConfig(
        use_https=False,
        verify_checksum=False,
        verify_signature=False,
        check_size_limit=False,
        prevent_rollback=False,
        use_timeouts=False,
        atomic_writes=False,
        allow_redirects=True,
    )
    
    # For simple URL-based updates, create a minimal manifest
    manifest = UpdateManifest(
        version="unknown",
        payload_url=update_url,
        sha256="",
        size=0,
    )
    
    try:
        logger.warning("INSECURE: All security features disabled!")
        payload_path = download_and_verify_payload(manifest, config)
        logger.info(f"Update downloaded (INSECURE): {payload_path}")
        return True
    except Exception as e:
        logger.exception(f"Update failed: {e}")
        return False

def direct_url_update(
    update_url: str,
    checksum_url: Optional[str] = None,
    config: Optional[UpdateConfig] = None
) -> bool:
    """
    Direct URL update without manifest (evolutionary approach).
    
    This demonstrates the evolution of security:
    - Level 0: Just download from URL (no checksum)
    - Level 1: Add HTTPS
    - Level 2: Add checksum verification from separate .sha256 file
    - Level 3: Use manifest with signature (see check_for_update)
    
    Args:
        update_url: Direct URL to the update file
        checksum_url: Optional URL to .sha256 file (e.g., update_url + ".sha256")
        config: Security configuration
    
    Returns:
        True if update was downloaded successfully, False otherwise
    """
    if config is None:
        config = UpdateConfig()
    
    expected_sha256 = ""
    expected_size = 0
    
    # If checksum verification is enabled and checksum_url provided, fetch it
    if config.verify_checksum and checksum_url:
        try:
            logger.info(f"Fetching checksum from: {checksum_url}")
            timeout = REQUEST_TIMEOUT if config.use_timeouts else None
            resp = requests.get(checksum_url, timeout=timeout, verify=True)
            resp.raise_for_status()
            
            # Parse checksum file (format: "hash  filename")
            checksum_content = resp.text.strip()
            parts = checksum_content.split()
            if parts:
                expected_sha256 = parts[0].lower()
                logger.info(f"Expected SHA256: {expected_sha256}")
        except Exception as e:
            logger.error(f"Failed to fetch checksum: {e}")
            if config.verify_checksum:
                return False
    
    # Create a minimal manifest for the direct URL
    manifest = UpdateManifest(
        version="unknown",
        payload_url=update_url,
        sha256=expected_sha256,
        size=expected_size,
    )
    
    try:
        payload_path = download_and_verify_payload(manifest, config)
        logger.info(f"✓ Update downloaded: {payload_path}")
        return True
    except Exception as e:
        logger.exception(f"Update failed: {e}")
        return False



def https_only_update(update_url: str) -> bool:
    """
    HTTPS-only update - transport encryption but no integrity checks.
    Still vulnerable to compromised servers.
    """
    config = UpdateConfig(
        use_https=True,
        verify_checksum=False,
        verify_signature=False,
        check_size_limit=False,
        prevent_rollback=False,
        use_timeouts=True,
        atomic_writes=False,
        allow_redirects=False,
    )
    
    manifest = UpdateManifest(
        version="unknown",
        payload_url=update_url,
        sha256="",
        size=0,
    )
    
    try:
        logger.info("HTTPS-only (no integrity checks)")
        payload_path = download_and_verify_payload(manifest, config)
        logger.info(f"Update downloaded over HTTPS: {payload_path}")
        return True
    except Exception as e:
        logger.exception(f"Update failed: {e}")
        return False


def checksum_update(update_url: str, expected_sha256: str, size: int) -> bool:
    """
    HTTPS + checksum verification.
    Better than HTTPS-only but checksum comes from same source.
    """
    config = UpdateConfig(
        use_https=True,
        verify_checksum=True,
        verify_signature=False,
        check_size_limit=True,
        prevent_rollback=False,
        use_timeouts=True,
        atomic_writes=True,
        allow_redirects=False,
    )
    
    manifest = UpdateManifest(
        version="unknown",
        payload_url=update_url,
        sha256=expected_sha256,
        size=size,
    )
    
    try:
        logger.info("HTTPS + checksum verification")
        payload_path = download_and_verify_payload(manifest, config)
        logger.info(f"Update downloaded and verified: {payload_path}")
        return True
    except Exception as e:
        logger.exception(f"Update failed: {e}")
        return False


def secure_update(
    manifest_url: str = UPDATE_MANIFEST_URL,
    public_key_b64: str = PINNED_PUBKEY_B64
) -> bool:
    """
    Fully secure update with all protections enabled.
    This is the recommended configuration.
    """
    config = UpdateConfig(
        use_https=True,
        verify_checksum=True,
        verify_signature=True,
        check_size_limit=True,
        prevent_rollback=True,
        use_timeouts=True,
        atomic_writes=True,
        allow_redirects=False,
    )
    
    return check_for_update(manifest_url, public_key_b64, config)
