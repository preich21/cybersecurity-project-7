#!/usr/bin/env python3
"""
Comprehensive tests for the secure update mechanism.

Tests cover:
1. Unit tests for individual security features
2. End-to-end tests for complete update flows
3. Attack scenario tests (MITM, rollback, size bombs, etc.)
4. Configuration validation tests
"""

import base64
import hashlib
import json
import os
import tempfile
import pytest
from unittest.mock import Mock, patch, MagicMock
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import requests
from cryptography.hazmat.primitives import serialization

from cra_demo_app import secure_update
from cra_demo_app.secure_update import (
    UpdateConfig,
    UpdateManifest,
    fetch_manifest,
    verify_manifest_signature,
    download_and_verify_payload,
    check_for_update,
    _is_newer_version,
    _load_installed_version,
    _save_installed_version,
    _canonical_manifest_bytes,
    _validate_payload_url,
    direct_url_update,
)


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture
def temp_dir(tmp_path):
    """Create a temporary directory for test files."""
    return tmp_path


@pytest.fixture
def test_keypair():
    """Generate a test Ed25519 keypair for signature testing."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    return {
        'private_key': private_key,
        'public_key': public_key,
        'private_b64': base64.b64encode(private_bytes).decode('utf-8'),
        'public_b64': base64.b64encode(public_bytes).decode('utf-8'),
    }


@pytest.fixture
def sample_manifest():
    """Create a sample update manifest for testing."""
    return UpdateManifest(
        version="1.2.3",
        payload_url="https://example.com/update.bin",
        sha256="a" * 64,
        size=1024,
        signature_b64="dGVzdHNpZ25hdHVyZQ=="
    )


@pytest.fixture
def mock_response():
    """Create a mock HTTP response."""
    mock = Mock()
    mock.status_code = 200
    mock.headers = {}
    mock.raise_for_status = Mock()
    return mock


@pytest.fixture(autouse=True)
def cleanup_test_files():
    """Clean up test files after each test."""
    yield
    # Clean up any test files created
    for file in [secure_update.LOCAL_UPDATE_FILE, secure_update.LOCAL_VERSION_FILE]:
        if os.path.exists(file):
            try:
                os.remove(file)
            except OSError:
                pass


# ============================================================================
# Unit Tests - Version Management
# ============================================================================

class TestVersionManagement:
    """Test version comparison and storage."""
    
    def test_is_newer_version_basic(self):
        """Test basic version comparison."""
        assert _is_newer_version("1.2.3", "1.2.2") is True
        assert _is_newer_version("1.3.0", "1.2.9") is True
        assert _is_newer_version("2.0.0", "1.9.9") is True
        
    def test_is_newer_version_equal(self):
        """Test that equal versions return False."""
        assert _is_newer_version("1.2.3", "1.2.3") is False
        
    def test_is_newer_version_older(self):
        """Test that older versions return False."""
        assert _is_newer_version("1.2.2", "1.2.3") is False
        assert _is_newer_version("1.2.9", "1.3.0") is False
        
    def test_is_newer_version_invalid(self):
        """Test handling of invalid version strings."""
        # Should handle gracefully
        assert _is_newer_version("1.2.3", "invalid") is True
        assert _is_newer_version("invalid", "1.2.3") is False
        
    def test_save_and_load_version(self, temp_dir):
        """Test saving and loading version from disk."""
        # Change to temp directory
        original_cwd = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            # Save version
            _save_installed_version("1.2.3")
            
            # Load version
            loaded = _load_installed_version()
            assert loaded == "1.2.3"
        finally:
            os.chdir(original_cwd)
            
    def test_load_version_no_file(self, temp_dir):
        """Test loading version when file doesn't exist."""
        original_cwd = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            version = _load_installed_version()
            assert version == "0.0.0"
        finally:
            os.chdir(original_cwd)


# ============================================================================
# Unit Tests - Configuration
# ============================================================================

class TestUpdateConfig:
    """Test UpdateConfig dataclass."""
    
    def test_default_config_all_secure(self):
        """Test that default config has all security features enabled."""
        config = UpdateConfig()
        assert config.use_https is True
        assert config.verify_checksum is True
        assert config.verify_signature is True
        assert config.check_size_limit is True
        assert config.prevent_rollback is True
        assert config.use_timeouts is True
        assert config.atomic_writes is True
        assert config.allow_redirects is False
        
    def test_insecure_config(self):
        """Test creating completely insecure config."""
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
        assert config.use_https is False
        assert config.verify_checksum is False
        
    def test_config_describe(self):
        """Test config description generation."""
        config = UpdateConfig()
        description = config.describe()
        assert "HTTPS" in description
        assert "checksum" in description
        assert "signature" in description
        
    def test_config_describe_insecure(self):
        """Test description for insecure config."""
        config = UpdateConfig(
            use_https=False,
            verify_checksum=False,
            verify_signature=False,
            check_size_limit=False,
            prevent_rollback=False,
            use_timeouts=False,
            atomic_writes=False,
        )
        description = config.describe()
        assert "HTTP" in description


# ============================================================================
# Unit Tests - Manifest Operations
# ============================================================================

class TestManifestOperations:
    """Test manifest fetching and validation."""
    
    def test_canonical_manifest_bytes(self, sample_manifest):
        """Test canonical JSON serialization for signatures."""
        canonical = _canonical_manifest_bytes(sample_manifest)
        
        # Should be valid JSON
        data = json.loads(canonical)
        assert data["version"] == "1.2.3"
        assert data["payload_url"] == "https://example.com/update.bin"
        assert "signature" not in data  # Signature excluded from canonical form
        
    def test_canonical_manifest_deterministic(self, sample_manifest):
        """Test that canonical form is deterministic."""
        canonical1 = _canonical_manifest_bytes(sample_manifest)
        canonical2 = _canonical_manifest_bytes(sample_manifest)
        assert canonical1 == canonical2
        
    @patch('requests.get')
    def test_fetch_manifest_success(self, mock_get, mock_response):
        """Test successful manifest fetch."""
        mock_response.json.return_value = {
            "version": "1.2.3",
            "payload_url": "https://example.com/update.bin",
            "sha256": "a" * 64,
            "size": 1024,
            "signature": "dGVzdA=="
        }
        mock_get.return_value = mock_response
        
        config = UpdateConfig()
        manifest = fetch_manifest("https://example.com/manifest.json", config)
        
        assert manifest.version == "1.2.3"
        assert manifest.size == 1024
        
    @patch('requests.get')
    def test_fetch_manifest_requires_https(self, mock_get):
        """Test that HTTPS is enforced when configured."""
        config = UpdateConfig(use_https=True)
        
        with pytest.raises(ValueError, match="must use HTTPS"):
            fetch_manifest("http://example.com/manifest.json", config)
            
    @patch('requests.get')
    def test_fetch_manifest_allows_http_when_disabled(self, mock_get, mock_response):
        """Test that HTTP is allowed when HTTPS check is disabled."""
        mock_response.json.return_value = {
            "version": "1.2.3",
            "payload_url": "http://example.com/update.bin",
            "sha256": "a" * 64,
            "size": 1024,
        }
        mock_get.return_value = mock_response
        
        config = UpdateConfig(use_https=False, verify_signature=False)
        manifest = fetch_manifest("http://example.com/manifest.json", config)
        
        assert manifest is not None
        
    @patch('requests.get')
    def test_fetch_manifest_missing_fields(self, mock_get, mock_response):
        """Test that missing required fields raise error."""
        mock_response.json.return_value = {
            "version": "1.2.3",
            # Missing payload_url, sha256, size
        }
        mock_get.return_value = mock_response
        
        config = UpdateConfig()
        with pytest.raises(ValueError, match="missing required fields"):
            fetch_manifest("https://example.com/manifest.json", config)
            
    @patch('requests.get')
    def test_fetch_manifest_timeout(self, mock_get):
        """Test that timeout is applied when configured."""
        config = UpdateConfig(use_timeouts=True)
        mock_response = Mock()
        mock_response.json.return_value = {
            "version": "1.2.3",
            "payload_url": "https://example.com/update.bin",
            "sha256": "a" * 64,
            "size": 1024,
            "signature": "dGVzdA=="
        }
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        fetch_manifest("https://example.com/manifest.json", config)
        
        # Verify timeout was passed
        call_kwargs = mock_get.call_args[1]
        assert call_kwargs['timeout'] == secure_update.REQUEST_TIMEOUT


# ============================================================================
# Unit Tests - Signature Verification
# ============================================================================

class TestSignatureVerification:
    """Test cryptographic signature verification."""
    
    def test_verify_signature_valid(self):
        """Test verification of valid signature."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        
        # Generate keypair
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        # Create manifest
        manifest = UpdateManifest(
            version="1.2.3",
            payload_url="https://example.com/update.bin",
            sha256="a" * 64,
            size=1024,
        )
        
        # Sign manifest
        message = _canonical_manifest_bytes(manifest)
        signature = private_key.sign(message)
        
        # Create signed manifest
        signed_manifest = UpdateManifest(
            version=manifest.version,
            payload_url=manifest.payload_url,
            sha256=manifest.sha256,
            size=manifest.size,
            signature_b64=base64.b64encode(signature).decode('utf-8')
        )
        
        # Get public key as base64
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        public_b64 = base64.b64encode(public_bytes).decode('utf-8')
        
        # Should not raise
        verify_manifest_signature(signed_manifest, public_b64)
        
    def test_verify_signature_invalid(self):
        """Test that invalid signature is rejected."""
        from cryptography.exceptions import InvalidSignature
        
        manifest = UpdateManifest(
            version="1.2.3",
            payload_url="https://example.com/update.bin",
            sha256="a" * 64,
            size=1024,
            signature_b64=base64.b64encode(b"invalid_signature").decode('utf-8')
        )
        
        # Use the pinned public key
        with pytest.raises(Exception):  # Will raise InvalidSignature or similar
            verify_manifest_signature(manifest, secure_update.PINNED_PUBKEY_B64)
            
    def test_verify_signature_missing(self):
        """Test that missing signature raises error."""
        manifest = UpdateManifest(
            version="1.2.3",
            payload_url="https://example.com/update.bin",
            sha256="a" * 64,
            size=1024,
            signature_b64=None
        )
        
        with pytest.raises(ValueError, match="no signature"):
            verify_manifest_signature(manifest, secure_update.PINNED_PUBKEY_B64)


# ============================================================================
# Unit Tests - Payload Download
# ============================================================================

class TestPayloadDownload:
    """Test payload download and verification."""
    
    def test_validate_payload_url_https_required(self):
        """Test that HTTPS is enforced for payload URLs."""
        with pytest.raises(ValueError, match="must use HTTPS"):
            _validate_payload_url("http://example.com/update.bin", require_https=True)
            
    def test_validate_payload_url_https_valid(self):
        """Test that valid HTTPS URL passes."""
        # Should not raise
        _validate_payload_url("https://example.com/update.bin", require_https=True)
        
    def test_validate_payload_url_missing_hostname(self):
        """Test that URL without hostname is rejected."""
        with pytest.raises(ValueError, match="missing hostname"):
            _validate_payload_url("https:///update.bin", require_https=True)
            
    @patch('requests.get')
    def test_download_payload_checksum_verification(self, mock_get, temp_dir):
        """Test that checksum is verified when enabled."""
        # Create test payload
        payload_content = b"test update content"
        expected_hash = hashlib.sha256(payload_content).hexdigest()
        
        # Mock response
        mock_response = Mock()
        mock_response.headers = {"Content-Length": str(len(payload_content))}
        mock_response.iter_content = Mock(return_value=[payload_content])
        mock_response.raise_for_status = Mock()
        mock_get.return_value.__enter__ = Mock(return_value=mock_response)
        mock_get.return_value.__exit__ = Mock(return_value=False)
        
        manifest = UpdateManifest(
            version="1.2.3",
            payload_url="https://example.com/update.bin",
            sha256=expected_hash,
            size=len(payload_content),
        )
        
        config = UpdateConfig(verify_checksum=True, atomic_writes=False)
        
        # Change to temp directory
        original_cwd = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            path = download_and_verify_payload(manifest, config)
            assert os.path.exists(path)
        finally:
            os.chdir(original_cwd)
            
    @patch('requests.get')
    def test_download_payload_checksum_mismatch(self, mock_get, temp_dir):
        """Test that checksum mismatch raises error."""
        payload_content = b"test update content"
        wrong_hash = "a" * 64  # Wrong hash
        
        mock_response = Mock()
        mock_response.headers = {"Content-Length": str(len(payload_content))}
        mock_response.iter_content = Mock(return_value=[payload_content])
        mock_response.raise_for_status = Mock()
        mock_get.return_value.__enter__ = Mock(return_value=mock_response)
        mock_get.return_value.__exit__ = Mock(return_value=False)
        
        manifest = UpdateManifest(
            version="1.2.3",
            payload_url="https://example.com/update.bin",
            sha256=wrong_hash,
            size=len(payload_content),
        )
        
        config = UpdateConfig(verify_checksum=True, atomic_writes=False)
        
        original_cwd = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            with pytest.raises(ValueError, match="SHA256 mismatch"):
                download_and_verify_payload(manifest, config)
        finally:
            os.chdir(original_cwd)
            
    @patch('requests.get')
    def test_download_payload_size_limit(self, mock_get, temp_dir):
        """Test that size limit is enforced."""
        # Create payload larger than limit
        large_payload = b"x" * (secure_update.MAX_UPDATE_BYTES + 1)
        
        mock_response = Mock()
        mock_response.headers = {"Content-Length": str(len(large_payload))}
        mock_response.iter_content = Mock(return_value=[large_payload])
        mock_response.raise_for_status = Mock()
        mock_get.return_value.__enter__ = Mock(return_value=mock_response)
        mock_get.return_value.__exit__ = Mock(return_value=False)
        
        manifest = UpdateManifest(
            version="1.2.3",
            payload_url="https://example.com/update.bin",
            sha256="a" * 64,
            size=len(large_payload),
        )
        
        config = UpdateConfig(check_size_limit=True, verify_checksum=False)
        
        original_cwd = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            with pytest.raises(ValueError, match="(too large|exceeds size limit)"):
                download_and_verify_payload(manifest, config)
        finally:
            os.chdir(original_cwd)
            
    @patch('requests.get')
    def test_download_payload_atomic_writes(self, mock_get, temp_dir):
        """Test that atomic writes use temporary file."""
        payload_content = b"test content"
        
        mock_response = Mock()
        mock_response.headers = {}
        mock_response.iter_content = Mock(return_value=[payload_content])
        mock_response.raise_for_status = Mock()
        mock_get.return_value.__enter__ = Mock(return_value=mock_response)
        mock_get.return_value.__exit__ = Mock(return_value=False)
        
        manifest = UpdateManifest(
            version="1.2.3",
            payload_url="https://example.com/update.bin",
            sha256=hashlib.sha256(payload_content).hexdigest(),
            size=len(payload_content),
        )
        
        config = UpdateConfig(atomic_writes=True, verify_checksum=True)
        
        original_cwd = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            path = download_and_verify_payload(manifest, config)
            # Should return the final path, not temp path
            assert path == secure_update.LOCAL_UPDATE_FILE
            assert os.path.exists(path)
        finally:
            os.chdir(original_cwd)


# ============================================================================
# Unit Tests - Direct URL Update
# ============================================================================

class TestDirectURLUpdate:
    """Test direct URL update mode (without manifest)."""
    
    @patch('requests.get')
    def test_direct_url_update_no_checksum(self, mock_get, temp_dir):
        """Test direct URL update without checksum verification."""
        payload_content = b"update content"
        
        # Mock payload download
        mock_response = Mock()
        mock_response.headers = {}
        mock_response.iter_content = Mock(return_value=[payload_content])
        mock_response.raise_for_status = Mock()
        mock_get.return_value.__enter__ = Mock(return_value=mock_response)
        mock_get.return_value.__exit__ = Mock(return_value=False)
        
        config = UpdateConfig(
            verify_checksum=False,
            verify_signature=False,
            atomic_writes=False,
            check_size_limit=False  # Disable size check since we're not providing size
        )
        
        original_cwd = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            result = direct_url_update(
                "https://example.com/update.bin",
                checksum_url=None,
                config=config
            )
            assert result is True
        finally:
            os.chdir(original_cwd)
            
    @patch('requests.get')
    def test_direct_url_update_with_checksum(self, mock_get, temp_dir):
        """Test direct URL update with separate checksum file."""
        payload_content = b"update content"
        expected_hash = hashlib.sha256(payload_content).hexdigest()
        
        # Mock checksum fetch
        checksum_response = Mock()
        checksum_response.text = f"{expected_hash}  update.bin"
        checksum_response.raise_for_status = Mock()
        
        # Mock payload download
        payload_response = Mock()
        payload_response.headers = {}
        payload_response.iter_content = Mock(return_value=[payload_content])
        payload_response.raise_for_status = Mock()
        
        # Setup mock to return different responses
        mock_get.side_effect = [
            checksum_response,  # First call for checksum
            Mock(__enter__=Mock(return_value=payload_response), __exit__=Mock(return_value=False))  # Second call for payload
        ]
        
        config = UpdateConfig(
            verify_checksum=True,
            verify_signature=False,
            atomic_writes=False,
            check_size_limit=False  # Disable size check since we're not providing size
        )
        
        original_cwd = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            result = direct_url_update(
                "https://example.com/update.bin",
                checksum_url="https://example.com/update.bin.sha256",
                config=config
            )
            assert result is True
        finally:
            os.chdir(original_cwd)


# ============================================================================
# End-to-End Tests
# ============================================================================

class TestE2EUpdateFlow:
    """End-to-end tests for complete update flows."""
    
    @patch('cra_demo_app.secure_update.fetch_manifest')
    @patch('cra_demo_app.secure_update.verify_manifest_signature')
    @patch('cra_demo_app.secure_update.download_and_verify_payload')
    def test_e2e_secure_update_success(self, mock_download, mock_verify, mock_fetch, temp_dir):
        """Test complete secure update flow with all security features."""
        # Setup mocks
        manifest = UpdateManifest(
            version="2.0.0",
            payload_url="https://example.com/update.bin",
            sha256="a" * 64,
            size=1024,
            signature_b64="dGVzdA=="
        )
        mock_fetch.return_value = manifest
        mock_verify.return_value = None  # Success
        mock_download.return_value = secure_update.LOCAL_UPDATE_FILE
        
        config = UpdateConfig()  # All security enabled
        
        original_cwd = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            # Set initial version
            _save_installed_version("1.0.0")
            
            result = check_for_update(
                manifest_url="https://example.com/manifest.json",
                public_key_b64=secure_update.PINNED_PUBKEY_B64,
                config=config
            )
            
            assert result is True
            mock_fetch.assert_called_once()
            mock_verify.assert_called_once()
            mock_download.assert_called_once()
        finally:
            os.chdir(original_cwd)
            
    @patch('cra_demo_app.secure_update.fetch_manifest')
    @patch('cra_demo_app.secure_update.verify_manifest_signature')
    def test_e2e_update_signature_failure(self, mock_verify, mock_fetch, temp_dir):
        """Test that update is rejected when signature verification fails."""
        from cryptography.exceptions import InvalidSignature
        
        manifest = UpdateManifest(
            version="2.0.0",
            payload_url="https://example.com/update.bin",
            sha256="a" * 64,
            size=1024,
            signature_b64="invalid"
        )
        mock_fetch.return_value = manifest
        mock_verify.side_effect = InvalidSignature("Invalid signature")
        
        config = UpdateConfig()
        
        original_cwd = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            result = check_for_update(
                manifest_url="https://example.com/manifest.json",
                public_key_b64=secure_update.PINNED_PUBKEY_B64,
                config=config
            )
            
            assert result is False
        finally:
            os.chdir(original_cwd)
            
    @patch('cra_demo_app.secure_update.fetch_manifest')
    @patch('cra_demo_app.secure_update.verify_manifest_signature')
    def test_e2e_rollback_protection(self, mock_verify, mock_fetch, temp_dir):
        """Test that rollback to older version is prevented."""
        manifest = UpdateManifest(
            version="1.0.0",  # Older version
            payload_url="https://example.com/update.bin",
            sha256="a" * 64,
            size=1024,
            signature_b64="dGVzdA=="
        )
        mock_fetch.return_value = manifest
        mock_verify.return_value = None
        
        config = UpdateConfig(prevent_rollback=True)
        
        original_cwd = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            # Set current version to newer
            _save_installed_version("2.0.0")
            
            result = check_for_update(
                manifest_url="https://example.com/manifest.json",
                public_key_b64=secure_update.PINNED_PUBKEY_B64,
                config=config
            )
            
            # Should reject older version
            assert result is False
        finally:
            os.chdir(original_cwd)
            
    @patch('requests.get')
    def test_e2e_direct_url_mode(self, mock_get, temp_dir):
        """Test direct URL mode (no signature verification)."""
        payload_content = b"update content"
        
        mock_response = Mock()
        mock_response.headers = {}
        mock_response.iter_content = Mock(return_value=[payload_content])
        mock_response.raise_for_status = Mock()
        mock_get.return_value.__enter__ = Mock(return_value=mock_response)
        mock_get.return_value.__exit__ = Mock(return_value=False)
        
        config = UpdateConfig(
            use_https=False,  # Allow HTTP since UPDATE_URL uses http
            verify_signature=False,  # Triggers direct URL mode
            verify_checksum=False,
            atomic_writes=False,
            check_size_limit=False
        )
        
        original_cwd = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            result = check_for_update(config=config)
            assert result is True
        finally:
            os.chdir(original_cwd)


# ============================================================================
# Attack Scenario Tests
# ============================================================================

class TestAttackScenarios:
    """Test protection against various attack scenarios."""
    
    @patch('requests.get')
    def test_mitm_attack_checksum_mismatch(self, mock_get, temp_dir):
        """Test that MITM attack is detected via checksum mismatch."""
        # Attacker modifies payload
        legitimate_content = b"legitimate update"
        malicious_content = b"malicious payload"
        legitimate_hash = hashlib.sha256(legitimate_content).hexdigest()
        
        # Mock returns malicious content
        mock_response = Mock()
        mock_response.headers = {}
        mock_response.iter_content = Mock(return_value=[malicious_content])
        mock_response.raise_for_status = Mock()
        mock_get.return_value.__enter__ = Mock(return_value=mock_response)
        mock_get.return_value.__exit__ = Mock(return_value=False)
        
        manifest = UpdateManifest(
            version="1.2.3",
            payload_url="https://example.com/update.bin",
            sha256=legitimate_hash,  # Hash of legitimate content
            size=len(legitimate_content),
        )
        
        config = UpdateConfig(verify_checksum=True, atomic_writes=False)
        
        original_cwd = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            with pytest.raises(ValueError, match="SHA256 mismatch"):
                download_and_verify_payload(manifest, config)
        finally:
            os.chdir(original_cwd)
            
    @patch('requests.get')
    def test_size_bomb_attack(self, mock_get, temp_dir):
        """Test protection against size bomb attacks."""
        # Attacker claims small size but sends huge payload
        def generate_huge_chunks():
            # Generate chunks that exceed size limit
            chunk_size = 8192
            total_sent = 0
            while total_sent < secure_update.MAX_UPDATE_BYTES + chunk_size:
                yield b"x" * chunk_size
                total_sent += chunk_size
        
        mock_response = Mock()
        mock_response.headers = {"Content-Length": "1024"}  # Lies about size
        mock_response.iter_content = Mock(return_value=generate_huge_chunks())
        mock_response.raise_for_status = Mock()
        mock_get.return_value.__enter__ = Mock(return_value=mock_response)
        mock_get.return_value.__exit__ = Mock(return_value=False)
        
        manifest = UpdateManifest(
            version="1.2.3",
            payload_url="https://example.com/update.bin",
            sha256="a" * 64,
            size=1024,  # Claims small size
        )
        
        config = UpdateConfig(check_size_limit=True, verify_checksum=False)
        
        original_cwd = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            with pytest.raises(ValueError, match="exceeds size limit"):
                download_and_verify_payload(manifest, config)
        finally:
            os.chdir(original_cwd)
            
    @patch('cra_demo_app.secure_update.fetch_manifest')
    @patch('cra_demo_app.secure_update.verify_manifest_signature')
    def test_rollback_attack(self, mock_verify, mock_fetch, temp_dir):
        """Test protection against rollback attacks."""
        # Attacker tries to force downgrade to vulnerable version
        old_manifest = UpdateManifest(
            version="0.9.0",  # Old vulnerable version
            payload_url="https://example.com/update.bin",
            sha256="a" * 64,
            size=1024,
            signature_b64="dGVzdA=="
        )
        mock_fetch.return_value = old_manifest
        mock_verify.return_value = None
        
        config = UpdateConfig(prevent_rollback=True)
        
        original_cwd = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            # Current version is newer
            _save_installed_version("1.5.0")
            
            result = check_for_update(
                manifest_url="https://example.com/manifest.json",
                public_key_b64=secure_update.PINNED_PUBKEY_B64,
                config=config
            )
            
            # Should reject downgrade
            assert result is False
            
            # Verify version wasn't changed
            assert _load_installed_version() == "1.5.0"
        finally:
            os.chdir(original_cwd)
            
    @patch('requests.get')
    def test_redirect_attack(self, mock_get):
        """Test that redirects are blocked when configured."""
        config = UpdateConfig(allow_redirects=False)
        
        # Mock response
        mock_response = Mock()
        mock_response.json.return_value = {
            "version": "1.2.3",
            "payload_url": "https://example.com/update.bin",
            "sha256": "a" * 64,
            "size": 1024,
            "signature": "dGVzdA=="
        }
        mock_response.raise_for_status = Mock()
        mock_get.return_value = mock_response
        
        fetch_manifest("https://example.com/manifest.json", config)
        
        # Verify redirects were disabled
        call_kwargs = mock_get.call_args[1]
        assert call_kwargs['allow_redirects'] is False
        
    def test_http_downgrade_attack(self):
        """Test that HTTP is rejected when HTTPS is required."""
        config = UpdateConfig(use_https=True)
        
        with pytest.raises(ValueError, match="must use HTTPS"):
            fetch_manifest("http://example.com/manifest.json", config)


# ============================================================================
# Integration Tests with CLI
# ============================================================================

class TestCLIIntegration:
    """Test integration with CLI module."""
    
    def test_configure_update_security(self):
        """Test that CLI properly configures update security."""
        from cra_demo_app.cli import configure_update_security
        
        # Create mock args
        args = Mock()
        args.use_https = True
        args.verify_checksum = True
        args.verify_signature = True
        args.check_size_limit = True
        args.prevent_rollback = True
        args.use_timeouts = True
        args.atomic_writes = True
        args.allow_redirects = False
        
        configure_update_security(args)
        
        from cra_demo_app.cli import UPDATE_SECURITY_CONFIG
        assert UPDATE_SECURITY_CONFIG is not None
        assert UPDATE_SECURITY_CONFIG.use_https is True
        assert UPDATE_SECURITY_CONFIG.verify_signature is True


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])

# Made with Bob
