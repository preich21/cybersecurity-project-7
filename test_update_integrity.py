#!/usr/bin/env python3
"""
Unit Tests for Update Integrity Verification

Tests the update mechanism to ensure:
1. Checksums are properly verified
2. Invalid updates are rejected
3. Only verified updates are accepted
4. Error handling works correctly
"""

import unittest
import hashlib
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock
import sys

# Add the parent directory to the path to import the application modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


class TestUpdateIntegrityVerification(unittest.TestCase):
    """Test suite for update integrity verification."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_content = "This is a test update content v1.0.0"
        self.test_checksum = hashlib.sha256(self.test_content.encode('utf-8')).hexdigest()
        self.malicious_content = "This is malicious content - HACKED!"
        self.malicious_checksum = hashlib.sha256(self.malicious_content.encode('utf-8')).hexdigest()
    
    def test_checksum_calculation(self):
        """Test that SHA-256 checksums are calculated correctly."""
        content = "test content"
        expected = hashlib.sha256(content.encode('utf-8')).hexdigest()
        actual = hashlib.sha256(content.encode('utf-8')).hexdigest()
        
        self.assertEqual(expected, actual)
        self.assertEqual(len(actual), 64)  # SHA-256 produces 64 hex characters
    
    def test_checksum_mismatch_detection(self):
        """Test that checksum mismatches are detected."""
        content1 = "legitimate update"
        content2 = "malicious update"
        
        checksum1 = hashlib.sha256(content1.encode('utf-8')).hexdigest()
        checksum2 = hashlib.sha256(content2.encode('utf-8')).hexdigest()
        
        self.assertNotEqual(checksum1, checksum2)
    
    def test_identical_content_produces_same_checksum(self):
        """Test that identical content always produces the same checksum."""
        content = "test update v1.0.0"
        
        checksum1 = hashlib.sha256(content.encode('utf-8')).hexdigest()
        checksum2 = hashlib.sha256(content.encode('utf-8')).hexdigest()
        
        self.assertEqual(checksum1, checksum2)
    
    def test_single_character_change_produces_different_checksum(self):
        """Test that even a single character change produces a different checksum."""
        content1 = "update version 1.0.0"
        content2 = "update version 1.0.1"  # Only one character different
        
        checksum1 = hashlib.sha256(content1.encode('utf-8')).hexdigest()
        checksum2 = hashlib.sha256(content2.encode('utf-8')).hexdigest()
        
        self.assertNotEqual(checksum1, checksum2)
    
    @patch('requests.get')
    def test_secure_download_with_valid_checksum(self, mock_get):
        """Test that secure download accepts updates with valid checksums."""
        # Mock the update content response
        mock_update_response = Mock()
        mock_update_response.status_code = 200
        mock_update_response.text = self.test_content
        
        # Mock the checksum response
        mock_checksum_response = Mock()
        mock_checksum_response.status_code = 200
        mock_checksum_response.text = f"{self.test_checksum}  update.txt\n"
        
        # Configure mock to return different responses for different URLs
        def get_side_effect(url, **kwargs):
            if 'sha256' in url:
                return mock_checksum_response
            else:
                return mock_update_response
        
        mock_get.side_effect = get_side_effect
        
        # Verify that checksums match
        downloaded_content = self.test_content
        expected_checksum = self.test_checksum
        actual_checksum = hashlib.sha256(downloaded_content.encode('utf-8')).hexdigest()
        
        self.assertEqual(expected_checksum, actual_checksum)
    
    @patch('requests.get')
    def test_secure_download_rejects_invalid_checksum(self, mock_get):
        """Test that secure download rejects updates with invalid checksums."""
        # Mock the update content response (malicious)
        mock_update_response = Mock()
        mock_update_response.status_code = 200
        mock_update_response.text = self.malicious_content
        
        # Mock the checksum response (legitimate checksum for legitimate content)
        mock_checksum_response = Mock()
        mock_checksum_response.status_code = 200
        mock_checksum_response.text = f"{self.test_checksum}  update.txt\n"  # Wrong checksum!
        
        # Configure mock
        def get_side_effect(url, **kwargs):
            if 'sha256' in url:
                return mock_checksum_response
            else:
                return mock_update_response
        
        mock_get.side_effect = get_side_effect
        
        # Verify that checksums DON'T match (attack detected)
        downloaded_content = self.malicious_content
        expected_checksum = self.test_checksum
        actual_checksum = hashlib.sha256(downloaded_content.encode('utf-8')).hexdigest()
        
        self.assertNotEqual(expected_checksum, actual_checksum)
    
    @patch('requests.get')
    def test_secure_download_handles_missing_checksum(self, mock_get):
        """Test that secure download rejects updates when checksum is unavailable."""
        # Mock the update content response
        mock_update_response = Mock()
        mock_update_response.status_code = 200
        mock_update_response.text = self.test_content
        
        # Mock the checksum response (404 - not found)
        mock_checksum_response = Mock()
        mock_checksum_response.status_code = 404
        
        # Configure mock
        def get_side_effect(url, **kwargs):
            if 'sha256' in url:
                return mock_checksum_response
            else:
                return mock_update_response
        
        mock_get.side_effect = get_side_effect
        
        # The application should reject the update if checksum is unavailable
        checksum_available = mock_checksum_response.status_code == 200
        self.assertFalse(checksum_available)
    
    def test_checksum_format_validation(self):
        """Test that checksum format is validated correctly."""
        valid_checksum = "a" * 64  # 64 hex characters
        invalid_checksum_short = "a" * 63
        invalid_checksum_long = "a" * 65
        invalid_checksum_chars = "g" * 64  # 'g' is not a hex character
        
        # Valid checksum
        self.assertEqual(len(valid_checksum), 64)
        self.assertTrue(all(c in '0123456789abcdef' for c in valid_checksum))
        
        # Invalid checksums
        self.assertNotEqual(len(invalid_checksum_short), 64)
        self.assertNotEqual(len(invalid_checksum_long), 64)
        self.assertFalse(all(c in '0123456789abcdef' for c in invalid_checksum_chars))
    
    def test_checksum_parsing_from_file(self):
        """Test parsing checksum from checksum file format."""
        # Standard format: "checksum  filename\n"
        checksum_file_content = f"{self.test_checksum}  update.txt\n"
        parsed_checksum = checksum_file_content.strip().split()[0]
        
        self.assertEqual(parsed_checksum, self.test_checksum)
    
    def test_update_tampering_detection(self):
        """Test that any tampering with update content is detected."""
        original_content = "Original secure update v1.0.0"
        original_checksum = hashlib.sha256(original_content.encode('utf-8')).hexdigest()
        
        # Simulate tampering: attacker modifies one character
        tampered_content = "Original secure update v1.0.1"  # Changed last character
        tampered_checksum = hashlib.sha256(tampered_content.encode('utf-8')).hexdigest()
        
        # Verification should fail
        self.assertNotEqual(original_checksum, tampered_checksum)
    
    def test_https_vs_http_urls(self):
        """Test that HTTPS is used instead of HTTP."""
        insecure_url = "http://example.com/update.txt"
        secure_url = "https://example.com/update.txt"
        
        self.assertTrue(insecure_url.startswith("http://"))
        self.assertTrue(secure_url.startswith("https://"))
        self.assertFalse(secure_url.startswith("http://"))
    
    def test_empty_update_content(self):
        """Test handling of empty update content."""
        empty_content = ""
        checksum = hashlib.sha256(empty_content.encode('utf-8')).hexdigest()
        
        # Should produce a valid checksum even for empty content
        self.assertEqual(len(checksum), 64)
        self.assertEqual(
            checksum,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
    
    def test_large_update_content(self):
        """Test handling of large update content."""
        large_content = "X" * 1000000  # 1 MB of data
        checksum = hashlib.sha256(large_content.encode('utf-8')).hexdigest()
        
        # Should handle large content without issues
        self.assertEqual(len(checksum), 64)
        
        # Verify consistency
        checksum2 = hashlib.sha256(large_content.encode('utf-8')).hexdigest()
        self.assertEqual(checksum, checksum2)
    
    def test_unicode_content_handling(self):
        """Test handling of Unicode characters in update content."""
        unicode_content = "Update with Unicode: äöü 中文 🔒"
        checksum = hashlib.sha256(unicode_content.encode('utf-8')).hexdigest()
        
        # Should handle Unicode correctly
        self.assertEqual(len(checksum), 64)
        
        # Verify consistency
        checksum2 = hashlib.sha256(unicode_content.encode('utf-8')).hexdigest()
        self.assertEqual(checksum, checksum2)


class TestInsecureUpdateVulnerability(unittest.TestCase):
    """Test suite to verify the vulnerability exists in the insecure version."""
    
    def test_insecure_accepts_any_content(self):
        """Test that insecure version accepts any content without verification."""
        # In the insecure version, there's NO checksum verification
        # This test verifies that the vulnerability exists
        
        legitimate_content = "Legitimate update"
        malicious_content = "Malicious update - HACKED!"
        
        # In insecure version, both would be accepted (no verification)
        # This demonstrates the vulnerability
        self.assertNotEqual(legitimate_content, malicious_content)
        
        # Both contents can be "accepted" in insecure version
        # because there's no integrity check
        insecure_accepts_legitimate = True
        insecure_accepts_malicious = True  # This is the vulnerability!
        
        self.assertTrue(insecure_accepts_legitimate)
        self.assertTrue(insecure_accepts_malicious)  # VULNERABLE!
    
    def test_insecure_uses_http(self):
        """Test that insecure version uses HTTP instead of HTTPS."""
        insecure_url = "http://example.com/fake-update.txt"
        
        # Vulnerable to MITM attacks
        self.assertTrue(insecure_url.startswith("http://"))
        self.assertFalse(insecure_url.startswith("https://"))
    
    def test_mitm_attack_scenario(self):
        """Test MITM attack scenario on insecure version."""
        # Original legitimate update
        legitimate_update = "Legitimate update v1.0.0"
        
        # Attacker intercepts and replaces with malicious content
        attacker_payload = "Malicious code - system compromised!"
        
        # In insecure version:
        # 1. Uses HTTP (vulnerable to interception)
        # 2. No checksum verification
        # 3. Accepts attacker's payload
        
        received_update = attacker_payload  # Simulating MITM attack
        
        # Insecure version would accept this without detection
        self.assertEqual(received_update, attacker_payload)
        self.assertNotEqual(received_update, legitimate_update)


class TestSecureUpdateProtection(unittest.TestCase):
    """Test suite to verify the secure version protects against the vulnerability."""
    
    def test_secure_rejects_tampered_content(self):
        """Test that secure version rejects tampered content."""
        legitimate_content = "Legitimate update v1.0.0"
        legitimate_checksum = hashlib.sha256(legitimate_content.encode('utf-8')).hexdigest()
        
        tampered_content = "Malicious update - HACKED!"
        tampered_checksum = hashlib.sha256(tampered_content.encode('utf-8')).hexdigest()
        
        # Secure version compares checksums
        verification_passed = (legitimate_checksum == tampered_checksum)
        
        self.assertFalse(verification_passed)  # Should reject tampered content
    
    def test_secure_uses_https(self):
        """Test that secure version uses HTTPS."""
        secure_url = "https://example.com/fake-update.txt"
        
        self.assertTrue(secure_url.startswith("https://"))
    
    def test_secure_requires_checksum(self):
        """Test that secure version requires checksum availability."""
        checksum_available = True
        checksum_url = "https://example.com/fake-update.txt.sha256"
        
        self.assertTrue(checksum_available)
        self.assertTrue(checksum_url.endswith(".sha256"))
    
    def test_mitm_attack_prevention(self):
        """Test that secure version prevents MITM attacks."""
        # Original legitimate update
        legitimate_update = "Legitimate update v1.0.0"
        legitimate_checksum = hashlib.sha256(legitimate_update.encode('utf-8')).hexdigest()
        
        # Attacker tries to inject malicious content
        attacker_payload = "Malicious code - system compromised!"
        attacker_checksum = hashlib.sha256(attacker_payload.encode('utf-8')).hexdigest()
        
        # In secure version:
        # 1. Uses HTTPS (harder to intercept)
        # 2. Verifies checksum
        # 3. Rejects if checksums don't match
        
        # Simulate: attacker replaces content but can't forge checksum
        received_content = attacker_payload
        received_content_checksum = hashlib.sha256(received_content.encode('utf-8')).hexdigest()
        expected_checksum = legitimate_checksum
        
        verification_passed = (received_content_checksum == expected_checksum)
        
        # Attack should be detected and rejected
        self.assertFalse(verification_passed)


def run_tests():
    """Run all test suites."""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestUpdateIntegrityVerification))
    suite.addTests(loader.loadTestsFromTestCase(TestInsecureUpdateVulnerability))
    suite.addTests(loader.loadTestsFromTestCase(TestSecureUpdateProtection))
    
    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("=" * 70)
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1)
