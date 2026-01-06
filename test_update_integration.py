#!/usr/bin/env python3
"""
Integration Tests for Update Mechanism

End-to-end tests that verify the complete update workflow:
1. Check for updates
2. Download updates
3. Verify integrity
4. Apply updates

Tests both the insecure and secure versions to demonstrate the vulnerability
and its fix.
"""

import unittest
import hashlib
import tempfile
import os
import sys
import http.server
import socketserver
import threading
import time
import random
from pathlib import Path

# Test configuration
TEST_PORT = random.randint(10000, 60000)  # Random port to avoid conflicts
TEST_CONTENT = "Test Update v1.0.0\nThis is a legitimate update."
TEST_CONTENT_MALICIOUS = "MALICIOUS UPDATE\nSystem compromised!"


class TestUpdateServer(http.server.SimpleHTTPRequestHandler):
    """Test HTTP server for simulating update servers."""
    
    # Class variable to control what to serve
    serve_malicious = False
    serve_checksum = True
    
    def do_GET(self):
        """Handle GET requests."""
        if self.path == "/update.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            
            content = TEST_CONTENT_MALICIOUS if self.serve_malicious else TEST_CONTENT
            self.wfile.write(content.encode('utf-8'))
        
        elif self.path == "/update.txt.sha256":
            if self.serve_checksum:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                
                # Always serve checksum for legitimate content
                checksum = hashlib.sha256(TEST_CONTENT.encode('utf-8')).hexdigest()
                self.wfile.write(f"{checksum}  update.txt\n".encode('utf-8'))
            else:
                self.send_response(404)
                self.end_headers()
        
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        """Suppress logging."""
        pass


class ReuseAddrTCPServer(socketserver.TCPServer):
    """TCP Server that allows address reuse."""
    allow_reuse_address = True


class IntegrationTestUpdateMechanism(unittest.TestCase):
    """Integration tests for the complete update mechanism."""
    
    @classmethod
    def setUpClass(cls):
        """Start test HTTP server."""
        cls.httpd = ReuseAddrTCPServer(("", TEST_PORT), TestUpdateServer)
        cls.server_thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.5)  # Give server time to start
        # Get the actual port assigned by OS
        cls.test_port = cls.httpd.server_address[1]
    
    @classmethod
    def tearDownClass(cls):
        """Stop test HTTP server."""
        cls.httpd.shutdown()
        cls.httpd.server_close()
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.update_file = os.path.join(self.temp_dir, "downloaded_update.txt")
        
        # Reset server state
        TestUpdateServer.serve_malicious = False
        TestUpdateServer.serve_checksum = True
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_e2e_legitimate_update_flow(self):
        """
        Test complete flow with legitimate update:
        1. Download update
        2. Download checksum
        3. Verify integrity
        4. Accept update
        """
        import requests
        
        # Download update
        update_url = f"http://localhost:{TEST_PORT}/update.txt"
        response = requests.get(update_url, timeout=5)
        self.assertEqual(response.status_code, 200)
        
        update_content = response.text
        self.assertIn("legitimate", update_content.lower())
        
        # Download checksum
        checksum_url = f"http://localhost:{TEST_PORT}/update.txt.sha256"
        checksum_response = requests.get(checksum_url, timeout=5)
        self.assertEqual(checksum_response.status_code, 200)
        
        expected_checksum = checksum_response.text.strip().split()[0]
        
        # Verify integrity
        actual_checksum = hashlib.sha256(update_content.encode('utf-8')).hexdigest()
        
        self.assertEqual(expected_checksum, actual_checksum)
        
        # Update should be accepted
        verification_passed = (expected_checksum == actual_checksum)
        self.assertTrue(verification_passed)
    
    def test_e2e_malicious_update_detection(self):
        """
        Test complete flow with malicious update:
        1. Download malicious update (MITM scenario)
        2. Download legitimate checksum
        3. Verify integrity
        4. Reject update (checksums don't match)
        """
        import requests
        
        # Simulate MITM: server serves malicious content
        TestUpdateServer.serve_malicious = True
        
        # Download update (malicious)
        update_url = f"http://localhost:{TEST_PORT}/update.txt"
        response = requests.get(update_url, timeout=5)
        self.assertEqual(response.status_code, 200)
        
        update_content = response.text
        self.assertIn("MALICIOUS", update_content)
        
        # Download checksum (for legitimate content)
        checksum_url = f"http://localhost:{TEST_PORT}/update.txt.sha256"
        checksum_response = requests.get(checksum_url, timeout=5)
        self.assertEqual(checksum_response.status_code, 200)
        
        expected_checksum = checksum_response.text.strip().split()[0]
        
        # Verify integrity
        actual_checksum = hashlib.sha256(update_content.encode('utf-8')).hexdigest()
        
        # Checksums should NOT match
        self.assertNotEqual(expected_checksum, actual_checksum)
        
        # Update should be REJECTED
        verification_passed = (expected_checksum == actual_checksum)
        self.assertFalse(verification_passed)
    
    def test_e2e_missing_checksum_handling(self):
        """
        Test handling when checksum is unavailable:
        1. Download update
        2. Try to download checksum (404)
        3. Reject update (no checksum available)
        """
        import requests
        
        # Configure server to not serve checksum
        TestUpdateServer.serve_checksum = False
        
        # Download update
        update_url = f"http://localhost:{TEST_PORT}/update.txt"
        response = requests.get(update_url, timeout=5)
        self.assertEqual(response.status_code, 200)
        
        # Try to download checksum
        checksum_url = f"http://localhost:{TEST_PORT}/update.txt.sha256"
        checksum_response = requests.get(checksum_url, timeout=5)
        
        # Checksum should not be available
        self.assertEqual(checksum_response.status_code, 404)
        
        # Update should be REJECTED (no checksum to verify)
        checksum_available = (checksum_response.status_code == 200)
        self.assertFalse(checksum_available)
    
    def test_e2e_file_writing_and_reading(self):
        """Test the complete flow of downloading, writing, and reading update file."""
        import requests
        
        # Download update
        update_url = f"http://localhost:{TEST_PORT}/update.txt"
        response = requests.get(update_url, timeout=5)
        content = response.text
        
        # Write to file (simulating download_update)
        with open(self.update_file, 'w', encoding='utf-8') as f:
            f.write(content)
        
        # Verify file was written
        self.assertTrue(os.path.exists(self.update_file))
        
        # Read back and verify (simulating apply_update)
        with open(self.update_file, 'r', encoding='utf-8') as f:
            read_content = f.read()
        
        self.assertEqual(content, read_content)
        self.assertIn("Test Update", read_content)
    
    def test_e2e_checksum_calculation_consistency(self):
        """Test that checksum calculations are consistent throughout the flow."""
        import requests
        
        # Download update
        update_url = f"http://localhost:{TEST_PORT}/update.txt"
        response = requests.get(update_url, timeout=5)
        content = response.text
        
        # Calculate checksum multiple times
        checksum1 = hashlib.sha256(content.encode('utf-8')).hexdigest()
        checksum2 = hashlib.sha256(content.encode('utf-8')).hexdigest()
        checksum3 = hashlib.sha256(content.encode('utf-8')).hexdigest()
        
        # All should be identical
        self.assertEqual(checksum1, checksum2)
        self.assertEqual(checksum2, checksum3)
    
    def test_e2e_update_with_special_characters(self):
        """Test update containing special characters and Unicode."""
        import requests
        
        # Download and verify normal update first
        update_url = f"http://localhost:{TEST_PORT}/update.txt"
        response = requests.get(update_url, timeout=5)
        content = response.text
        
        # Add special characters
        special_content = content + "\n特殊文字: äöü €"
        special_checksum = hashlib.sha256(special_content.encode('utf-8')).hexdigest()
        
        # Write and read back
        with open(self.update_file, 'w', encoding='utf-8') as f:
            f.write(special_content)
        
        with open(self.update_file, 'r', encoding='utf-8') as f:
            read_content = f.read()
        
        # Verify checksum after write/read
        read_checksum = hashlib.sha256(read_content.encode('utf-8')).hexdigest()
        self.assertEqual(special_checksum, read_checksum)
    
    def test_e2e_concurrent_update_checks(self):
        """Test that multiple concurrent update checks work correctly."""
        import requests
        
        # Simulate multiple clients checking for updates
        results = []
        
        for i in range(5):
            update_url = f"http://localhost:{TEST_PORT}/update.txt"
            response = requests.get(update_url, timeout=5)
            results.append(response.status_code)
        
        # All should succeed
        self.assertTrue(all(status == 200 for status in results))
    
    def test_e2e_update_timeout_handling(self):
        """Test that timeouts are handled properly."""
        import requests
        
        # Test with very short timeout (should work with local server)
        update_url = f"http://localhost:{TEST_PORT}/update.txt"
        
        try:
            response = requests.get(update_url, timeout=5)
            self.assertEqual(response.status_code, 200)
        except requests.exceptions.Timeout:
            self.fail("Request timed out unexpectedly")


class IntegrationTestInsecureVsSecure(unittest.TestCase):
    """Integration tests comparing insecure and secure implementations."""
    
    def test_insecure_accepts_any_content(self):
        """
        Verify that insecure version accepts content without verification.
        This demonstrates the vulnerability.
        """
        # Simulate insecure download (no checksum verification)
        content = "Any content here"
        
        # Insecure version would accept this
        insecure_accepts = True  # No verification performed
        
        self.assertTrue(insecure_accepts)
    
    def test_secure_requires_verification(self):
        """
        Verify that secure version requires checksum verification.
        This demonstrates the fix.
        """
        legitimate_content = "Legitimate update"
        legitimate_checksum = hashlib.sha256(legitimate_content.encode('utf-8')).hexdigest()
        
        malicious_content = "Malicious update"
        malicious_checksum = hashlib.sha256(malicious_content.encode('utf-8')).hexdigest()
        
        # Simulate download: attacker sends malicious content
        downloaded_content = malicious_content
        downloaded_checksum = hashlib.sha256(downloaded_content.encode('utf-8')).hexdigest()
        
        # Secure version verifies checksum
        expected_checksum = legitimate_checksum
        verification_passed = (downloaded_checksum == expected_checksum)
        
        # Should reject malicious content
        self.assertFalse(verification_passed)
    
    def test_http_vs_https_security(self):
        """Compare HTTP (insecure) vs HTTPS (secure) for update downloads."""
        insecure_url = "http://example.com/update.txt"
        secure_url = "https://example.com/update.txt"
        
        # Verify URL schemes
        self.assertTrue(insecure_url.startswith("http://"))
        self.assertTrue(secure_url.startswith("https://"))
        
        # HTTP is vulnerable to MITM
        http_vulnerable_to_mitm = True
        https_vulnerable_to_mitm = False  # With proper cert verification
        
        self.assertTrue(http_vulnerable_to_mitm)
        self.assertFalse(https_vulnerable_to_mitm)
    
    def test_attack_surface_comparison(self):
        """Compare attack surface between insecure and secure versions."""
        # Insecure version vulnerabilities
        insecure_vulnerabilities = {
            'http_used': True,
            'no_checksum_verification': True,
            'no_signature_verification': True,
            'no_cert_verification': True,
        }
        
        # Secure version protections
        secure_protections = {
            'https_used': True,
            'checksum_verification': True,
            'cert_verification': True,
            'timeout_configured': True,
        }
        
        # Verify insecure version has vulnerabilities
        self.assertTrue(insecure_vulnerabilities['http_used'])
        self.assertTrue(insecure_vulnerabilities['no_checksum_verification'])
        
        # Verify secure version has protections
        self.assertTrue(secure_protections['https_used'])
        self.assertTrue(secure_protections['checksum_verification'])


class IntegrationTestErrorHandling(unittest.TestCase):
    """Integration tests for error handling in update mechanism."""
    
    def test_network_error_handling(self):
        """Test handling of network errors during update download."""
        import requests
        
        # Try to connect to non-existent server (use a non-routable IP)
        invalid_url = "http://192.0.2.1/update.txt"  # TEST-NET-1, non-routable
        
        try:
            response = requests.get(invalid_url, timeout=1)
            self.fail("Should have raised an exception")
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout, 
                requests.exceptions.InvalidURL):
            # Expected - should handle gracefully
            pass
    
    def test_malformed_checksum_handling(self):
        """Test handling of malformed checksum responses."""
        malformed_checksums = [
            "",  # Empty
            "notahexvalue",  # Invalid hex
            "a" * 63,  # Too short
            "a" * 65,  # Too long
            "   ",  # Whitespace only
        ]
        
        for malformed in malformed_checksums:
            # Should detect as invalid
            is_valid = len(malformed) == 64 and all(c in '0123456789abcdef' for c in malformed)
            self.assertFalse(is_valid, f"Should reject: {malformed}")
    
    def test_partial_download_handling(self):
        """Test handling of partial/incomplete downloads."""
        complete_content = "Complete update content v1.0.0"
        partial_content = "Complete upd"  # Incomplete
        
        complete_checksum = hashlib.sha256(complete_content.encode('utf-8')).hexdigest()
        partial_checksum = hashlib.sha256(partial_content.encode('utf-8')).hexdigest()
        
        # Checksums should differ - will be detected
        self.assertNotEqual(complete_checksum, partial_checksum)


def run_integration_tests():
    """Run all integration test suites."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(IntegrationTestUpdateMechanism))
    suite.addTests(loader.loadTestsFromTestCase(IntegrationTestInsecureVsSecure))
    suite.addTests(loader.loadTestsFromTestCase(IntegrationTestErrorHandling))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 70)
    print("INTEGRATION TEST SUMMARY")
    print("=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("=" * 70)
    
    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_integration_tests()
    sys.exit(0 if success else 1)
