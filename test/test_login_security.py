"""
End-to-end tests for login security in fixed-application.py

Tests verify:
1. No password leakage in logs/output
2. Authentication required for all functions except login and exit
3. Passwords stored using bcrypt (instead of plaintext)
"""

import subprocess
import sys
import os
import bcrypt
import pytest
import pexpect


class TestLoginSecurity:
    """Test suite for login security functionality"""

    @pytest.fixture
    def app_env(self):
        """Set up environment variables for testing"""
        test_password = "TestPass123!"
        test_hash = bcrypt.hashpw(test_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        env = os.environ.copy()
        env['SECRET_KEY'] = 'test-secret-key-12345'
        env['INITIAL_USERS'] = f'testuser:{test_hash}'

        return env, 'testuser', test_password

    def test_no_password_in_logs(self, app_env, capfd):
        """
        Test that passwords are never written to logs or output after login.

        This test simulates a login attempt and verifies that the password
        does not appear in any form in the captured output.
        """

        env, username, password = app_env

        # Run the application with pexpect to handle password prompts
        child = pexpect.spawn(
            sys.executable,
            ['-m', 'cra_demo_app.cli'],
            env=env,
            timeout=5,
            encoding='utf-8'
        )

        try:
            # Wait for menu and select login (option 1)
            child.expect('Auswahl:')
            child.sendline('1')

            # Enter username
            child.expect('Benutzername:')
            child.sendline(username)

            # Enter password (this is where getpass is used)
            child.expect('Passwort:')
            child.sendline(password)

            # Wait for login result
            child.expect('Login erfolgreich!')

            # Select exit (option 5)
            child.expect('Auswahl:')
            child.sendline('5')

            # Wait for exit
            child.expect(pexpect.EOF)

            # Get all output
            all_output = child.before

        finally:
            if child.isalive():
                child.terminate(force=True)

        # Check that password does not appear in output
        assert password not in all_output, \
            f"Password '{password}' found in application output! This is a security vulnerability."

        # Also check for common password patterns that might leak
        password_patterns = [
            f"password: {password}",
            f"Password: {password}",
            f"pwd={password}",
            f"pass={password}",
            f'"{password}"',
            f"'{password}'",
        ]

        for pattern in password_patterns:
            assert pattern.lower() not in all_output.lower(), \
                f"Password pattern '{pattern}' found in output!"

        print("Test passed: No password leakage in logs/output")

    def test_authentication_required_for_hash_function(self, app_env):
        """
        Test that the hash calculation function (option 2) is not accessible
        before login.
        """
        env, username, password = app_env

        # Try to access hash function (option 2) without logging in
        input_data = "2\ntest data\n5\n"

        process = subprocess.Popen(
            [sys.executable, '-m', 'cra_demo_app.cli'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True
        )

        stdout, stderr = process.communicate(input=input_data, timeout=5)
        all_output = stdout + stderr

        # Should see authentication warning
        assert "nur eingeloggten benutzern" in all_output.lower(), \
            "Application should require authentication for hash function!"

        # Should NOT see the hash result
        assert "SHA256-Hash:" not in all_output, \
            "Hash function should not execute without authentication!"

        print("Test passed: Hash function requires authentication")

    def test_authentication_required_for_ping_function(self, app_env):
        """
        Test that the ping function (option 3) is not accessible before login.
        """
        env, username, password = app_env

        # Try to access ping function (option 3) without logging in
        input_data = "3\n8.8.8.8\n5\n"

        process = subprocess.Popen(
            [sys.executable, '-m', 'cra_demo_app.cli'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True
        )

        stdout, stderr = process.communicate(input=input_data, timeout=5)
        all_output = stdout + stderr

        # Should see authentication warning
        assert "nur eingeloggten benutzern" in all_output.lower(), \
            "Application should require authentication for ping function!"

        # Should NOT see ping execution
        assert "Executing command" not in all_output, \
            "Ping function should not execute without authentication!"

        print("Test passed: Ping function requires authentication")

    def test_authentication_required_for_update_function(self, app_env):
        """
        Test that the update function (option 4) is not accessible before login.
        """
        env, username, password = app_env

        # Try to access update function (option 4) without logging in
        input_data = "4\n5\n"

        process = subprocess.Popen(
            [sys.executable, '-m', 'cra_demo_app.cli'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True
        )

        stdout, stderr = process.communicate(input=input_data, timeout=5)
        all_output = stdout + stderr

        # Should see authentication warning
        assert "nur eingeloggten benutzern" in all_output.lower(), \
            "Application should require authentication for update function!"

        # Should NOT see update check/download
        assert "Update available" not in all_output and \
               "No update available" not in all_output, \
            "Update function should not execute without authentication!"

        print("Test passed: Update function requires authentication")

    def test_login_and_exit_accessible_without_auth(self, app_env):
        """
        Test that login (option 1) and exit (option 5) are accessible
        without prior authentication.
        """
        env, username, password = app_env

        # Test exit without login
        input_data = "5\n"

        process = subprocess.Popen(
            [sys.executable, '-m', 'cra_demo_app.cli'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True
        )

        stdout, stderr = process.communicate(input=input_data, timeout=5)
        all_output = stdout + stderr

        # Should exit cleanly
        assert "Beende Programm" in all_output or process.returncode == 0, \
            "Exit should be accessible without authentication!"

        print("Test passed: Login and Exit are accessible without authentication")

    def test_successful_login_grants_access(self, app_env):
        """
        Test that after successful login, protected functions become accessible.
        """

        env, username, password = app_env

        # Run the application with pexpect
        child = pexpect.spawn(
            sys.executable,
            ['-m', 'cra_demo_app.cli'],
            env=env,
            timeout=5,
            encoding='utf-8'
        )

        try:
            # Login
            child.expect('Auswahl:')
            child.sendline('1')
            child.expect('Benutzername:')
            child.sendline(username)
            child.expect('Passwort:')
            child.sendline(password)

            # Check successful login
            child.expect('Login erfolgreich!')

            # Try to access hash function (option 2)
            child.expect('Auswahl:')
            child.sendline('2')
            child.expect('Text für Hash-Berechnung:')
            child.sendline('testdata')
            child.expect('SHA256-Hash:')

            # Try to access ping function (option 3)
            child.expect('Auswahl:')
            child.sendline('3')
            child.expect('Host/IP zum Pingen:')
            child.sendline('google.com')
            child.expect('PING google.com')

            # Try to access update function (option 4)
            child.expect('Auswahl:')
            child.sendline('4')
            child.expect('Update check with features')

            # Exit
            child.expect('Auswahl:')
            child.sendline('5')
            child.expect(pexpect.EOF)

        finally:
            if child.isalive():
                child.terminate(force=True)

        print("Test passed: Successful login grants access to protected functions")

    def test_failed_login_denies_access(self, app_env):
        """
        Test that failed login does not grant access to protected functions.
        """

        env, username, password = app_env

        # Try to log in with wrong password
        wrong_password = "WrongPassword123!"

        child = pexpect.spawn(
            sys.executable,
            ['-m', 'cra_demo_app.cli'],
            env=env,
            timeout=5,
            encoding='utf-8'
        )

        try:
            # Attempt login with wrong password
            child.expect('Auswahl:')
            child.sendline('1')
            child.expect('Benutzername:')
            child.sendline(username)
            child.expect('Passwort:')
            child.sendline(wrong_password)

            # Should see failed login
            child.expect('Login fehlgeschlagen')

            # Try to access hash function (option 2)
            child.expect('Auswahl:')
            child.sendline('2')

            # Should see authentication error
            index = child.expect(['nicht eingelogg', 'not authenticated', 'nur eingeloggten'])

            # Exit
            child.expect('Auswahl:')
            child.sendline('5')
            child.expect(pexpect.EOF)

            all_output = child.before

            # Should NOT see hash result
            assert "SHA256-Hash:" not in all_output, \
                "Hash function should not execute after failed login!"

        finally:
            if child.isalive():
                child.terminate(force=True)

        print("Test passed: Failed login denies access to protected functions")


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "-s"])

