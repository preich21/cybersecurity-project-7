#!/usr/bin/env python3
"""
Test Runner for Update Vulnerability Testing

This script runs all tests related to the unvalidated update vulnerability:
- Unit tests
- Integration tests
- Exploit demonstration
"""

import sys
import subprocess
import os


def run_command(cmd, description):
    """Run a command and report results."""
    print("\n" + "=" * 70)
    print(f"Running: {description}")
    print("=" * 70)
    
    result = subprocess.run(cmd, shell=True, capture_output=False)
    
    if result.returncode == 0:
        print(f"✓ {description} PASSED")
        return True
    else:
        print(f"✗ {description} FAILED")
        return False


def main():
    """Main test runner."""
    print("""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║        Unvalidated Update Vulnerability - Test Suite Runner         ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
    """)
    
    results = []
    
    # Run exploit demonstration
    results.append(run_command(
        "python3 exploit_unvalidated_update.py",
        "Exploit Demonstration"
    ))
    
    # Run unit tests
    results.append(run_command(
        "python3 test_update_integrity.py",
        "Unit Tests"
    ))
    
    # Run integration tests
    results.append(run_command(
        "python3 test_update_integration.py",
        "Integration Tests"
    ))
    
    # Summary
    print("\n" + "=" * 70)
    print("OVERALL TEST SUMMARY")
    print("=" * 70)
    
    total = len(results)
    passed = sum(results)
    failed = total - passed
    
    print(f"Total test suites: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    
    if all(results):
        print("\n✓ ALL TESTS PASSED")
        print("=" * 70)
        return 0
    else:
        print("\n✗ SOME TESTS FAILED")
        print("=" * 70)
        return 1


if __name__ == "__main__":
    sys.exit(main())
