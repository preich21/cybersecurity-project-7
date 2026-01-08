#!/usr/bin/env python3
"""
Starter-Code fr Projekt C: CRA-konformes Patch- & Vulnerability-Handling

ACHTUNG:
Dieses Programm enthält ABSICHTLICH mehrere Sicherheitslücken und
Designschwächen. Es dient ausschließlich Ausbildungszwecken
(Secure Coding, CRA, Vulnerability Handling).

NICHT in Produktion einsetzen!
"""
import argparse
import getpass
import os
import hashlib
import logging
import bcrypt
import requests
import time

from dotenv import load_dotenv

# Import secure update system
from . import secure_update

# ---------------------------------------------------------
# Globale Konfiguration (mehrere Schwachstellen hier drin)
# ---------------------------------------------------------

load_dotenv()

# Might as well be removed completely, since the app doesn't actually use it.
# However, we keep it to illustrate the concept of secret keys.
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("Environment variable SECRET_KEY is not set!")

DEBUG = True


logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

logger = logging.getLogger("insecure_app")

# Version aus uv package importieren
from importlib.metadata import version
APP_VERSION = version("cra-demo-app")


# ---------------------------------------------------------
# Dummy-User-Verwaltung
# ---------------------------------------------------------

def create_user_db():
    """
    Creates a dummy user database.
    In a real project, we should definitely use a proper database that doesn't live in memory.
    """
    result = {}

    default_users = os.getenv("INITIAL_USERS")
    if default_users:
        for entry in default_users.split(","):
            try:
                username, password = entry.split(":")
                result[username.strip()] = password.strip()
            except ValueError:
                raise RuntimeError(f"Invalid user entry in the INITIAL_USERS env variable: {entry}")

        # In production, an alerting should be configured to fire if this log line is ever printed.
        logger.warning(f"Loaded {len(default_users.split(","))} initial users from environment variable.")

    return result


USERS = create_user_db()
LOGGED_IN_USER: str|None = None


def login(username: str, password: str) -> bool:
    """
    Sehr vereinfachter Login.
    """
    global LOGGED_IN_USER

    logger.info(f"Login attempt for user={username}")
    if LOGGED_IN_USER is not None:
        logger.warning(f"User {LOGGED_IN_USER} is already logged in. Logging them out first.")
        LOGGED_IN_USER = None

    stored_pw_hash = USERS.get(username)
    if stored_pw_hash is None:
        logger.warning(f"Unknown user [{username}]")
        return False

    pw_bytes = password.encode("utf-8")
    stored_pw_hash_bytes = stored_pw_hash.encode("utf-8")
    if bcrypt.checkpw(pw_bytes, stored_pw_hash_bytes):
        logger.info(f"User {username} successfully logged in")
        LOGGED_IN_USER = username
        return True

    logger.warning("Invalid password")
    return False


def validate_authentication() -> bool:
    """
    Dummy function for user authentication validation.
    Optimally, in a real application, the user should decorate each request with a valid JWT token or session cookie which we then verify here.
    For simplicity, we assume the user is correctly authenticated once they have logged in.
    """
    if LOGGED_IN_USER is None:
        logger.warning("User not authenticated.")
        return False
    elif USERS.get(LOGGED_IN_USER) is None:
        logger.warning("Authenticated user not found in user database. This should never happen.")
        return False
    return True


def logout() -> None:
    """
    Logs out the current user.
    """
    global LOGGED_IN_USER
    if LOGGED_IN_USER:
        logger.info(f"User {LOGGED_IN_USER} logged out.")
    LOGGED_IN_USER = None


def insecure_hash(data: str) -> str:
    """
    Berechnet einen SHA256 Hash über die eingegebenen Daten.
    """
    h = hashlib.sha256(data.encode("utf-8")).hexdigest()
    logger.debug(f"Calculated SHA256 hash") # We could remove the whole log line, but maybe it's useful for tracing or something.
    return h



def ping_host(host: str) -> None:
    """
    Pingt einen Host an.
   """
    command = f"ping -c 1 {host}"
    logger.info(f"Executing command: {command}")
    os.system(command)  # <-- unsicher, host kann z. B. '8.8.8.8; rm -rf /' sein


# ---------------------------------------------------------
# Update-Mechanismus mit konfigurierbarer Sicherheit
# ---------------------------------------------------------

# Global variable to store security configuration
UPDATE_SECURITY_CONFIG = None


def configure_update_security(args) -> None:
    """
    Configure update security features based on command-line arguments.
    """
    global UPDATE_SECURITY_CONFIG
    
    UPDATE_SECURITY_CONFIG = secure_update.UpdateConfig(
        use_https=args.use_https,
        verify_checksum=args.verify_checksum,
        verify_signature=args.verify_signature,
        check_size_limit=args.check_size_limit,
        prevent_rollback=args.prevent_rollback,
        use_timeouts=args.use_timeouts,
        atomic_writes=args.atomic_writes,
        allow_redirects=args.allow_redirects,
    )


def check_and_apply_update(demo_mode: bool = False) -> None:
    """
    Check for updates using the configured security settings.
    """
    if UPDATE_SECURITY_CONFIG is None:
        print("❌ Update system not properly initialized.")
        return
    
    try:
        # Use the secure update system with configured security features
        success = secure_update.check_for_update(
            config=UPDATE_SECURITY_CONFIG,
            demo_mode=demo_mode
        )
        
        if success:
            print("\n✅ Update downloaded successfully!")
            # Apply the update
            secure_update.apply_update(secure_update.LOCAL_UPDATE_FILE)
            print("✅ Update applied successfully!\n")
        else:
            print("\n⚠️  No update available or update check failed.\n")
    except Exception as e:
        print(f"\n❌ Update failed: {e}\n")


# ---------------------------------------------------------
# Einfaches CLI-Menu
# ---------------------------------------------------------

def main_menu():
    print("=" * 50)
    print(" CRA Demo App (Schulungszwecke) ")
    print(f" Version: {APP_VERSION}")
    if UPDATE_SECURITY_CONFIG:
        print(f" Update Security: {UPDATE_SECURITY_CONFIG.describe()}")
    print("=" * 50)
    print("1) Login")
    print("2) Hash berechnen (SHA256)")
    print("3) Host anpingen (Command Injection möglich)")
    print("4) Nach Update suchen & anwenden")
    print("5) Beenden")
    print()

    choice = input("Auswahl: ").strip()
    return choice


def parse_arguments():
    """Parse command-line arguments for security feature configuration."""
    parser = argparse.ArgumentParser(
        description="CRA Demo App - Configurable Update Security",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Security Feature Examples:
  # Completely insecure (all features disabled):
  python -m cra_demo_app.cli --no-https --no-checksum --no-signature --no-size-limit --no-rollback --no-timeouts --no-atomic --allow-redirects

  # HTTPS only (transport security, no integrity):
  python -m cra_demo_app.cli --no-checksum --no-signature --no-size-limit --no-rollback --no-atomic

  # HTTPS + Checksum (integrity but no authenticity):
  python -m cra_demo_app.cli --no-signature --no-rollback

  # Fully secure (all features enabled - default):
  python -m cra_demo_app.cli

  # Demo mode with verbose output:
  python -m cra_demo_app.cli --demo
        """
    )
    
    # Security feature flags (all enabled by default for secure-by-default)
    parser.add_argument(
        "--no-https",
        dest="use_https",
        action="store_false",
        default=True,
        help="Disable HTTPS requirement (allows HTTP - INSECURE)"
    )
    parser.add_argument(
        "--no-checksum",
        dest="verify_checksum",
        action="store_false",
        default=True,
        help="Disable SHA256 checksum verification"
    )
    parser.add_argument(
        "--no-signature",
        dest="verify_signature",
        action="store_false",
        default=True,
        help="Disable cryptographic signature verification"
    )
    parser.add_argument(
        "--no-size-limit",
        dest="check_size_limit",
        action="store_false",
        default=True,
        help="Disable update size limit checks"
    )
    parser.add_argument(
        "--no-rollback",
        dest="prevent_rollback",
        action="store_false",
        default=True,
        help="Disable rollback protection (allows downgrades)"
    )
    parser.add_argument(
        "--no-timeouts",
        dest="use_timeouts",
        action="store_false",
        default=True,
        help="Disable request timeouts"
    )
    parser.add_argument(
        "--no-atomic",
        dest="atomic_writes",
        action="store_false",
        default=True,
        help="Disable atomic file writes"
    )
    parser.add_argument(
        "--allow-redirects",
        dest="allow_redirects",
        action="store_true",
        default=False,
        help="Allow HTTP redirects (can be exploited)"
    )
    parser.add_argument(
        "--demo",
        dest="demo_mode",
        action="store_true",
        default=False,
        help="Enable verbose demo mode with detailed output"
    )
    
    return parser.parse_args()


def interactive_mode(demo_mode: bool = False):
    """Run the interactive CLI menu."""
    logger.info("Application started")

    while True:
        choice = main_menu()

        if choice == "1":
            username = input("Benutzername: ")
            password = getpass.getpass("Passwort: ")
            success = login(username, password)
            print("Login erfolgreich!" if success else "Login fehlgeschlagen.")

        elif choice == "2":
            if not validate_authentication():
                print("Diese Funktionalität steht nur eingeloggten Benutzern zur Verfügung.")
                continue
            data = input("Text für Hash-Berechnung: ")
            h = insecure_hash(data)
            print(f"SHA256-Hash: {h}")

        elif choice == "3":
            if not validate_authentication():
                print("Diese Funktionalität steht nur eingeloggten Benutzern zur Verfügung.")
                continue
            host = input("Host/IP zum Pingen: ")
            ping_host(host)

        elif choice == "4":
            if not validate_authentication():
                print("Diese Funktionalität steht nur eingeloggten Benutzern zur Verfügung.")
                continue
            check_and_apply_update(demo_mode=demo_mode)

        elif choice == "5":
            logout()
            print("Beende Programm.")
            break

        else:
            print("Ungültige Auswahl.")


def main():
    """Main entry point with argument parsing."""
    args = parse_arguments()
    
    # Configure update security based on arguments
    configure_update_security(args)
    
    # Show warning only if running with reduced security
    if not args.use_https or not args.verify_signature:
        print("\nWARNING: Running with reduced security for DEMONSTRATION purposes!\n")
    
    # Run interactive mode
    interactive_mode(demo_mode=args.demo_mode)


if __name__ == "__main__":
    main()

