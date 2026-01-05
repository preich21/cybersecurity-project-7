#!/usr/bin/env python3
"""
Starter-Code fr Projekt C: CRA-konformes Patch- & Vulnerability-Handling

ACHTUNG:
Dieses Programm enthält ABSICHTLICH mehrere Sicherheitslücken und
Designschwächen. Es dient ausschlielich Ausbildungszwecken
(Secure Coding, CRA, Vulnerability Handling).

NICHT in Produktion einsetzen!
"""

import os
import hashlib
import logging
import bcrypt
import requests
import time
import subprocess
import re

from dotenv import load_dotenv

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

APP_VERSION = "1.0.0" 


# ---------------------------------------------------------
# Dummy-User-Verwaltung (mit Schwachstellen)
# ---------------------------------------------------------

def create_user_db():
    """
    Creates a dummy user database.
    In a real project, we should definitely use a proper database that doesn't live in memory.
    """
    result = {}

    initial_users = os.getenv("INITIAL_USERS")
    if initial_users:
        for entry in initial_users.split(","):
            try:
                username, password = entry.split(":")
                result[username.strip()] = password.strip()
            except ValueError:
                raise RuntimeError(f"Invalid user entry in the INITIAL_USERS env variable: {entry}")

    return result


USERS = create_user_db()
LOGGED_IN_USER: str|None = None


def login(username: str, password: str) -> bool:
    """
    Sehr vereinfachter Login.
    """
    logger.info(f"Login attempt for user={username}")

    stored_pw_hash = USERS.get(username)
    if stored_pw_hash is None:
        logger.warning(f"Unknown user [{username}]")
        return False

    pw_bytes = password.encode("utf-8")
    stored_pw_hash_bytes = stored_pw_hash.encode("utf-8")
    if bcrypt.checkpw(pw_bytes, stored_pw_hash_bytes):
        logger.info(f"User {username} successfully logged in")
        global LOGGED_IN_USER
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
    Pingt einen Host an mit sicherer Eingabevalidierung.
    """
    # Validate host input to prevent command injection
    # Allow only valid hostnames and IP addresses
    if not re.match(r'^[a-zA-Z0-9\.\-]+$', host):
        logger.error(f"Invalid host format: {host}")
        print("Fehler: Ungültiges Host-Format. Nur Buchstaben, Zahlen, Punkte und Bindestriche sind erlaubt.")
        return
    
    # Additional validation: limit length to prevent abuse
    if len(host) > 253:  # Max DNS hostname length
        logger.error(f"Host name too long: {host}")
        print("Fehler: Host-Name zu lang.")
        return
    
    logger.info(f"Executing ping for host: {host}")
    
    try:
        # Use subprocess with list of arguments instead of shell=True
        # This prevents command injection
        result = subprocess.run(
            ["ping", "-c", "1", host],
            capture_output=True,
            text=True,
            timeout=5,
            check=False
        )
        print(result.stdout)
        if result.returncode != 0:
            print(f"Ping fehlgeschlagen (exit code: {result.returncode})")
    except subprocess.TimeoutExpired:
        logger.error(f"Ping timeout for host: {host}")
        print("Fehler: Ping-Timeout überschritten.")
    except Exception as ex:
        logger.exception(f"Error while pinging host: {ex}")
        print(f"Fehler beim Pingen: {ex}")


# ---------------------------------------------------------
# Simulierter Update-Mechanismus
# ---------------------------------------------------------

UPDATE_URL = "https://example.com/fake-update.txt"  # Use HTTPS instead of HTTP
LOCAL_UPDATE_FILE = "update_payload.txt"
UPDATE_CHECKSUM_URL = "https://example.com/fake-update.txt.sha256"  # Checksum for integrity verification


def check_for_update() -> bool:
    """
    Simuliert eine Update-Prfung.
    In der Realitt wrde z. B. eine API-Version abgefragt werden.

    Hier wird einfach "zufllig" entschieden.
    """
    # zur Vereinfachung: wir tun so, als gäbe es alle 2 Aufrufe ein "Update"
    ts = int(time.time())
    if ts % 2 == 0:
        logger.info("Update available (simuliert)")
        return True
    else:
        logger.info("No update available (simuliert)")
        return False


def download_update() -> str:
    """
    Simuliert den Download eines Updates von einem externen Server mit Integritätsprüfung.
    """
    logger.info(f"Downloading update from {UPDATE_URL}")

    try:
        # Download with certificate verification enabled (default in requests)
        # and with timeout to prevent hanging
        resp = requests.get(UPDATE_URL, verify=True, timeout=30)
        if resp.status_code == 200:
            payload = resp.text
            
            # Download checksum for integrity verification
            try:
                checksum_resp = requests.get(UPDATE_CHECKSUM_URL, verify=True, timeout=30)
                if checksum_resp.status_code == 200:
                    expected_checksum = checksum_resp.text.strip().split()[0]  # Get first field (checksum)
                    
                    # Calculate actual checksum
                    actual_checksum = hashlib.sha256(payload.encode('utf-8')).hexdigest()
                    
                    if actual_checksum != expected_checksum:
                        logger.error("Update checksum verification failed!")
                        print("Fehler: Update-Integritätsprüfung fehlgeschlagen.")
                        return ""
                    
                    logger.info("Update checksum verified successfully.")
                else:
                    logger.warning("Could not download update checksum for verification.")
                    print("Warnung: Checksum konnte nicht heruntergeladen werden. Update wird nicht angewendet.")
                    return ""
            except Exception as checksum_ex:
                logger.exception(f"Error while verifying update checksum: {checksum_ex}")
                print("Fehler bei der Checksum-Überprüfung. Update wird nicht angewendet.")
                return ""
            
            # Write verified update to file
            with open(LOCAL_UPDATE_FILE, "w", encoding="utf-8") as f:
                f.write(payload)
            logger.info("Update downloaded and stored locally.")
            return LOCAL_UPDATE_FILE
        else:
            logger.error(f"Update server responded with status {resp.status_code}")
            return ""
    except requests.exceptions.SSLError as ssl_ex:
        logger.exception(f"SSL certificate verification failed: {ssl_ex}")
        print("Fehler: SSL-Zertifikat konnte nicht verifiziert werden.")
        return ""
    except requests.exceptions.Timeout:
        logger.error("Update download timeout")
        print("Fehler: Update-Download Timeout.")
        return ""
    except Exception as ex:
        logger.exception(f"Error while downloading update: {ex}")
        return ""


def apply_update(file_path: str) -> None:
    """
    Simuliert das Anwenden eines Updates.
    Das Update wurde bereits auf Integrität geprüft (Checksum-Verifikation).
    """
    if not file_path:
        logger.error("No update file to apply.")
        return

    logger.info(f"Applying verified update from {file_path}.")
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Wir tun nur so, als würden wir "Code" übernehmen.
        # In einer echten Anwendung würde hier das Update installiert werden.
            logger.debug(f"Update content preview:\n{content[:200]}")

            logger.info("Update applied (simuliert).")
    except Exception as ex:
        logger.exception(f"Failed to apply update: {ex}")


# ---------------------------------------------------------
# Einfaches CLI-Menu
# ---------------------------------------------------------

def main_menu():
    print("=" * 50)
    print(" Secure Demo App (mit Sicherheitsverbesserungen) ")
    print(f" Version: {APP_VERSION}")
    print("=" * 50)
    print("1) Login")
    print("2) Hash berechnen (SHA256)")
    print("3) Host anpingen (gesichert gegen Command Injection)")
    print("4) Nach Update suchen & anwenden (mit Integritätsprüfung)")
    print("5) Beenden")
    print()

    choice = input("Auswahl: ").strip()
    return choice


def main():
    logger.info("Application started (SECURE MODE)")

    while True:
        choice = main_menu()

        if choice == "1":
            username = input("Benutzername: ")
            password = input("Passwort: ")
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
            if check_for_update():
                path = download_update()
                apply_update(path)
            else:
                print("Kein Update verfügbar.")

        elif choice == "5":
            logout()
            print("Beende Programm.")
            break

        else:
            print("Ungültige Auswahl.")


if __name__ == "__main__":
    main()

