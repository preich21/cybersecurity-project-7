#!/usr/bin/env python3
"""
Starter-Code fr Projekt C: CRA-konformes Patch- & Vulnerability-Handling

ACHTUNG:
Dieses Programm enthlt ABSICHTLICH mehrere Sicherheitslcken und
Designschwchen. Es dient ausschlielich Ausbildungszwecken
(Secure Coding, CRA, Vulnerability Handling).

NICHT in Produktion einsetzen!
"""

import os
import hashlib
import logging
import bcrypt
import requests
import time

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
        return True

    logger.warning("Invalid password")
    return False



def insecure_hash(data: str) -> str:
    """
    Berechnet einen SHA256 Hash über die eingegebenen Daten.
    """
    h = hashlib.sha256(data.encode("utf-8")).hexdigest()
    logger.debug(f"Calculated SHA256 hash for data={data}: {h}")
    return h



def ping_host(host: str) -> None:
    """
    Pingt einen Host an.
   """
    command = f"ping -c 1 {host}"
    logger.info(f"Executing command: {command}")
    os.system(command)  # <-- unsicher, host kann z. B. '8.8.8.8; rm -rf /' sein


# ---------------------------------------------------------
# Simulierter Update-Mechanismus
# ---------------------------------------------------------

UPDATE_URL = "http://example.com/fake-update.txt"
LOCAL_UPDATE_FILE = "update_payload.txt"


def check_for_update() -> bool:
    """
    Simuliert eine Update-Prfung.
    In der Realitt wrde z. B. eine API-Version abgefragt werden.

    Hier wird einfach "zufllig" entschieden.
    """
    # zur Vereinfachung: wir tun so, als gbe es alle 2 Aufrufe ein "Update"
    ts = int(time.time())
    if ts % 2 == 0:
        logger.info("Update available (simuliert)")
        return True
    else:
        logger.info("No update available (simuliert)")
        return False


def download_update() -> str:
    """
    Simuliert den Download eines Updates von einem externen Server.
    """
    logger.info(f"Downloading update from {UPDATE_URL}")

    try:
        resp = requests.get(UPDATE_URL) 
        if resp.status_code == 200:
            payload = resp.text
            with open(LOCAL_UPDATE_FILE, "w", encoding="utf-8") as f:
                f.write(payload)
            logger.info("Update downloaded and stored locally.")
            return LOCAL_UPDATE_FILE
        else:
            logger.error(f"Update server responded with status {resp.status_code}")
            return ""
    except Exception as ex:
        logger.exception(f"Error while downloading update: {ex}")
        return ""


def apply_update(file_path: str) -> None:
    """
    Simuliert das Anwenden eines Updates.
    """
    if not file_path:
        logger.error("No update file to apply.")
        return

    logger.warning(f"Applying update from {file_path} WITHOUT validation (insecure).")
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Wir tun nur so, als wrden wir "Code" bernehmen.
        # In einer echten (noch schlechteren) Variante knnte man hier exec() aufrufen.
            logger.debug(f"Update content preview:\n{content[:200]}")

            logger.info("Update applied (simuliert).")
    except Exception as ex:
        logger.exception(f"Failed to apply update: {ex}")


# ---------------------------------------------------------
# Einfaches CLI-Menu
# ---------------------------------------------------------

def main_menu():
    print("=" * 50)
    print(" Insecure Demo App (nur zu Schulungszwecken) ")
    print(f" Version: {APP_VERSION}")
    print("=" * 50)
    print("1) Login")
    print("2) Hash berechnen (SHA256)")
    print("3) Host anpingen (Command Injection mglich)")
    print("4) Nach Update suchen & anwenden")
    print("5) Beenden")
    print()

    choice = input("Auswahl: ").strip()
    return choice


def main():
    logger.info("Application started (INSECURE DEMO MODE)")

    while True:
        choice = main_menu()

        if choice == "1":
            username = input("Benutzername: ")
            password = input("Passwort: ")
            success = login(username, password)
            print("Login erfolgreich!" if success else "Login fehlgeschlagen.")

        elif choice == "2":
            data = input("Text für Hash-Berechnung: ")
            h = insecure_hash(data)
            print(f"SHA256-Hash: {h}")

        elif choice == "3":
            host = input("Host/IP zum Pingen: ")
            ping_host(host)

        elif choice == "4":
            if check_for_update():
                path = download_update()
                apply_update(path)
            else:
                print("Kein Update verfgbar.")

        elif choice == "5":
            print("Beende Programm.")
            break

        else:
            print("Ungltige Auswahl.")


if __name__ == "__main__":
    main()

