# Sicherheitsanalyse und Schwachstellenbehebung

## Übersicht

Dieses Dokument beschreibt die identifizierten Sicherheitslücken in der Anwendung und die implementierten Behebungsmaßnahmen.

## Identifizierte Sicherheitslücken

### 1. **Hardcodierte Secrets (CWE-798)**

**Schweregrad:** KRITISCH

**Beschreibung:**
- Der SECRET_KEY war direkt im Quellcode hardcodiert (`SECRET_KEY = "1234567890abcdef"`)
- Hardcodierte Secrets können leicht durch Code-Analyse oder durch Zugriff auf das Repository gefunden werden

**Auswirkung:**
- Kompromittierung der Anwendungssicherheit
- Möglicher unbefugter Zugriff auf geschützte Ressourcen

**Behebung:**
- SECRET_KEY wird nun aus einer Umgebungsvariable geladen
- Verwendung von `python-dotenv` zur Verwaltung von Umgebungsvariablen
- `.env` Datei wurde aus der Versionskontrolle entfernt und in `.gitignore` aufgenommen
- `.env.example` Template erstellt für Entwickler

**Code-Änderung:**
```python
# Vorher:
SECRET_KEY = "1234567890abcdef"

# Nachher:
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("Environment variable SECRET_KEY is not set!")
```

---

### 2. **Klartextspeicherung von Passwörtern (CWE-256)**

**Schweregrad:** KRITISCH

**Beschreibung:**
- Benutzerpasswörter wurden im Klartext gespeichert
- Direkter Vergleich von Klartext-Passwörtern ohne Hashing

**Auswirkung:**
- Bei Kompromittierung des Systems sind alle Passwörter sofort lesbar
- Keine Möglichkeit zur sicheren Passwortverifikation

**Behebung:**
- Implementierung von bcrypt für Passwort-Hashing
- Passwörter werden nun gehasht gespeichert
- Verwendung von `bcrypt.checkpw()` für sichere Passwortverifikation

**Code-Änderung:**
```python
# Vorher:
USERS = {
    "alice": "password123",
    "bob": "qwerty",
}

# Nachher:
# Passwörter als bcrypt-Hashes gespeichert
# Verifikation mit bcrypt.checkpw()
```

---

### 3. **Logging von Sensiblen Daten (CWE-532)**

**Schweregrad:** HOCH

**Beschreibung:**
- Passwörter wurden im Klartext in Logs geschrieben
- Hash-Eingabedaten wurden geloggt

**Auswirkung:**
- Sensible Daten können aus Logdateien extrahiert werden
- Compliance-Verstöße (DSGVO, etc.)

**Behebung:**
- Entfernung des Passwort-Loggings aus der Login-Funktion
- Reduzierung des Loggings von Hash-Eingabedaten

**Code-Änderung:**
```python
# Vorher:
logger.info(f"Login attempt for user={username} with password={password}")
logger.debug(f"Calculated insecure MD5 hash for data={data}: {h}")

# Nachher:
logger.info(f"Login attempt for user={username}")
logger.debug(f"Calculated SHA256 hash")
```

---

### 4. **Verwendung schwacher Kryptographie (CWE-327)**

**Schweregrad:** MITTEL

**Beschreibung:**
- Verwendung des MD5-Hash-Algorithmus
- MD5 ist kryptographisch gebrochen und anfällig für Kollisionsangriffe

**Auswirkung:**
- Unsichere Hash-Berechnungen
- Möglichkeit von Hash-Kollisionen

**Behebung:**
- Ersetzung von MD5 durch SHA-256
- SHA-256 ist ein sicherer, moderner Hash-Algorithmus

**Code-Änderung:**
```python
# Vorher:
h = hashlib.md5(data.encode("utf-8")).hexdigest()

# Nachher:
h = hashlib.sha256(data.encode("utf-8")).hexdigest()
```

---

### 5. **Command Injection (CWE-78)**

**Schweregrad:** KRITISCH

**Beschreibung:**
- Verwendung von `os.system()` mit nicht-validierten Benutzereingaben
- Möglichkeit zur Ausführung beliebiger Shell-Befehle durch Injection-Angriffe
- Beispiel: Eingabe von `8.8.8.8; rm -rf /` würde gefährliche Befehle ausführen

**Auswirkung:**
- Vollständige Kompromittierung des Systems
- Möglichkeit zur Ausführung beliebiger Befehle
- Datenverlust oder Systemzerstörung

**Behebung:**
- Ersetzung von `os.system()` durch `subprocess.run()` mit Argumentliste
- Implementierung strenger Input-Validierung mit Regex
- Verwendung von Timeouts zur Verhinderung von DoS-Angriffen
- Keine Shell-Interpretation (`shell=False`)

**Code-Änderung:**
```python
# Vorher:
command = f"ping -c 1 {host}"
os.system(command)  # Unsicher!

# Nachher:
# Input-Validierung
if not re.match(r'^[a-zA-Z0-9\.\-]+$', host):
    logger.error(f"Invalid host format: {host}")
    return

# Sichere Befehlsausführung
result = subprocess.run(
    ["ping", "-c", "1", host],
    capture_output=True,
    text=True,
    timeout=5,
    check=False
)
```

---

### 6. **Unsichere HTTP-Kommunikation (CWE-319)**

**Schweregrad:** HOCH

**Beschreibung:**
- Verwendung von HTTP statt HTTPS für Update-Downloads
- Keine Zertifikatsverifikation bei HTTPS-Verbindungen

**Auswirkung:**
- Man-in-the-Middle-Angriffe möglich
- Updates können abgefangen und manipuliert werden
- Keine Vertraulichkeit oder Integrität der Übertragung

**Behebung:**
- Änderung der Update-URL von HTTP zu HTTPS
- Explizite Aktivierung der Zertifikatsverifikation (`verify=True`)
- Implementierung von Timeout-Mechanismen
- Spezielle Fehlerbehandlung für SSL-Fehler

**Code-Änderung:**
```python
# Vorher:
UPDATE_URL = "http://example.com/fake-update.txt"
resp = requests.get(UPDATE_URL)

# Nachher:
UPDATE_URL = "https://example.com/fake-update.txt"
resp = requests.get(UPDATE_URL, verify=True, timeout=30)
```

---

### 7. **Fehlende Integritätsprüfung (CWE-345)**

**Schweregrad:** KRITISCH

**Beschreibung:**
- Updates wurden ohne Integritäts- oder Authentizitätsprüfung angewendet
- Keine Verifikation, ob die heruntergeladenen Daten korrekt sind

**Auswirkung:**
- Möglichkeit zur Einschleusung von Schadcode
- Kompromittierung der Anwendung durch manipulierte Updates

**Behebung:**
- Implementierung einer SHA-256-Checksum-Verifikation
- Download einer separaten Checksum-Datei
- Vergleich der berechneten mit der erwarteten Checksum
- Update wird nur angewendet, wenn die Checksum übereinstimmt

**Code-Änderung:**
```python
# Neu hinzugefügt:
UPDATE_CHECKSUM_URL = "https://example.com/fake-update.txt.sha256"

# Download und Verifikation:
checksum_resp = requests.get(UPDATE_CHECKSUM_URL, verify=True, timeout=30)
expected_checksum = checksum_resp.text.strip().split()[0]
actual_checksum = hashlib.sha256(payload.encode('utf-8')).hexdigest()

if actual_checksum != expected_checksum:
    logger.error("Update checksum verification failed!")
    return ""
```

---

### 8. **Fehlende Authentifizierung (CWE-306)**

**Schweregrad:** HOCH

**Beschreibung:**
- Alle Funktionen waren ohne Authentifizierung zugänglich
- Keine Zugriffskontrolle für sensible Operationen

**Auswirkung:**
- Unbefugter Zugriff auf Funktionalitäten
- Keine Benutzerverfolgung oder Accountability

**Behebung:**
- Implementierung einer `validate_authentication()` Funktion
- Authentifizierungsprüfung vor sensiblen Operationen
- Login-State-Management mit `LOGGED_IN_USER` Variable

**Code-Änderung:**
```python
# Neu hinzugefügt:
def validate_authentication() -> bool:
    if LOGGED_IN_USER is None:
        logger.warning("User not authenticated.")
        return False
    return True

# In den Menu-Optionen:
if not validate_authentication():
    print("Diese Funktionalität steht nur eingeloggten Benutzern zur Verfügung.")
    continue
```

---

### 9. **Secrets in Versionskontrolle (CWE-540)**

**Schweregrad:** KRITISCH

**Beschreibung:**
- Die `.env` Datei mit sensiblen Daten war in Git committed
- Passwort-Hashes und Secret Keys waren öffentlich sichtbar

**Auswirkung:**
- Kompromittierung aller in der Datei gespeicherten Secrets
- Potentieller unbefugter Zugriff auf das System

**Behebung:**
- Entfernung der `.env` Datei aus der Versionskontrolle
- Hinzufügung von `.env` zur `.gitignore`
- Erstellung einer `.env.example` Template-Datei
- Dokumentation zur sicheren Konfiguration

**Code-Änderung:**
```bash
# .gitignore aktualisiert:
.env

# .env aus Git entfernt:
git rm --cached .env
```

---

## Zusammenfassung der Änderungen

### Kritische Fixes:
1. ✅ Hardcodierte Secrets entfernt
2. ✅ Klartextpasswörter durch bcrypt-Hashes ersetzt
3. ✅ Command Injection behoben
4. ✅ Integritätsprüfung für Updates implementiert
5. ✅ Secrets aus Versionskontrolle entfernt

### Wichtige Verbesserungen:
6. ✅ HTTP durch HTTPS ersetzt
7. ✅ Zertifikatsverifikation aktiviert
8. ✅ Authentifizierung für sensible Funktionen
9. ✅ Logging von sensiblen Daten entfernt
10. ✅ MD5 durch SHA-256 ersetzt

### Zusätzliche Sicherheitsmaßnahmen:
- Input-Validierung mit Regex
- Timeout-Mechanismen
- Proper Exception Handling
- Sichere Subprocess-Ausführung
- Length-Limiting für Eingaben

---

## Verbleibende Einschränkungen

Diese Demo-Anwendung dient ausschließlich Ausbildungszwecken. Folgende Punkte sollten in einer Produktionsanwendung zusätzlich beachtet werden:

1. **Session-Management:** Implementierung eines robusten Session-Managements mit JWT oder Session-Cookies
2. **Datenbank:** Verwendung einer echten Datenbank statt In-Memory-Speicher
3. **Rate Limiting:** Schutz gegen Brute-Force-Angriffe
4. **Input-Sanitization:** Erweiterte Input-Validierung für alle Benutzereingaben
5. **Audit Logging:** Umfassendes Audit-Logging für Compliance
6. **Update-Signierung:** Verwendung digitaler Signaturen (z.B. GPG) statt nur Checksums
7. **Least Privilege:** Ausführung mit minimalen Berechtigungen
8. **Security Headers:** Bei Web-Anwendungen: CSP, HSTS, etc.

---

## Empfohlene Nächste Schritte

1. **Security Audit:** Durchführung eines vollständigen Security Audits durch externe Experten
2. **Penetration Testing:** Testen der Anwendung auf weitere Schwachstellen
3. **Dependency Scanning:** Regelmäßiges Scannen der Abhängigkeiten auf bekannte Schwachstellen
4. **Security Training:** Schulung der Entwickler in Secure Coding Practices
5. **CI/CD Integration:** Integration von Security-Tests in die CI/CD-Pipeline

---

## Referenzen

- CWE (Common Weakness Enumeration): https://cwe.mitre.org/
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- Python Security Best Practices: https://python.readthedocs.io/en/stable/library/security_warnings.html
- bcrypt Documentation: https://github.com/pyca/bcrypt

---

**Dokumentation erstellt am:** 2026-01-05  
**Version:** 1.0  
**Autor:** Security Review Team
