# Cybersecurity Project: Vulnerability Analysis and Remediation

## Übersicht

Dieses Projekt demonstriert häufige Sicherheitslücken in Python-Anwendungen und deren professionelle Behebung. Es enthält zwei Versionen einer Demo-Anwendung:

- **`insecure-application.py`**: Enthält absichtlich eingebaute Sicherheitslücken zu Schulungszwecken
- **`fixed-application.py`**: Die gesicherte Version mit allen behobenen Schwachstellen

## Wichtiger Hinweis

⚠️ **Diese Anwendung dient ausschließlich Ausbildungszwecken!**  
Die unsichere Version (`insecure-application.py`) enthält absichtlich kritische Sicherheitslücken und sollte **NIEMALS** in Produktionsumgebungen eingesetzt werden.

## Installation

### Voraussetzungen

- Python 3.8 oder höher
- pip (Python Package Manager)

### Setup

1. Repository klonen:
```bash
git clone <repository-url>
cd cybersecurity-project-7
```

2. Abhängigkeiten installieren:
```bash
pip install -r requirements.txt
```

3. Umgebungsvariablen konfigurieren:
```bash
cp .env.example .env
# Bearbeiten Sie .env und setzen Sie sichere Werte
```

**Wichtig:** Generieren Sie einen starken, zufälligen SECRET_KEY:
```bash
python -c "import secrets; print(secrets.token_hex(16))"
```

## Verwendung

### Sichere Version ausführen

```bash
python3 fixed-application.py
```

### Unsichere Version (nur zu Demonstrationszwecken)

```bash
python3 insecure-application.py
```

## Identifizierte Sicherheitslücken

Die folgende Tabelle fasst die wichtigsten Sicherheitslücken zusammen:

| ID | Schwachstelle | Schweregrad | CWE | Status |
|----|---------------|-------------|-----|--------|
| 1 | Hardcodierte Secrets | KRITISCH | CWE-798 | ✅ Behoben |
| 2 | Klartextpasswörter | KRITISCH | CWE-256 | ✅ Behoben |
| 3 | Logging sensibler Daten | HOCH | CWE-532 | ✅ Behoben |
| 4 | Schwache Kryptographie (MD5) | MITTEL | CWE-327 | ✅ Behoben |
| 5 | Command Injection | KRITISCH | CWE-78 | ✅ Behoben |
| 6 | Unsichere HTTP-Kommunikation | HOCH | CWE-319 | ✅ Behoben |
| 7 | Fehlende Integritätsprüfung | KRITISCH | CWE-345 | ✅ Behoben |
| 8 | Fehlende Authentifizierung | HOCH | CWE-306 | ✅ Behoben |
| 9 | Secrets in Versionskontrolle | KRITISCH | CWE-540 | ✅ Behoben |

Detaillierte Informationen zu jeder Schwachstelle und deren Behebung finden Sie in [SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md).

## Hauptverbesserungen

### 1. Secrets-Management
- ✅ Verwendung von Umgebungsvariablen statt Hardcoding
- ✅ `.env` aus Versionskontrolle ausgeschlossen
- ✅ `.env.example` Template für sichere Konfiguration

### 2. Passwort-Sicherheit
- ✅ bcrypt-Hashing für Passwörter
- ✅ Keine Klartext-Passwörter in Logs
- ✅ Sichere Passwortverifikation

### 3. Command Injection Prevention
- ✅ Ersetzung von `os.system()` durch `subprocess.run()`
- ✅ Strikte Input-Validierung mit Regex
- ✅ Keine Shell-Interpretation
- ✅ Timeout-Mechanismen

### 4. Sichere Kommunikation
- ✅ HTTPS statt HTTP
- ✅ TLS-Zertifikatsverifikation
- ✅ Timeout-Handling
- ✅ SSL-Error-Behandlung

### 5. Update-Sicherheit
- ✅ SHA-256 Checksum-Verifikation
- ✅ Integritätsprüfung vor Anwendung
- ✅ Sichere Download-Mechanismen

### 6. Authentifizierung & Autorisierung
- ✅ Login-System mit Session-Management
- ✅ Zugriffskontrolle für sensible Funktionen
- ✅ Logout-Funktionalität

## Architektur

```
cybersecurity-project-7/
├── insecure-application.py    # Unsichere Demo-Version (NUR zu Schulungszwecken!)
├── fixed-application.py       # Gesicherte Version mit allen Fixes
├── requirements.txt           # Python-Abhängigkeiten
├── .env.example              # Template für Umgebungsvariablen
├── .gitignore                # Git-Ignore-Regeln (inkl. .env)
├── SECURITY_ANALYSIS.md      # Detaillierte Sicherheitsanalyse
└── README.md                 # Diese Datei
```

## Sicherheits-Features

### Input-Validierung
- Regex-basierte Validierung für Hostnamen
- Längenbeschränkungen zur DoS-Prevention
- Whitelist-Ansatz für erlaubte Zeichen

### Kryptographie
- bcrypt für Passwort-Hashing (Work Factor: 10)
- SHA-256 für Checksums und Hashes
- Keine schwachen Algorithmen (MD5, SHA-1)

### Netzwerksicherheit
- TLS 1.2+ für alle externen Verbindungen
- Zertifikatsverifikation aktiviert
- Timeout-Konfiguration (30s)

### Logging
- Keine sensiblen Daten in Logs
- Strukturiertes Logging mit Log-Levels
- Audit-Trail für Authentifizierung

## Abhängigkeiten

- **bcrypt** (5.0.0): Sichere Passwort-Hashing
- **requests** (2.32.5): HTTP-Client mit TLS-Support
- **python-dotenv** (1.2.1): Umgebungsvariablen-Management

Alle Abhängigkeiten wurden auf bekannte Sicherheitslücken geprüft.

## Testing

### Manuelle Tests

Die Anwendung kann manuell getestet werden durch:

1. Start der Anwendung
2. Test aller Menüpunkte
3. Versuch von Command-Injection-Angriffen
4. Überprüfung der Logging-Ausgabe

### Sicherheitstests

Empfohlene Security-Testing-Tools:

- **CodeQL**: Statische Code-Analyse ✅ (0 Findings)
- **Bandit**: Python Security Linter
- **Safety**: Dependency Security Checker
- **OWASP ZAP**: Dynamic Application Security Testing

## Best Practices

Dieses Projekt demonstriert folgende Security Best Practices:

1. **Defense in Depth**: Mehrschichtige Sicherheitsmaßnahmen
2. **Least Privilege**: Minimale Berechtigungen
3. **Secure by Default**: Sichere Standardkonfiguration
4. **Input Validation**: Strikte Eingabevalidierung
5. **Fail Securely**: Sichere Fehlerbehandlung
6. **Separation of Concerns**: Trennung von Code und Konfiguration
7. **Security Logging**: Audit-Trail ohne sensible Daten

## Compliance & Standards

Diese Implementierung berücksichtigt:

- **OWASP Top 10**: Schutz gegen die häufigsten Web-Schwachstellen
- **CWE Top 25**: Abdeckung der gefährlichsten Software-Schwächen
- **DSGVO**: Datenschutzkonformes Logging
- **CRA**: EU Cyber Resilience Act Anforderungen

## Weiterführende Informationen

- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
- [Python Security Best Practices](https://python.readthedocs.io/en/stable/library/security_warnings.html)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

## Lizenz

Dieses Projekt dient ausschließlich Ausbildungszwecken.

## Kontakt

Für Fragen oder Feedback zu diesem Projekt, bitte ein Issue erstellen.

---

**⚠️ Wichtiger Sicherheitshinweis:**  
Verwenden Sie die `insecure-application.py` niemals in einer Produktionsumgebung oder mit Zugriff auf sensible Daten. Diese Datei enthält absichtlich Sicherheitslücken zu Demonstrationszwecken!
