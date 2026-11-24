# Webserver Security Auditor & Remediation Tool (`webserver-audit.sh`)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Audit Target: Apache & NGINX](https://img.shields.io/badge/Target-Apache%20%26%20NGINX-brightgreen.svg)](#)
[![Vulnerabilities: 2026 HTTP/2 Criticals](https://img.shields.io/badge/Vulnerabilities-2026%20HTTP%2F2-red.svg)](#)
[![Release: v1.1.0](https://img.shields.io/badge/Release-v1.1.0-green.svg)](https://github.com/it-reinbek/webserver-auditor/releases)

Language / Sprache: **[🇬🇧 English](README.md)** | **[🇩🇪 Deutsch](README.de.md)**

---

Eigenständiges Bash-Audit- und Notfall-Remediation-Tool zur Erkennung und Absicherung gegen die kritischen 2026er Webserver-Sicherheitslücken in **Apache HTTP Server** und **NGINX**.

Entwickelt von [IT-Reinbek](https://it-reinbek.de/) · Dokumentation & Repository: [github.com/it-reinbek/webserver-auditor](https://github.com/it-reinbek/webserver-auditor)

---

### 🔍 Erkannte Schwachstellen
* **Apache HTTP Server (CVE-2026-119618):** Race Condition in `assign_headers()` innerhalb des Moduls `mod_http2`, die zu Heap-Korruption und unauthentifizierter Remote Code Execution (RCE) führen kann.
* **NGINX Webserver (CVE-2026-123007 & CVE-2026-123634):** Integer Underflow & Speicher-Korruptionen bei der Verarbeitung malformierter HTTP/2-Frames.
* **Webserver Worker Forensics:** Erkennung bösartiger Subprozesse (Reverse Shells wie `bash`, `sh`, `nc`, `python`, `curl`, `socat`) unter Webserver-Benutzern (`www-data`, `nginx`, `apache`, `nobody`, `_nginx`, `_www`, `lighttpd`).

---

### 🚀 Schnellstart

```bash
# Repository klonen
git clone https://github.com/it-reinbek/webserver-auditor.git
cd webserver-auditor

# Tool starten (interaktiv mit Untermenüs - Root für Härtung empfohlen)
sudo ./webserver-audit.sh

# Nur Scan durchführen (z. B. für Cronjobs oder CI)
./webserver-audit.sh --no-menu

# Scan mit automatischem Exit-Code bei Schwachstellen (CI/CD)
./webserver-audit.sh --audit --strict

# Revisionsbericht ohne ANSI-Steuerzeichen direkt exportieren
./webserver-audit.sh --report /var/log/webserver-audit-report.txt
```

---

### 📋 Wichtigste Funktionen (v1.1.0)
* **Modulare Untermenüs:** Getrennte Steuerungs- und Härtungsbereiche für Apache und NGINX.
* **Reversible Notfall-Mitigation:** Vorübergehendes Abschalten von HTTP/2 bzw. Erzwingen von HTTP/1.1 (`Protocols http/1.1` in Apache bzw. `http2 off;` / Pufferhärtung in NGINX) über Drop-in-Konfigurationen inkl. Rollback mit Rechteprüfung.
* **Forensischer Prozess-Scanner:** Rekursive Prüfung aller Kindprozesse von laufenden Webserver-Workern (`www-data`, `nginx`, `apache`, `nobody`, etc.) auf Reverse Shells (`python3`, `bash`, `nc`, `socat` etc.).
* **Sauberer Berichtsexport:** Generierung ANSI-bereinigter Revisions-Berichte nach `/var/log/webserver-audit-report.txt` (mit automatischem Fallback ins lokale Verzeichnis bei Ausführung ohne Root).
* **Automatisierte Terminal- & Farb-Erkennung:** Automatische Unterdrückung von ANSI-Farbcodes und Clear-Screen bei Pipes, Weiterleitungen oder gesetztem `NO_COLOR=1`.
* **Protokollierung:** Strukturierte Audit-Logs aller durchgeführten Maßnahmen und Befunde.

---

### 🛡️ Details zu den Gegenmaßnahmen

#### Apache HTTP Server (CVE-2026-119618)
* Deaktiviert das Modul `http2` via `a2dismod http2`.
* Erstellt eine isolierte Drop-in-Konfiguration (`99-mitigate-cve-2026-119618.conf`), die `Protocols http/1.1` erzwingt.
* Jederzeit reversibel über Untermenüpunkt 3 oder Löschen der Drop-in-Datei.

#### NGINX Webserver (CVE-2026-123007 & Pufferhärtung)
* Hinterlegt ein Härtungs-Drop-in unter `/etc/nginx/conf.d/99-mitigate-http2-hardening.conf`.
* Erzwingt `http2 off;` (ab NGINX $\ge$ 1.25.1) sowie restriktive Header-Puffer (`client_header_buffer_size 1k;`, `large_client_header_buffers 4 8k;`, `server_tokens off;`).
* Prüft vor jedem Neuladen die Syntax mit `nginx -t`.

---

### 📄 Lizenz

Dieses Projekt ist unter der MIT-Lizenz lizenziert - siehe die Datei [LICENSE](LICENSE) für Details.
Copyright (c) 2026 IT-Reinbek.
