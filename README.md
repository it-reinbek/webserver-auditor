# Webserver Security Auditor & Remediation Tool (`webserver-audit.sh`)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Audit Target: Apache & NGINX](https://img.shields.io/badge/Target-Apache%20%26%20NGINX-brightgreen.svg)](#)
[![Vulnerabilities: 2026 HTTP/2 Criticals](https://img.shields.io/badge/Vulnerabilities-2026%20HTTP%2F2-red.svg)](#)
[![Release: v1.1.0](https://img.shields.io/badge/Release-v1.1.0-green.svg)](https://github.com/it-reinbek/webserver-auditor/releases)

Language / Sprache: **[🇬🇧 English](README.md)** | **[🇩🇪 Deutsch](README.de.md)**

---

Standalone Bash auditing and emergency remediation tool designed to detect and mitigate critical 2026 web server vulnerabilities in **Apache HTTP Server** and **NGINX**.

Developed by [IT-Reinbek](https://it-reinbek.de/) · Documentation & Repository: [github.com/it-reinbek/webserver-auditor](https://github.com/it-reinbek/webserver-auditor)

---

### 🔍 Covered Vulnerabilities
* **Apache HTTP Server (CVE-2026-119618):** Race condition in `mod_http2` (`assign_headers()`) enabling unauthenticated Remote Code Execution.
* **NGINX Web Server (CVE-2026-123007 & CVE-2026-123634):** Integer underflow & heap memory corruption flaws in HTTP/2 frame parsing.
* **Worker Process Forensics:** Detection of anomalous child processes (interactive shells, socket relay tools) spawned under webserver worker users (`www-data`, `nginx`, `apache`, `nobody`, `_nginx`, `_www`, `lighttpd`).

---

### 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/it-reinbek/webserver-auditor.git
cd webserver-auditor

# Start interactive wizard (root recommended for remediation)
sudo ./webserver-audit.sh

# Non-interactive audit only (ideal for Cronjobs and CI/CD)
./webserver-audit.sh --no-menu

# Audit with strict exit codes (exits with code 1 if critical flaws are found)
./webserver-audit.sh --audit --strict

# Export sanitized audit report directly
./webserver-audit.sh --report /var/log/webserver-audit-report.txt
```

---

### 📋 Key Features (v1.1.0)
* **Modular Submenus:** Dedicated management and mitigation interfaces for Apache and NGINX.
* **Reversible Emergency Remediation:** Disabling HTTP/2 or enforcing HTTP/1.1 (`Protocols http/1.1` in Apache, `http2 off;` & buffer hardening in NGINX) with privilege verification and 1-click rollback.
* **Process Forensics:** Recursive inspection of web server worker child processes for spawned reverse shells (`python3`, `bash`, `sh`, `nc`, `socat`, etc.).
* **Clean Report Export:** ANSI-sanitized audit reports exported to `/var/log/webserver-audit-report.txt` (with automatic fallback to local directory for non-root users).
* **Terminal & Color Awareness:** Automatic suppression of ANSI colors and screen clears in pipelines, non-interactive shells, or when `NO_COLOR=1` is set.
* **Audit Logging:** Systematic logging of all security operations, mitigations, and findings.

---

### 🛡️ Remediation Details

#### Apache HTTP Server (CVE-2026-119618)
* Disables `http2` module via `a2dismod http2`.
* Places an isolated drop-in configuration (`99-mitigate-cve-2026-119618.conf`) enforcing `Protocols http/1.1`.
* Reversible at any time via Submenu option 3 or by removing the drop-in.

#### NGINX Webserver (CVE-2026-123007 & Buffer Hardening)
* Places drop-in hardening under `/etc/nginx/conf.d/99-mitigate-http2-hardening.conf`.
* Enforces `http2 off;` (for NGINX $\ge$ 1.25.1) and restricts client header buffer sizes (`client_header_buffer_size 1k;`, `large_client_header_buffers 4 8k;`, `server_tokens off;`).
* Validates configuration syntax with `nginx -t` before reloading.

---

### 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
Copyright (c) 2026 IT-Reinbek.
