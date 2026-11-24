#!/usr/bin/env bash
#
# webserver-audit.sh - Webserver Security Auditor & Remediation Tool
# Audits Apache HTTP Server and NGINX for critical 2026 vulnerabilities:
# - Apache mod_http2 Race Condition (CVE-2026-119618)
# - NGINX HTTP/2 Frame / Buffer Handling (CVE-2026-123007 & CVE-2026-123634)
# - Rogue worker subprocesses and webshell / reverse shell detection
#
set -euo pipefail

VERSION="1.1.0"
LANG_UI="${LANG_UI:-de}"

# Privileges and path initialization
if [ "$(id -u)" -eq 0 ]; then
  STATE_DIR="/var/lib/webserver-auditor"
  LOG_FILE="/var/log/webserver-audit.log"
  DEFAULT_REPORT_FILE="/var/log/webserver-audit-report.txt"
else
  STATE_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/webserver-auditor"
  LOG_FILE="${STATE_DIR}/webserver-audit.log"
  DEFAULT_REPORT_FILE="${PWD}/webserver-audit-report.txt"
fi
BACKUP_DIR="${STATE_DIR}/backups"

# ANSI Colors (only when in interactive terminal and NO_COLOR is not set)
setup_colors() {
  if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    NC='\033[0m'
  else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
    BOLD=''
    NC=''
  fi
}
setup_colors

# Audit counters
CRIT_COUNT=0
WARN_COUNT=0
OK_COUNT=0

init_storage() {
  mkdir -p "${STATE_DIR}" "${BACKUP_DIR}" 2>/dev/null || true
  if [ "$(id -u)" -eq 0 ]; then
    chmod 700 "${STATE_DIR}" 2>/dev/null || true
  fi
}

log_message() {
  local msg="$1"
  local ts
  ts=$(date '+%Y-%m-%d %H:%M:%S')
  local log_dir
  log_dir=$(dirname "${LOG_FILE}")
  if [ -d "${log_dir}" ] && [ -w "${log_dir}" ]; then
    echo "[${ts}] ${msg}" >> "${LOG_FILE}" 2>/dev/null || true
  fi
}

print_header() {
  if [ -t 1 ] && [ -z "${NO_CLEAR:-}" ]; then
    clear 2>/dev/null || true
  fi
  echo -e "${CYAN}======================================================================${NC}"
  echo -e "${BOLD}  Webserver Security Auditor v${VERSION} (Apache & NGINX)${NC}"
  echo -e "${CYAN}======================================================================${NC}"
  echo ""
}

# ==================== APACHE AUDITING ====================

audit_apache() {
  echo -e "${BOLD}[1] Auditierung: Apache HTTP Server${NC}"
  echo "--------------------------------------------------"
  local ap_bin=""
  for b in apache2 httpd /usr/sbin/apache2 /usr/sbin/httpd; do
    if command -v "$b" >/dev/null 2>&1; then
      ap_bin="$b"
      break
    fi
  done

  if [ -z "$ap_bin" ]; then
    echo -e "${BLUE}[INFO]${NC} Kein Apache HTTP Server auf diesem Host gefunden."
    return 0
  fi

  local ap_ver
  ap_ver=$("$ap_bin" -v 2>&1 | head -n 1)
  echo -e "${BLUE}[INFO]${NC} Gefundene Binärdatei: ${ap_bin} (${ap_ver})"

  # Check active modules
  local mods=""
  if "$ap_bin" -M >/dev/null 2>&1; then
    mods=$("$ap_bin" -M 2>&1)
  fi

  if echo "$mods" | grep -qi "http2_module"; then
    echo -e "${YELLOW}[WARN]${NC} Apache mod_http2 ist aktiv geladen."
    # Check if Protocols directive enables h2
    local h2_conf=0
    for conf_dir in /etc/apache2 /etc/httpd /usr/local/apache2/conf; do
      if [ -d "$conf_dir" ]; then
        if grep -rnEi "Protocols.*h2" "$conf_dir" 2>/dev/null | grep -v "#" >/dev/null; then
          h2_conf=1
          break
        fi
      fi
    done

    if [ "$h2_conf" -eq 1 ]; then
      echo -e "${RED}[CRIT]${NC} CVE-2026-119618: Apache mod_http2 ist geladen und HTTP/2 ('h2'/'h2c') ist konfiguriert!"
      echo -e "       Risiko: Race Condition in assign_headers() ermöglicht unauthentifizierte RCE."
      CRIT_COUNT=$((CRIT_COUNT + 1))
    else
      echo -e "${YELLOW}[WARN]${NC} mod_http2 ist geladen, aber keine explizite 'Protocols h2'-Direktive gefunden."
      WARN_COUNT=$((WARN_COUNT + 1))
    fi
  else
    echo -e "${GREEN}[ OK ]${NC} Apache mod_http2 ist nicht aktiv geladen."
    OK_COUNT=$((OK_COUNT + 1))
  fi

  # Check ServerTokens & ServerSignature
  local sec_tokens
  sec_tokens=$(grep -rEi "ServerTokens\s+(Full|OS|Min)" /etc/apache2 /etc/httpd 2>/dev/null | grep -v "#" || true)
  if [ -n "$sec_tokens" ]; then
    echo -e "${YELLOW}[WARN]${NC} ServerTokens gibt detaillierte Versionsinformationen preis."
    WARN_COUNT=$((WARN_COUNT + 1))
  else
    echo -e "${GREEN}[ OK ]${NC} ServerTokens ist restriktiv oder Standard."
    OK_COUNT=$((OK_COUNT + 1))
  fi
  echo ""
}

# ==================== NGINX AUDITING ====================

audit_nginx() {
  echo -e "${BOLD}[2] Auditierung: NGINX Webserver${NC}"
  echo "--------------------------------------------------"
  if ! command -v nginx >/dev/null 2>&1; then
    echo -e "${BLUE}[INFO]${NC} Kein NGINX Webserver auf diesem Host gefunden."
    return 0
  fi

  local ng_ver
  ng_ver=$(nginx -v 2>&1)
  echo -e "${BLUE}[INFO]${NC} Gefundene Binärdatei: $(command -v nginx) (${ng_ver})"

  # Check HTTP/2 configuration
  local http2_found=0
  if [ -d /etc/nginx ]; then
    if grep -rnEi "listen\s+.*http2|http2\s+on;" /etc/nginx 2>/dev/null | grep -v "#" >/dev/null; then
      http2_found=1
    fi
  fi

  if [ "$http2_found" -eq 1 ]; then
    echo -e "${RED}[CRIT]${NC} CVE-2026-123007 / CVE-2026-123634: NGINX hat HTTP/2 aktiviert!"
    echo -e "       Risiko: Integer Underflow & Memory Corruption bei der Frame-Verarbeitung."
    CRIT_COUNT=$((CRIT_COUNT + 1))
  else
    echo -e "${GREEN}[ OK ]${NC} Keine aktiven 'http2 on;' oder 'listen ... http2' Direktiven in /etc/nginx gefunden."
    OK_COUNT=$((OK_COUNT + 1))
  fi

  # Check server_tokens
  if grep -rnEi "server_tokens\s+off;" /etc/nginx 2>/dev/null | grep -v "#" >/dev/null; then
    echo -e "${GREEN}[ OK ]${NC} NGINX server_tokens ist deaktiviert (Information Disclosure Schutz)."
    OK_COUNT=$((OK_COUNT + 1))
  else
    echo -e "${YELLOW}[WARN]${NC} NGINX server_tokens ist nicht explizit auf 'off' gesetzt."
    WARN_COUNT=$((WARN_COUNT + 1))
  fi
  echo ""
}

# ==================== PROCESS & FORENSICS AUDITING ====================

audit_processes() {
  echo -e "${BOLD}[3] Auditierung: Webserver-Prozesse & Verdächtige Subprozesse${NC}"
  echo "--------------------------------------------------"
  local rogue=0
  local susp_patterns="bash|sh|dash|zsh|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|php[0-9.]*|nc|ncat|netcat|curl|wget|socat"

  # Find worker processes across common webserver user accounts
  local pids
  pids=$(pgrep -u www-data,nginx,apache,httpd,nobody,_nginx,_www,lighttpd 2>/dev/null || true)

  if [ -n "$pids" ]; then
    for pid in $pids; do
      local children
      children=$(pgrep -P "$pid" 2>/dev/null || true)
      for cpid in $children; do
        local ccomm
        ccomm=$(ps -p "$cpid" -o comm= 2>/dev/null || true)
        if echo "$ccomm" | grep -qE "^(${susp_patterns})$"; then
          local cmdline=""
          if [ -r "/proc/${cpid}/cmdline" ]; then
            cmdline=$(tr '\0' ' ' < "/proc/${cpid}/cmdline" 2>/dev/null || true)
          fi
          if [ -z "$cmdline" ]; then
            cmdline="$ccomm"
          fi
          echo -e "${RED}[CRIT]${NC} Verdächtiger Child-Prozess unter Webserver-Worker gefunden!"
          echo -e "       PID: ${cpid} (Parent Worker: ${pid}) | Befehl: ${cmdline}"
          log_message "CRIT: Verdächtiger Child-Prozess gefunden (PID: ${cpid}, Parent: ${pid}, Befehl: ${cmdline})"
          rogue=$((rogue + 1))
        fi
      done
    done
  fi

  if [ "$rogue" -eq 0 ]; then
    echo -e "${GREEN}[ OK ]${NC} Keine verdächtigen Child-Prozesse (Shells/Netcat/Python) unter Webserver-Workern aktiv."
    OK_COUNT=$((OK_COUNT + 1))
  else
    CRIT_COUNT=$((CRIT_COUNT + rogue))
  fi
  echo ""
}

# ==================== REMEDIATION ACTIONS ====================

apply_apache_mitigation() {
  echo -e "${YELLOW}--> Wende Notfall-Mitigation für Apache (CVE-2026-119618) an...${NC}"
  if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[FEHLER] Root-Rechte erforderlich.${NC}"
    return 1
  fi

  if command -v a2dismod >/dev/null 2>&1; then
    a2dismod http2 2>/dev/null || true
  fi

  # Add drop-in config to enforce HTTP/1.1
  if [ -d /etc/apache2/conf-available ]; then
    echo "Protocols http/1.1" > /etc/apache2/conf-available/99-mitigate-cve-2026-119618.conf
    a2enconf 99-mitigate-cve-2026-119618 2>/dev/null || true
    echo "1" > "${STATE_DIR}/apache_http2_mitigated"
    log_message "Apache Notfall-Mitigation aktiviert: Protocols http/1.1 erzwungen."
    echo -e "${GREEN}[ERFOLG] Apache Drop-in aktiviert: 'Protocols http/1.1' erzwungen.${NC}"
    if command -v apache2ctl >/dev/null 2>&1; then
      if apache2ctl configtest >/dev/null 2>&1; then
        systemctl reload apache2 2>/dev/null || true
        echo -e "${GREEN}[ERFOLG] Apache neu geladen.${NC}"
      fi
    fi
  elif [ -d /etc/httpd/conf.d ]; then
    echo "Protocols http/1.1" > /etc/httpd/conf.d/99-mitigate-cve-2026-119618.conf
    echo "1" > "${STATE_DIR}/apache_http2_mitigated"
    log_message "HTTPD Notfall-Mitigation aktiviert: Protocols http/1.1 erzwungen."
    systemctl reload httpd 2>/dev/null || true
    echo -e "${GREEN}[ERFOLG] HTTPD Drop-in aktiviert und Dienst neu geladen.${NC}"
  else
    echo -e "${YELLOW}[WARNUNG] Konnte Standard-Apache-Konfigurationspfade nicht ermitteln.${NC}"
  fi
}

revert_apache_mitigation() {
  echo -e "${YELLOW}--> Mache Apache-Mitigation rückgängig...${NC}"
  if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[FEHLER] Root-Rechte erforderlich für Rollback.${NC}"
    return 1
  fi

  rm -f /etc/apache2/conf-available/99-mitigate-cve-2026-119618.conf \
        /etc/apache2/conf-enabled/99-mitigate-cve-2026-119618.conf \
        /etc/httpd/conf.d/99-mitigate-cve-2026-119618.conf \
        "${STATE_DIR}/apache_http2_mitigated" 2>/dev/null || true
  if command -v a2enmod >/dev/null 2>&1; then
    a2enmod http2 2>/dev/null || true
  fi
  systemctl reload apache2 2>/dev/null || systemctl reload httpd 2>/dev/null || true
  log_message "Apache Notfall-Mitigation rückgängig gemacht."
  echo -e "${GREEN}[ERFOLG] Apache-Mitigation wurde rückabgewickelt.${NC}"
}

apply_nginx_mitigation() {
  echo -e "${YELLOW}--> Wende Notfall-Mitigation für NGINX (CVE-2026-123007 & Buffer Hardening) an...${NC}"
  if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[FEHLER] Root-Rechte erforderlich.${NC}"
    return 1
  fi

  local ng_conf_dir="/etc/nginx/conf.d"
  if [ ! -d "$ng_conf_dir" ] && [ -d /etc/nginx ]; then
    mkdir -p "$ng_conf_dir" 2>/dev/null || true
  fi

  if [ -d "$ng_conf_dir" ]; then
    local dropin_file="${ng_conf_dir}/99-mitigate-http2-hardening.conf"
    
    # Try mitigation with http2 off directive first (supported in NGINX >= 1.25.1)
    cat <<'EOF' > "$dropin_file"
# Webserver-Auditor Emergency Mitigation (CVE-2026-123007 & Buffer Hardening)
client_header_buffer_size 1k;
large_client_header_buffers 4 8k;
server_tokens off;
http2 off;
EOF

    # Verify configuration with nginx -t
    if command -v nginx >/dev/null 2>&1; then
      if ! nginx -t >/dev/null 2>&1; then
        # If 'http2 off;' is rejected (older NGINX), fall back to buffer hardening
        cat <<'EOF' > "$dropin_file"
# Webserver-Auditor Emergency Mitigation (Buffer & Header Protection)
client_header_buffer_size 1k;
large_client_header_buffers 4 8k;
server_tokens off;
EOF
        echo -e "${YELLOW}[INFO] 'http2 off;' wird von dieser NGINX-Version nicht unterstützt. Pufferhärtung angewendet.${NC}"
      fi
    fi

    echo "1" > "${STATE_DIR}/nginx_mitigated"
    log_message "NGINX Notfall-Härtung aktiviert unter ${dropin_file}"
    echo -e "${GREEN}[ERFOLG] NGINX Härtungs-Drop-in unter ${dropin_file} abgelegt.${NC}"
    if command -v nginx >/dev/null 2>&1; then
      if nginx -t >/dev/null 2>&1; then
        systemctl reload nginx 2>/dev/null || true
        echo -e "${GREEN}[ERFOLG] NGINX Konfiguration geprüft und Dienst neu geladen.${NC}"
      else
        echo -e "${RED}[WARNUNG] NGINX Konfigurationstest fehlgeschlagen! Bitte manuell prüfen.${NC}"
      fi
    fi
  else
    echo -e "${YELLOW}[WARNUNG] /etc/nginx existiert nicht.${NC}"
  fi
}

revert_nginx_mitigation() {
  echo -e "${YELLOW}--> Mache NGINX-Mitigation rückgängig...${NC}"
  if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[FEHLER] Root-Rechte erforderlich für Rollback.${NC}"
    return 1
  fi

  rm -f /etc/nginx/conf.d/99-mitigate-http2-hardening.conf "${STATE_DIR}/nginx_mitigated" 2>/dev/null || true
  if command -v nginx >/dev/null 2>&1 && nginx -t >/dev/null 2>&1; then
    systemctl reload nginx 2>/dev/null || true
  fi
  log_message "NGINX Notfall-Mitigation rückgängig gemacht."
  echo -e "${GREEN}[ERFOLG] NGINX-Mitigation rückabgewickelt.${NC}"
}

# ==================== REPORT EXPORT ====================

export_report() {
  local target="${1:-$DEFAULT_REPORT_FILE}"
  echo -e "${YELLOW}--> Exportiere Audit-Bericht nach: ${target}...${NC}"

  local target_dir
  target_dir=$(dirname "$target")
  if [ ! -d "$target_dir" ] || [ ! -w "$target_dir" ]; then
    local fallback_target="${PWD}/webserver-audit-report.txt"
    echo -e "${YELLOW}[HINWEIS] Zielverzeichnis '${target_dir}' nicht beschreibbar.${NC}"
    echo -e "${YELLOW}          Weiche auf Arbeitsverzeichnis aus: ${fallback_target}${NC}"
    target="$fallback_target"
  fi

  # Run full audit cleanly stripped of ANSI escape sequences and screen clears
  (
    NO_COLOR=1 NO_CLEAR=1 run_full_audit
  ) | sed -r 's/\x1B\[[0-9;]*[mK]//g' > "$target" 2>&1

  if [ -s "$target" ]; then
    echo -e "${GREEN}[ERFOLG] Bericht erfolgreich gespeichert in: ${target}${NC}"
    log_message "Audit-Bericht exportiert nach: ${target}"
  else
    echo -e "${RED}[FEHLER] Bericht konnte nicht geschrieben werden.${NC}"
    return 1
  fi
}

# ==================== INTERACTIVE SUBMENUS ====================

submenu_apache() {
  while true; do
    print_header
    echo -e "${BOLD}UNTERMENÜ: Apache HTTP Server Management & Härtung${NC}"
    echo "--------------------------------------------------"
    local status_txt="Inaktiv [ ]"
    [ -f "${STATE_DIR}/apache_http2_mitigated" ] && status_txt="${GREEN}Aktiv [x]${NC}"
    echo -e "Status HTTP/2 Mitigation: ${status_txt}"
    echo ""
    echo "  1) Apache Live-Audit durchführen"
    echo "  2) Notfall-Mitigation aktivieren (HTTP/2 deaktivieren: CVE-2026-119618)"
    echo "  3) Notfall-Mitigation rückgängig machen (Rollback)"
    echo "  4) Apache Konfiguration testen (configtest) & Status"
    echo "  5) Zurück zum Hauptmenü"
    echo ""
    read -rp "Auswahl [1-5]: " achoice
    case "$achoice" in
      1)
        CRIT_COUNT=0; WARN_COUNT=0; OK_COUNT=0
        audit_apache
        read -rp "Drücken Sie [Enter] zum Fortfahren..." ;;
      2) apply_apache_mitigation; read -rp "Drücken Sie [Enter] zum Fortfahren..." ;;
      3) revert_apache_mitigation; read -rp "Drücken Sie [Enter] zum Fortfahren..." ;;
      4)
        if command -v apache2ctl >/dev/null 2>&1; then
          apache2ctl configtest
        elif command -v httpd >/dev/null 2>&1; then
          httpd -t
        elif command -v apachectl >/dev/null 2>&1; then
          apachectl configtest
        else
          echo -e "${BLUE}[INFO]${NC} Kein Apache-Befehl (apache2ctl/httpd) gefunden."
        fi
        systemctl status apache2 --no-pager 2>/dev/null || systemctl status httpd --no-pager 2>/dev/null || true
        read -rp "Drücken Sie [Enter] zum Fortfahren..." ;;
      5) break ;;
      *) echo "Ungültige Auswahl." ; sleep 1 ;;
    esac
  done
}

submenu_nginx() {
  while true; do
    print_header
    echo -e "${BOLD}UNTERMENÜ: NGINX Webserver Management & Härtung${NC}"
    echo "--------------------------------------------------"
    local status_txt="Inaktiv [ ]"
    [ -f "${STATE_DIR}/nginx_mitigated" ] && status_txt="${GREEN}Aktiv [x]${NC}"
    echo -e "Status NGINX Mitigation: ${status_txt}"
    echo ""
    echo "  1) NGINX Live-Audit durchführen"
    echo "  2) Notfall-Härtung aktivieren (HTTP/2 Abschaltung & Puffer-Schutz)"
    echo "  3) Notfall-Härtung rückgängig machen (Rollback)"
    echo "  4) NGINX Konfiguration testen (nginx -t) & Status"
    echo "  5) Zurück zum Hauptmenü"
    echo ""
    read -rp "Auswahl [1-5]: " nchoice
    case "$nchoice" in
      1)
        CRIT_COUNT=0; WARN_COUNT=0; OK_COUNT=0
        audit_nginx
        read -rp "Drücken Sie [Enter] zum Fortfahren..." ;;
      2) apply_nginx_mitigation; read -rp "Drücken Sie [Enter] zum Fortfahren..." ;;
      3) revert_nginx_mitigation; read -rp "Drücken Sie [Enter] zum Fortfahren..." ;;
      4)
        if command -v nginx >/dev/null 2>&1; then
          nginx -t 2>&1 || true
        else
          echo -e "${BLUE}[INFO]${NC} Kein NGINX-Befehl auf diesem System gefunden."
        fi
        systemctl status nginx --no-pager 2>/dev/null || true
        read -rp "Drücken Sie [Enter] zum Fortfahren..." ;;
      5) break ;;
      *) echo "Ungültige Auswahl." ; sleep 1 ;;
    esac
  done
}

run_full_audit() {
  print_header
  CRIT_COUNT=0
  WARN_COUNT=0
  OK_COUNT=0

  audit_apache
  audit_nginx
  audit_processes

  echo "=================================================="
  echo -e "${BOLD}AUDIT-ZUSAMMENFASSUNG:${NC}"
  echo -e "  Kritische Befunde (CRIT): ${RED}${CRIT_COUNT}${NC}"
  echo -e "  Warnungen         (WARN): ${YELLOW}${WARN_COUNT}${NC}"
  echo -e "  Sichere Prüfungen ( OK ): ${GREEN}${OK_COUNT}${NC}"
  echo "=================================================="
  echo ""
}

main_menu() {
  while true; do
    print_header
    echo -e "${BOLD}HAUPTMENÜ:${NC}"
    echo "  1) Vollständiges System-Audit ausführen (Apache + NGINX + Forensik)"
    echo "  2) Untermenü: Apache HTTP Server (CVE-2026-119618)"
    echo "  3) Untermenü: NGINX Webserver (CVE-2026-123007 & Buffer)"
    echo "  4) Forensik-Check: Laufende Worker & Child-Prozesse analysieren"
    echo "  5) Audit-Bericht exportieren (${DEFAULT_REPORT_FILE})"
    echo "  q) Beenden"
    echo ""
    read -rp "Ihre Wahl: " mchoice
    case "$mchoice" in
      1) run_full_audit; read -rp "Drücken Sie [Enter] für das Menü..." ;;
      2) submenu_apache ;;
      3) submenu_nginx ;;
      4)
        print_header
        CRIT_COUNT=0; WARN_COUNT=0; OK_COUNT=0
        audit_processes
        read -rp "Drücken Sie [Enter] für das Menü..." ;;
      5)
        export_report
        read -rp "Drücken Sie [Enter] für das Menü..." ;;
      q|Q) echo "Beende."; exit 0 ;;
      *) echo "Ungültige Option."; sleep 1 ;;
    esac
  done
}

# CLI Argument handling & Entrypoint
init_storage

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  STRICT_MODE=0
  REPORT_MODE=0
  REPORT_OUT=""
  AUDIT_MODE=0

  while [ $# -gt 0 ]; do
    case "$1" in
      --audit|--no-menu)
        AUDIT_MODE=1
        shift ;;
      --strict)
        STRICT_MODE=1
        shift ;;
      --report)
        REPORT_MODE=1
        if [ $# -gt 1 ] && [[ "$2" != --* ]]; then
          REPORT_OUT="$2"
          shift 2
        else
          shift
        fi ;;
      -h|--help)
        echo "Verwendung: $0 [OPTIONEN]"
        echo ""
        echo "Optionen:"
        echo "  --audit, --no-menu     Vollständiges Audit direkt ausführen und beenden"
        echo "  --strict               Mit Exit-Code 1 beenden, falls kritische Schwachstellen vorliegen"
        echo "  --report [DATEI]       Audit durchführen und sauberen Revisionsbericht speichern"
        echo "  -h, --help             Diese Hilfe anzeigen"
        echo "  (Ohne Argumente)       Interaktives Konsolenmenü starten"
        exit 0 ;;
      *)
        echo "Unbekannte Option: $1"
        echo "Verwenden Sie '$0 --help' für weitere Informationen."
        exit 1 ;;
    esac
  done

  if [ "$REPORT_MODE" -eq 1 ]; then
    export_report "$REPORT_OUT"
    if [ "$STRICT_MODE" -eq 1 ] && [ "$CRIT_COUNT" -gt 0 ]; then
      exit 1
    fi
    exit 0
  fi

  if [ "$AUDIT_MODE" -eq 1 ]; then
    run_full_audit
    if [ "$STRICT_MODE" -eq 1 ] && [ "$CRIT_COUNT" -gt 0 ]; then
      exit 1
    fi
    exit 0
  fi

  main_menu
fi
