#!/usr/bin/env bash

clear

# =========================
# CORES
# =========================
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
BLUE='\033[1;34m'
NC='\033[0m'

# =========================
# VARIÁVEIS
# =========================
root_hits=0
bypass_hits=0
hook_hits=0
system_hits=0
risk_score=0

timestamp=$(date +%s)
report="randol_report_$timestamp.log"
json="randol_report_$timestamp.json"

# =========================
# UI
# =========================
banner() {
  clear
  echo -e "${CYAN}"
  echo "======================================="
  echo "        SCANNER RANDOL v3"
  echo "======================================="
  echo -e "${NC}"
}

progress_bar() {
  for i in {1..20}; do
    echo -ne "${CYAN}█${NC}"
    sleep 0.03
  done
  echo ""
}

line() {
  printf "${YELLOW}%-15s${NC}: %s\n" "$1" "$2"
}

# =========================
# LOG
# =========================
log() {
  echo "$1" >> "$report"
}

# =========================
# SCAN ROOT
# =========================
scan_root() {
  echo -e "${CYAN}[*] Root...${NC}"
  progress_bar

  for path in /system/bin/su /system/xbin/su /sbin/su /vendor/bin/su /su/bin/su; do
    [ -f "$path" ] && root_hits=$((root_hits+5)) && log "[ROOT] $path"
  done

  if su -c id >/dev/null 2>&1; then
    root_hits=$((root_hits+10))
    log "[ROOT] acesso root"
  fi
}

# =========================
# BYPASS
# =========================
scan_bypass() {
  echo -e "${CYAN}[*] Bypass...${NC}"
  progress_bar

  pm list packages 2>/dev/null | grep -Ei "magisk|zygisk" >/dev/null && {
    bypass_hits=$((bypass_hits+10))
    log "[BYPASS] Magisk app"
  }

  ps -A 2>/dev/null | grep -Ei "zygisk|magisk" >/dev/null && {
    bypass_hits=$((bypass_hits+10))
    log "[BYPASS] Zygisk"
  }

  cat /proc/self/mounts 2>/dev/null | grep -qi magisk && {
    bypass_hits=$((bypass_hits+10))
    log "[BYPASS] mount magisk"
  }
}

# =========================
# HOOK
# =========================
scan_hook() {
  echo -e "${CYAN}[*] Hook...${NC}"
  progress_bar

  ps -A | grep -qi frida && {
    hook_hits=$((hook_hits+15))
    log "[HOOK] Frida"
  }

  netstat -an 2>/dev/null | grep -E "27042|27043" >/dev/null && {
    hook_hits=$((hook_hits+10))
    log "[HOOK] porta frida"
  }

  ps -A | grep -qi xposed && {
    hook_hits=$((hook_hits+10))
    log "[HOOK] Xposed"
  }
}

# =========================
# SISTEMA
# =========================
scan_system() {
  echo -e "${CYAN}[*] Sistema...${NC}"
  progress_bar

  [ "$(getprop ro.debuggable)" = "1" ] && system_hits=$((system_hits+5)) && log "[SYS] debug"

  getprop ro.build.tags | grep -qi test-keys && {
    system_hits=$((system_hits+5))
    log "[SYS] test-keys"
  }

  getenforce 2>/dev/null | grep -qi permissive && {
    system_hits=$((system_hits+10))
    log "[SYS] permissive"
  }

  mount | grep -qi overlay && {
    system_hits=$((system_hits+5))
    log "[SYS] overlay"
  }

  [ -w /system ] && {
    system_hits=$((system_hits+15))
    log "[SYS] system writable"
  }
}

# =========================
# RESULTADO
# =========================
final_result() {
  risk_score=$((root_hits + bypass_hits + hook_hits + system_hits))

  if [ "$root_hits" -ge 10 ]; then
    status="ROOT"
    color=$RED
  elif [ "$risk_score" -ge 20 ]; then
    status="SUSPEITO"
    color=$YELLOW
  else
    status="LIMPO"
    color=$GREEN
  fi

  banner

  echo -e "${color}STATUS: $status${NC}"
  line "Score" "$risk_score"
  line "Android" "$(getprop ro.build.version.release)"
  line "Modelo" "$(getprop ro.product.model)"

  echo ""
  line "Root" "$root_hits"
  line "Bypass" "$bypass_hits"
  line "Hook" "$hook_hits"
  line "Sistema" "$system_hits"

  echo ""
  echo -e "${CYAN}Log:${NC} $report"

  # JSON
  cat <<EOF > $json
{
  "status": "$status",
  "score": $risk_score,
  "root": $root_hits,
  "bypass": $bypass_hits,
  "hook": $hook_hits,
  "system": $system_hits
}
EOF

  echo -e "${CYAN}JSON:${NC} $json"
}

# =========================
# MENU
# =========================
menu() {
  banner
  echo "1) Scan completo"
  echo "2) Scan rápido"
  echo "3) Sair"
  echo ""
  read -p "Escolha: " opt

  case $opt in
    1)
      scan_root
      scan_bypass
      scan_hook
      scan_system
      final_result
      ;;
    2)
      scan_root
      scan_system
      final_result
      ;;
    3)
      exit
      ;;
    *)
      echo "Opção inválida"
      sleep 1
      menu
      ;;
  esac
}

menu
