#!/usr/bin/env bash

clear

# =========================
# CORES
# =========================
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
GRAY='\033[0;37m'
NC='\033[0m'

# =========================
# VARIÁVEIS
# =========================
root_hits=0
bypass_hits=0
hook_hits=0
system_hits=0
app_hits=0
env_hits=0
risk_score=0

start_time=$(date +%s)
device_hash=$(getprop ro.serialno 2>/dev/null | md5sum | cut -c1-8)

mkdir -p logs

# =========================
# UI
# =========================
banner() {
  clear
  echo -e "${CYAN}"
  echo "╔══════════════════════════════════════╗"
  echo "║         SCANNER RANDOL v10           ║"
  echo "║            PRO EDITION               ║"
  echo "╚══════════════════════════════════════╝"
  echo -e "${NC}"
}

loading() {
  echo -ne "${WHITE}[$1] ${NC}"
  for i in {1..15}; do
    echo -ne "${GRAY}▓${NC}"
    sleep 0.01
  done
  echo -e " ${GREEN}OK${NC}"
}

line() {
  printf "${WHITE}➤ %-12s${NC}: %s\n" "$1" "$2"
}

safe_exec() {
  timeout 2 "$@" >/dev/null 2>&1
}

# =========================
# CHECKS
# =========================

check_su() {
  for p in /system/bin/su /system/xbin/su /sbin/su; do
    [ -f "$p" ] && root_hits=$((root_hits+5))
  done

  command -v su >/dev/null && root_hits=$((root_hits+5))

  su -c id >/dev/null 2>&1 && root_hits=$((root_hits+25))
}

check_mounts() {
  mount | grep -E " /system | /vendor " | grep -q "rw," && root_hits=$((root_hits+15))
}

check_props() {
  getprop ro.debuggable | grep -q "1" && system_hits=$((system_hits+10))
  getprop ro.secure | grep -q "0" && system_hits=$((system_hits+10))
  getprop ro.build.tags | grep -qi "test-keys" && system_hits=$((system_hits+10))
}

check_magisk() {
  [ -d "/sbin/.magisk" ] && bypass_hits=$((bypass_hits+25))
  [ -d "/data/adb" ] && bypass_hits=$((bypass_hits+15))
}

check_frida() {
  ps -A 2>/dev/null | grep -v grep | grep -qi "frida" && hook_hits=$((hook_hits+20))

  netstat -an 2>/dev/null | grep -E "27042|27043" >/dev/null && hook_hits=$((hook_hits+15))
}

check_maps() {
  maps=$(cat /proc/self/maps 2>/dev/null)

  echo "$maps" | grep -Ei "frida|gum-js|inject" >/dev/null && hook_hits=$((hook_hits+30))
}

check_tracer() {
  tracer=$(awk '/TracerPid/ {print $2}' /proc/self/status 2>/dev/null)
  [ "$tracer" != "0" ] && hook_hits=$((hook_hits+20))
}

check_apps() {
  pm list packages 2>/dev/null | grep -Ei "hack|cheat|mod|lucky" >/dev/null && app_hits=$((app_hits+20))
}

check_emulator() {
  getprop ro.product.model | grep -qi "sdk\|emulator" && env_hits=$((env_hits+15))
}

# =========================
# EXEC
# =========================
run_checks() {
  check_su
  check_mounts
  check_props
  check_magisk
  check_frida
  check_maps
  check_tracer
  check_apps
  check_emulator
}

# =========================
# IP
# =========================
scan_ip() {
  loading "IP"
  ip=$(curl -s --max-time 2 ifconfig.me)
}

# =========================
# RESULTADO
# =========================
final_result() {

  risk_score=$((root_hits + bypass_hits + hook_hits + system_hits + app_hits + env_hits))

  runtime=$(( $(date +%s) - start_time ))

  if [ "$root_hits" -ge 30 ]; then
    status="ROOT CONFIRMADO"
    color=$RED
  elif [ "$risk_score" -ge 70 ]; then
    status="CRÍTICO"
    color=$RED
  elif [ "$risk_score" -ge 40 ]; then
    status="ALTO RISCO"
    color=$YELLOW
  elif [ "$risk_score" -ge 20 ]; then
    status="SUSPEITO"
    color=$YELLOW
  else
    status="LIMPO"
    color=$GREEN
  fi

  log_file="logs/scan_$(date +%H%M%S).json"

  echo ""
  echo -e "${WHITE}════════ RESULTADO ════════${NC}"
  echo ""

  echo -e "${color}STATUS: $status${NC}"
  line "Score" "$risk_score"
  line "Tempo" "${runtime}s"
  line "DeviceID" "$device_hash"
  line "IP" "$ip"

  echo ""
  line "Root" "$root_hits"
  line "Bypass" "$bypass_hits"
  line "Hook" "$hook_hits"
  line "Sistema" "$system_hits"
  line "Apps" "$app_hits"
  line "Ambiente" "$env_hits"

  echo ""

  cat <<EOF > "$log_file"
{
  "status": "$status",
  "score": $risk_score,
  "runtime": "$runtime",
  "device": "$device_hash",
  "ip": "$ip",
  "root": $root_hits,
  "bypass": $bypass_hits,
  "hook": $hook_hits,
  "system": $system_hits,
  "apps": $app_hits,
  "env": $env_hits
}
EOF

  echo -e "${CYAN}Log JSON salvo em: $log_file${NC}"
}

# =========================
# MENU
# =========================
menu() {
  banner
  echo "[1] Scan completo"
  echo "[2] Ver logs"
  echo "[3] Sair"
  echo ""

  read -p ">> " opt

  case $opt in
    1)
      run_checks
      scan_ip
      final_result
      ;;
    2)
      ls logs
      ;;
    3)
      exit
      ;;
    *)
      menu
      ;;
  esac
}

menu