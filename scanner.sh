#!/usr/bin/env bash

clear

# =========================
# CORES
# =========================
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
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

mkdir -p logs

# =========================
# DETECTAR ADB
# =========================
ADB_MODE=false

if command -v adb >/dev/null 2>&1; then
  if adb get-state 2>/dev/null | grep -q "device"; then
    ADB_MODE=true
  fi
fi

# =========================
# WRAPPER
# =========================
run_cmd() {
  if $ADB_MODE; then
    adb shell "$@" 2>/dev/null
  else
    "$@" 2>/dev/null
  fi
}

# =========================
# DEVICE ID
# =========================
device_hash=$(run_cmd getprop ro.serialno | md5sum | cut -c1-8)

# =========================
# UI
# =========================
banner() {
  clear
  echo -e "${WHITE}"
  echo "╔══════════════════════════════════════╗"
  echo "║           Scanner Randol             ║"
  echo "╚══════════════════════════════════════╝"
  echo -e "${NC}"

  if $ADB_MODE; then
    echo -e "${GREEN}ADB conectado${NC}"
  else
    echo -e "${YELLOW}Modo local (limitado)${NC}"
  fi
}

loading() {
  echo -ne "${WHITE}[$1] ${NC}"
  for i in {1..10}; do
    echo -ne "${GRAY}▓${NC}"
    sleep 0.01
  done
  echo -e " ${GREEN}OK${NC}"
}

line() {
  printf "${WHITE}➤ %-12s${NC}: %s\n" "$1" "$2"
}

# =========================
# CHECKS
# =========================

check_su() {
  for p in /system/bin/su /system/xbin/su /sbin/su; do
    run_cmd ls "$p" >/dev/null && root_hits=$((root_hits+5))
  done

  run_cmd which su >/dev/null && root_hits=$((root_hits+5))
  run_cmd su -c id >/dev/null && root_hits=$((root_hits+25))
}

check_mounts() {
  run_cmd mount | grep -E " /system | /vendor " | grep -q "rw," && root_hits=$((root_hits+15))
}

check_props() {
  run_cmd getprop ro.debuggable | grep -q "1" && system_hits=$((system_hits+10))
  run_cmd getprop ro.secure | grep -q "0" && system_hits=$((system_hits+10))
  run_cmd getprop ro.build.tags | grep -qi "test-keys" && system_hits=$((system_hits+10))
}

check_magisk() {
  run_cmd ls /sbin/.magisk >/dev/null && bypass_hits=$((bypass_hits+25))
  run_cmd ls /data/adb >/dev/null && bypass_hits=$((bypass_hits+15))
}

check_frida() {
  run_cmd ps -A | grep -qi frida && hook_hits=$((hook_hits+20))
  run_cmd netstat -an | grep -E "27042|27043" >/dev/null && hook_hits=$((hook_hits+15))
}

check_maps() {
  maps=$(run_cmd cat /proc/self/maps)
  echo "$maps" | grep -Ei "frida|gum-js|inject" >/dev/null && hook_hits=$((hook_hits+30))
}

check_tracer() {
  tracer=$(run_cmd cat /proc/self/status | grep TracerPid | awk '{print $2}')
  [ "$tracer" != "0" ] && hook_hits=$((hook_hits+20))
}

check_apps() {
  run_cmd pm list packages | grep -Ei "hack|cheat|mod|lucky" >/dev/null && app_hits=$((app_hits+20))
}

check_emulator() {
  run_cmd getprop ro.product.model | grep -qi "sdk\|emulator" && env_hits=$((env_hits+15))
}

# =========================
# EXEC
# =========================
run_checks() {
  loading "Checks"
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

  cat <<EOF > "$log_file"
{
  "status": "$status",
  "score": $risk_score,
  "runtime": "$runtime",
  "device": "$device_hash",
  "ip": "$ip"
}
EOF

  echo ""
  echo -e "${WHITE}Log salvo em: $log_file${NC}"
}

# =========================
# MENU
# =========================
menu() {
  banner
  echo "[1] Scan"
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