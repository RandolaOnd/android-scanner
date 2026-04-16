#!/usr/bin/env bash

clear

# =========================
# CORES
# =========================
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
MAGENTA='\033[1;35m'
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

TOTAL_STEPS=14
CURRENT_STEP=0

start_time=$(date +%s)
mkdir -p logs

# =========================
# ADB
# =========================
ADB_MODE=false
if command -v adb >/dev/null 2>&1 && adb get-state 2>/dev/null | grep -q device; then
  ADB_MODE=true
fi

run_cmd() {
  if $ADB_MODE; then adb shell "$@" 2>/dev/null; else "$@" 2>/dev/null; fi
}

device_hash=$(run_cmd getprop ro.serialno | md5sum | cut -c1-8)

# =========================
# UI
# =========================
banner() {
  clear
  echo -e "${CYAN}"
  echo "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓"
  echo "┃     ANDROID THREAT ANALYZER v3.0     ┃"
  echo "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛"
  echo -e "${NC}"

  $ADB_MODE && echo -e "${GREEN}✔ ADB ONLINE${NC}" || echo -e "${YELLOW}⚠ LOCAL MODE${NC}"
  echo ""
}

draw_bar() {
  percent=$((CURRENT_STEP * 100 / TOTAL_STEPS))
  filled=$((percent / 5))
  empty=$((20 - filled))
  bar=$(printf "%${filled}s" | tr ' ' '█')
  printf "\r${CYAN}[%-20s]${NC} %3d%%" "$bar" "$percent"
}

spinner() {
  local pid=$!
  local spin='-\|/'
  while kill -0 $pid 2>/dev/null; do
    for i in {0..3}; do
      printf "\r${MAGENTA}[%c]${NC} scanning..." "${spin:$i:1}"
      sleep 0.08
    done
  done
  printf "\r"
}

step() { CURRENT_STEP=$((CURRENT_STEP+1)); draw_bar; }

section() {
  echo ""
  echo -e "${GRAY}━━━━━━━━ $1 ━━━━━━━━${NC}"
}

# =========================
# CHECKS AVANÇADOS
# =========================

check_su() {
  for p in /system/bin/su /system/xbin/su /sbin/su /system_ext/bin/su; do
    run_cmd ls "$p" && root_hits=$((root_hits+5))
  done
  run_cmd su -c id && root_hits=$((root_hits+30))
}

check_magisk_hidden() {
  run_cmd ls /sbin/.magisk && bypass_hits=$((bypass_hits+25))
  run_cmd ls /data/adb && bypass_hits=$((bypass_hits+15))
  run_cmd ps -A | grep -Ei "zygisk|magisk" && bypass_hits=$((bypass_hits+20))
}

check_lsposed() {
  run_cmd pm list packages | grep -Ei "lsposed|xposed" && hook_hits=$((hook_hits+25))
}

check_frida_deep() {
  run_cmd ps -A | grep -i frida && hook_hits=$((hook_hits+25))
  run_cmd netstat -an | grep -E "27042|27043" && hook_hits=$((hook_hits+20))
}

check_ports() {
  ports=$(run_cmd netstat -tuln)
  echo "$ports" | grep -E "4444|5555|8080" && env_hits=$((env_hits+10))
}

check_proc_injection() {
  for pid in $(run_cmd ps -A | awk '{print $2}' | head -n 20); do
    run_cmd cat /proc/$pid/maps | grep -Ei "frida|inject|hook" && hook_hits=$((hook_hits+10))
  done
}

check_binaries() {
  run_cmd find /data/local/tmp -type f 2>/dev/null | grep -Ei "frida|inject" && bypass_hits=$((bypass_hits+20))
}

check_permissions() {
  run_cmd dumpsys package | grep -Ei "android.permission.SYSTEM_ALERT_WINDOW" && app_hits=$((app_hits+10))
}

check_props() {
  run_cmd getprop ro.debuggable | grep -q 1 && system_hits=$((system_hits+10))
  run_cmd getprop ro.secure | grep -q 0 && system_hits=$((system_hits+10))
}

check_logs() {
  logs=$(run_cmd logcat -d | tail -n 800)
  echo "$logs" | grep -Ei "magisk|zygisk|frida|xposed" && bypass_hits=$((bypass_hits+20))
}

check_emulator() {
  run_cmd getprop ro.product.model | grep -qi emulator && env_hits=$((env_hits+15))
}

# =========================
# EXECUÇÃO
# =========================
run_checks() {
  section "DEEP SCAN"

  (
    check_su; step
    check_magisk_hidden; step
    check_lsposed; step
    check_frida_deep; step
    check_ports; step
    check_proc_injection; step
    check_binaries; step
    check_permissions; step
    check_props; step
    check_logs; step
    check_emulator; step
  ) & spinner

  echo ""
}

# =========================
# RESULTADO
# =========================
final_result() {

  score=$((root_hits + bypass_hits + hook_hits + system_hits + app_hits + env_hits))
  runtime=$(( $(date +%s) - start_time ))

  if [ "$root_hits" -ge 30 ]; then
    status="ROOT DETECTADO"
    color=$RED
  elif [ "$score" -ge 80 ]; then
    status="COMPROMETIDO"
    color=$RED
  elif [ "$score" -ge 40 ]; then
    status="ALTO RISCO"
    color=$YELLOW
  elif [ "$score" -ge 20 ]; then
    status="SUSPEITO"
    color=$YELLOW
  else
    status="SEGURO"
    color=$GREEN
  fi

  section "RESULTADO FINAL"

  printf "${WHITE}┌───────────────┬───────────────┐\n"
  printf "│ Status        │ ${color}%-13s${WHITE} │\n" "$status"
  printf "│ Score         │ %-13s │\n" "$score"
  printf "│ Tempo         │ %-13ss│\n" "$runtime"
  printf "└───────────────┴───────────────┘${NC}\n"

  echo ""
  printf "${GRAY}Root:%s  Bypass:%s  Hook:%s  Sys:%s  Apps:%s  Env:%s${NC}\n" \
    "$root_hits" "$bypass_hits" "$hook_hits" "$system_hits" "$app_hits" "$env_hits"
}

# =========================
# MENU
# =========================
menu() {
  banner
  echo -e "${WHITE}[1] Scan Profundo${NC}"
  echo -e "${WHITE}[2] Logs${NC}"
  echo -e "${WHITE}[3] Sair${NC}"
  echo ""

  read -p "➤ " opt

  case $opt in
    1) run_checks; final_result ;;
    2) ls logs ;;
    3) exit ;;
    *) menu ;;
  esac
}

menu