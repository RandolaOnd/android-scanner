#!/usr/bin/env bash

clear

# =========================
# SCANNER RANDOL
# =========================
RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
MAGENTA='\033[1;35m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
GRAY='\033[0;37m'
NC='\033[0m'

root_hits=0
bypass_hits=0
hook_hits=0
system_hits=0
app_hits=0
env_hits=0

TOTAL_STEPS=13
CURRENT_STEP=0

start_time=$(date +%s)
mkdir -p logs

ADB_MODE=false
if command -v adb >/dev/null 2>&1 && adb get-state 2>/dev/null | grep -q device; then
  ADB_MODE=true
fi

run_cmd() {
  if $ADB_MODE; then adb shell "$@" 2>/dev/null; else "$@" 2>/dev/null; fi
}

get_ps() { run_cmd ps -A 2>/dev/null || run_cmd ps 2>/dev/null; }
get_ports() { run_cmd ss -tuln 2>/dev/null || run_cmd netstat -tuln 2>/dev/null; }
get_logcat() { run_cmd logcat -d 2>/dev/null || echo ""; }

device_hash=$(run_cmd getprop ro.serialno | md5sum | cut -c1-8)
LOG_TXT="logs/scan_${device_hash}.txt"
LOG_JSON="logs/scan_${device_hash}.json"

exec > >(tee -a "$LOG_TXT") 2>&1

draw_bar() {
  percent=$((CURRENT_STEP * 100 / TOTAL_STEPS))
  filled=$((percent / 5))
  bar=$(printf "%${filled}s" | tr ' ' '█')
  printf "\r${CYAN}[%-20s]${NC} %3d%%" "$bar" "$percent"
}
spinner() {
  local pid=$!
  local spin='-\|/'
  while kill -0 $pid 2>/dev/null; do
    for i in {0..3}; do
      printf "\r${MAGENTA}[%c]${NC} Analisando..." "${spin:$i:1}"
      sleep 0.08
    done
  done
  printf "\r"
}
step() { CURRENT_STEP=$((CURRENT_STEP+1)); draw_bar; }
section() { echo -e "\n${GRAY}━━━━━━━━━━ $1 ━━━━━━━━━━${NC}"; }

# =========================
# CHECKS
# =========================
check_su() {
  for p in /system/bin/su /system/xbin/su /sbin/su; do run_cmd ls "$p" && root_hits=$((root_hits+15)); done
  run_cmd su -c id && root_hits=$((root_hits+30))
}
check_magisk() {
  run_cmd ls /sbin/.magisk && bypass_hits=$((bypass_hits+20))
  run_cmd ls /data/adb && bypass_hits=$((bypass_hits+15))
  get_ps | grep -Ei "magisk|zygisk" && bypass_hits=$((bypass_hits+20))
}
check_hooks() {
  get_ps | grep -i frida && hook_hits=$((hook_hits+25))
  get_ports | grep -E "27042|27043" && hook_hits=$((hook_hits+20))
}
check_injection() {
  for pid in $(get_ps | awk '{print $2}' | head -n 5); do
    run_cmd cat /proc/$pid/maps 2>/dev/null | grep -Ei "frida|inject" && hook_hits=$((hook_hits+10))
  done
}
check_binaries() { run_cmd find /data/local/tmp -type f 2>/dev/null | grep -Ei "frida" && bypass_hits=$((bypass_hits+10)); }
check_permissions() { run_cmd dumpsys package | grep -Ei "SYSTEM_ALERT_WINDOW" && app_hits=$((app_hits+5)); }
check_props() {
  run_cmd getprop ro.debuggable | grep -q 1 && system_hits=$((system_hits+10))
  run_cmd getprop ro.secure | grep -q 0 && system_hits=$((system_hits+10))
}
check_env() { get_ports | grep -E "5555" && env_hits=$((env_hits+5)); }
check_emulator() { run_cmd getprop ro.product.model | grep -qi emulator && env_hits=$((env_hits+10)); }
check_adb_root() { run_cmd getprop service.adb.root | grep -q 1 && root_hits=$((root_hits+30)); }

check_logs() {
  suspicious=0
  for buf in main system events radio; do
    logs=$(run_cmd logcat -b $buf -d 2>/dev/null | grep -Ei "magisk|frida|xposed|zygisk")
    [ -n "$logs" ] && echo -e "${RED}▸ Indicadores suspeitos no buffer $buf${NC}" && suspicious=1 && bypass_hits=$((bypass_hits+10))
  done
  count=$(get_logcat | wc -l)
  [ "$count" -lt 50 ] && echo -e "${YELLOW}⚠ Buffer de logs apagado${NC}" && env_hits=$((env_hits+10))
  lastlog_time=$(run_cmd logcat -d -v time | tail -n 1 | awk '{print $1}')
  [ -n "$lastlog_time" ] && echo "Último log registrado em: $lastlog_time"
  [ "$suspicious" -eq 0 ] && echo -e "${GREEN}✔ Nenhum indicador suspeito nos logs${NC}"
}
check_dev() { run_cmd settings get global adb_enabled | grep -q 1 && echo -e "${YELLOW}⚠ Depuração USB/Wi-Fi ATIVA${NC}"; }

# =========================
# EXECUÇÃO
# =========================
(
  check_su; step
  check_magisk; step
  check_hooks; step
  check_injection; step
  check_binaries; step
  check_permissions; step
  check_props; step
  check_env; step
  check_emulator; step
  check_adb_root; step
  check_logs; step
  check_dev; step
) & spinner

echo ""

# =========================
# RESULTADO
# =========================
score=$((root_hits + bypass_hits + hook_hits + system_hits + app_hits + env_hits))
runtime=$(( $(date +%s) - start_time ))

if [ "$root_hits" -ge 30 ]; then status="ROOT DETECTADO"; color=$RED
elif [ "$hook_hits" -ge 25 ]; then status="INSTRUMENTAÇÃO DETECTADA"; color=$RED
elif [ "$score" -ge 80 ]; then status="COMPROMETIDO"; color=$RED
elif [ "$score" -ge 40 ]; then status="SUSPEITO"; color=$YELLOW
else status="SEGURO"; color=$GREEN
fi

section "RESULTADO FINAL"
echo -e "Status   : ${color}$status${NC}"
echo "Score    : $score"
echo "Tempo    : ${runtime}s"

section "DETECÇÕES"
[ "$root_hits" -gt 0 ] && echo -e "${RED}▸ Root/BYPASS detectado${NC}"
[ "$bypass_hits" -gt 0 ] && echo -e "${RED}▸ Magisk/Zygisk detectado${NC}"
[ "$hook_hits" -gt 0 ] && echo -e "${MAGENTA}▸ Hooks/Frida detectados${NC}"
[ "$system_hits" -gt 0 ] && echo -e "${YELLOW}▸ Sistema em modo DEBUG/INSEGURO${NC}"
[ "$env_hits" -gt 0 ] && echo -e "${YELLOW}▸ Ambiente suspeito (emulador/ports/logs)${NC}"
[ "$app_hits" -gt 0 ] && echo -e "${YELLOW}▸ Permissões suspeitas detectadas${NC}"

# =========================
# EXPORTAÇÃO JSON + PUSH
# =========================
cat <<EOF > "$LOG_JSON"
{
  "status": "$status",
  "score": $score,
  "root_hits": $root_hits,
  "bypass_hits": $bypass_hits,
  "hook_hits": $hook_hits,
  "system_hits": $system_hits,
  "app_hits": $app_hits,
  "env_hits": $env_hits,
  "runtime": $runtime
}
EOF

echo -e "\n${CYAN}✔ Logs salvos:${NC}"
echo "$LOG_TXT"
echo "$LOG_JSON"

# Push automático para GitHub
git add "$LOG_TXT" "$LOG_JSON"
git commit -m "Scanner Randol: $status (score $score)"
git push origin main
