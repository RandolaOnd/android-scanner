#!/usr/bin/env bash

# Scanner Randol - versão final completa

RED='\033[1;31m'; GREEN='\033[1;32m'; ORANGE='\033[1;33m'
MAGENTA='\033[1;35m'; CYAN='\033[1;36m'; GRAY='\033[0;37m'; NC='\033[0m'

root_hits=0; bypass_hits=0; hook_hits=0; system_hits=0; app_hits=0; env_hits=0; rom_hits=0

W_ROOT=30; W_BYPASS=20; W_HOOK=25; W_SYSTEM=15; W_APP=20; W_ENV=15; W_ROM=25

TOTAL_STEPS=25; CURRENT_STEP=0
start_time=$(date +%s)

ADB_MODE=false
if command -v adb >/dev/null 2>&1 && adb get-state 2>/dev/null | grep -q device; then ADB_MODE=true; fi

run_cmd() { if $ADB_MODE; then adb shell "$@" 2>/dev/null; else bash -c "$@" 2>/dev/null; fi; }
get_ps() { run_cmd "ps -A 2>/dev/null || ps 2>/dev/null"; }
get_ports() { run_cmd "ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null"; }
get_logcat() { run_cmd "logcat -d 2>/dev/null || true"; }

device_hash=$(run_cmd "getprop ro.boot.serialno || getprop ro.serialno || echo unknown" | tr -d '\r' | md5sum | cut -c1-8)

spinner() { local pid="$1"; local spin='-\|/'; while kill -0 "$pid" 2>/dev/null; do for i in 0 1 2 3; do printf "\r${MAGENTA}[%c]${NC} Analisando..." "${spin:$i:1}"; sleep 0.08; done; done; printf "\r"; }
draw_bar() { percent=$((CURRENT_STEP * 100 / TOTAL_STEPS)); filled=$((percent / 5)); bar=$(printf "%${filled}s" | tr ' ' '█'); printf "\r${CYAN}[%-20s]${NC} %3d%%" "$bar" "$percent"; }
step() { CURRENT_STEP=$((CURRENT_STEP+1)); draw_bar; }
section() { echo -e "\n${GRAY}━━━━━━━━━━ $1 ━━━━━━━━━━${NC}"; }

# ===== Checks principais =====
check_su() { run_cmd "su -c id" >/dev/null 2>&1 && root_hits=$((root_hits+W_ROOT)); }
check_magisk() { run_cmd "ls /sbin/.magisk" >/dev/null 2>&1 && bypass_hits=$((bypass_hits+W_BYPASS)); }
check_hooks() { get_ps | grep -i frida >/dev/null 2>&1 && hook_hits=$((hook_hits+W_HOOK)); }
check_injection() { for pid in $(get_ps | awk '{print $2}' | head -n 10); do run_cmd "cat /proc/$pid/maps 2>/dev/null | grep -i frida" && hook_hits=$((hook_hits+W_HOOK/2)); done; }
check_binaries() { run_cmd "ls /data/local/tmp" | grep -Ei "frida|xposed|magisk" && bypass_hits=$((bypass_hits+W_BYPASS)); }
check_permissions() { run_cmd "dumpsys package | grep SYSTEM_ALERT_WINDOW" && app_hits=$((app_hits+W_APP)); }
check_props() { run_cmd "getprop ro.build.tags | grep -qi test-keys" && system_hits=$((system_hits+W_SYSTEM)); }
check_env() { get_ports | grep 5555 && env_hits=$((env_hits+W_ENV)); }
check_emulator() { run_cmd "getprop ro.product.model | grep -qi emulator" && env_hits=$((env_hits+W_ENV)); }
check_dev() { run_cmd "settings get global adb_enabled | grep -q 1" && env_hits=$((env_hits+W_ENV/2)); }
check_busybox() { run_cmd "which busybox" && root_hits=$((root_hits+W_ROOT/3)); }
check_mounts() { run_cmd "mount | grep ' /system ' | grep rw" && root_hits=$((root_hits+W_ROOT)); }
check_packages() { run_cmd "pm list packages | grep -i magisk" && root_hits=$((root_hits+W_ROOT)); }
check_selinux() { run_cmd "getenforce | grep -qi permissive" && system_hits=$((system_hits+W_SYSTEM)); }
check_overlay() { run_cmd "dumpsys window windows | grep -i overlay" && app_hits=$((app_hits+W_APP/2)); }
check_partitions() { prod=$(run_cmd "getprop ro.product.name"); sysprod=$(run_cmd "getprop ro.system.product"); [ "$prod" != "$sysprod" ] && rom_hits=$((rom_hits+W_ROM)); }
check_rom_integrity() { build_fp=$(run_cmd "getprop ro.build.fingerprint"); sys_fp=$(run_cmd "getprop ro.system.build.fingerprint"); [ "$build_fp" != "$sys_fp" ] && rom_hits=$((rom_hits+W_ROM)); }

main_checks() {
  check_su; step
  check_magisk; step
  check_hooks; step
  check_injection; step
  check_binaries; step
  check_permissions; step
  check_props; step
  check_env; step
  check_emulator; step
  check_dev; step
  check_busybox; step
  check_mounts; step
  check_packages; step
  check_selinux; step
  check_overlay; step
  check_partitions; step
  check_rom_integrity; step
}

(main_checks) & pid=$!; spinner "$pid"; wait "$pid"

# ===== Resultado =====
score=$((root_hits + bypass_hits + hook_hits + system_hits + app_hits + env_hits + rom_hits))
runtime=$(( $(date +%s) - start_time ))

if [ "$root_hits" -ge $W_ROOT ] || [ "$hook_hits" -ge $W_HOOK ] || [ "$rom_hits" -ge $W_ROM ]; then
  status="CRÍTICO"; color=$RED
elif [ "$score" -gt 0 ]; then
  status="SUSPEITO"; color=$ORANGE
else
  status="SEGURO"; color=$GREEN
fi

echo -e "\n${MAGENTA}════════════════════════════════════════${NC}"
echo -e "              ${color}STATUS: $status${NC}"
echo -e "${MAGENTA}════════════════════════════════════════${NC}\n"

section "📋 INFORMAÇÕES"
printf "Android      : %s\n" "$(run_cmd "getprop ro.build.version.release")"
printf "Dispositivo  : %s\n" "$(run_cmd "getprop ro.product.model")"
printf "HWID         : %s\n" "$device_hash"
printf "Tempo        : %ss\n" "$runtime"

section "📊 SCORE"
printf "Root         : %d\n" "$root_hits"
printf "Bypass       : %d\n" "$bypass_hits"
printf "Hook         : %d\n" "$hook_hits"
printf "Sistema      : %d\n" "$system_hits"
printf "Apps         : %d\n" "$app_hits"
printf "Ambiente     : %d\n" "$env_hits"
printf "ROM          : %d\n" "$rom_hits"
printf "Total        : %d\n" "$score"

section "🔎 DETECÇÕES"
[ "$root_hits" -gt 0 ] && echo -e "${RED}▸ Root/BYPASS detectado${NC}"
[ "$hook_hits" -gt 0 ] && echo -e "${RED}▸ Hooks/Frida detectados${NC}"
[ "$rom_hits" -gt 0 ] && echo -e "${RED}▸ ROM adulterada ou divergente${NC}"
[ "$system_hits" -gt 0 ] && echo -e "${ORANGE}▸ Sistema inseguro/test-keys${NC}"
[ "$env_hits" -gt 0 ] && echo -e "${ORANGE}▸ Ambiente suspeito (emulador/ports/partições)${NC}"
[ "$app_hits" -gt 0 ] && echo -e "${ORANGE}▸ Apps com permissões críticas${NC}"

[ "$score" -eq 0 ] && echo -e "${GREEN}Nenhuma anomalia detectada.${NC}"
