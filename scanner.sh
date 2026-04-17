#!/usr/bin/env bash

# Scanner Randol - Versão aprimorada
# - Spinner seguro (PID explícito)
# - Evita comandos pesados
# - Logcat tratado com limiar (>100 linhas)
# - Checks: su, magisk, frida, busybox, mounts, build tags, selinux, overlay
# - Novos checks: partitions, tmpfiles, hidden apps, rom integrity, bugreport
# - Score balanceado por categoria

set -o pipefail

clear

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
MAGENTA='\033[1;35m'
CYAN='\033[1;36m'
GRAY='\033[0;37m'
NC='\033[0m'

# ===== Contadores e pesos =====
root_hits=0
bypass_hits=0
hook_hits=0
system_hits=0
app_hits=0
env_hits=0

# Pesos (ajustáveis)
W_ROOT=30
W_BYPASS=20
W_HOOK=25
W_SYSTEM=15
W_APP=20
W_ENV=10

TOTAL_STEPS=24
CURRENT_STEP=0
start_time=$(date +%s)

# Detecta se rodando via adb shell
ADB_MODE=false
if command -v adb >/dev/null 2>&1 && adb get-state 2>/dev/null | grep -q device; then
  ADB_MODE=true
fi

run_cmd() {
  if $ADB_MODE; then
    adb shell "$@" 2>/dev/null
  else
    bash -c "$@" 2>/dev/null
  fi
}

get_ps() { run_cmd "ps -A 2>/dev/null || ps 2>/dev/null"; }
get_ports() { run_cmd "ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null"; }
get_logcat() { run_cmd "logcat -d 2>/dev/null || true"; }

device_hash=$(run_cmd "getprop ro.boot.serialno || getprop ro.serialno || echo unknown" | tr -d '\r' | md5sum | cut -c1-8)

# ===== Spinner robusto =====
spinner() {
  local pid="$1"
  local spin='-\|/'
  while kill -0 "$pid" 2>/dev/null; do
    for i in 0 1 2 3; do
      printf "\r${MAGENTA}[%c]${NC} Analisando..." "${spin:$i:1}"
      sleep 0.08
    done
  done
  printf "\r"
}

draw_bar() {
  percent=$((CURRENT_STEP * 100 / TOTAL_STEPS))
  filled=$((percent / 5))
  bar=$(printf "%${filled}s" | tr ' ' '█')
  printf "\r${CYAN}[%-20s]${NC} %3d%%" "$bar" "$percent"
}
step() { CURRENT_STEP=$((CURRENT_STEP+1)); draw_bar; }

section() { echo -e "\n${GRAY}━━━━━━━━━━ $1 ━━━━━━━━━━${NC}"; }

# ===== Helpers =====
safe_grep() {
  # grep case-insensitive, return 0 if found
  echo "$2" | grep -Ei "$1" >/dev/null 2>&1
}

# ===== CHECKS =====
check_su() {
  for p in /system/bin/su /system/xbin/su /sbin/su /vendor/bin/su; do
    if run_cmd "ls $p" >/dev/null 2>&1; then
      root_hits=$((root_hits + W_ROOT/2))
      echo -e "${YELLOW}▸ Encontrado su em: $p${NC}"
    fi
  done
  if run_cmd "su -c id" >/dev/null 2>&1; then
    root_hits=$((root_hits + W_ROOT))
    echo -e "${RED}▸ Comando su executável (root disponível)${NC}"
  fi
}

check_magisk() {
  if run_cmd "ls /sbin/.magisk" >/dev/null 2>&1 || run_cmd "ls /data/adb" >/dev/null 2>&1; then
    bypass_hits=$((bypass_hits + W_BYPASS))
    echo -e "${RED}▸ Artefatos Magisk detectados${NC}"
  fi
  if run_cmd "getprop | grep -i magisk" >/dev/null 2>&1 || run_cmd "mount | grep -i magisk" >/dev/null 2>&1; then
    bypass_hits=$((bypass_hits + W_BYPASS/2))
    echo -e "${YELLOW}▸ Indícios de Magisk via getprop/mount${NC}"
  fi
}

check_hooks() {
  if get_ps | grep -i frida >/dev/null 2>&1; then
    hook_hits=$((hook_hits + W_HOOK))
    echo -e "${MAGENTA}▸ Processo Frida detectado${NC}"
  fi
  if get_ports | grep -E "27042|27043" >/dev/null 2>&1; then
    hook_hits=$((hook_hits + W_HOOK/2))
    echo -e "${MAGENTA}▸ Portas típicas de Frida abertas${NC}"
  fi
}

check_injection() {
  # Evitar strings /proc/*/maps em massa: primeiro filtrar PIDs suspeitos
  pids=$(get_ps | awk '{print $2,$NF}' | grep -Ei "frida|gdbserver|inject" | awk '{print $1}' | tr '\n' ' ')
  if [ -n "$pids" ]; then
    for pid in $pids; do
      if run_cmd "cat /proc/$pid/maps 2>/dev/null | grep -Ei 'frida|inject|gum' >/dev/null 2>&1"; then
        hook_hits=$((hook_hits + W_HOOK/2))
        echo -e "${MAGENTA}▸ Injeção detectada no PID $pid${NC}"
      fi
    done
  else
    # fallback leve: checar apenas alguns mapas (limitar)
    for pid in $(get_ps | awk '{print $2}' | head -n 10); do
      if run_cmd "cat /proc/$pid/maps 2>/dev/null | grep -Ei 'frida|inject|gum' >/dev/null 2>&1"; then
        hook_hits=$((hook_hits + W_HOOK/4))
        echo -e "${MAGENTA}▸ Possível injeção detectada (PID $pid)${NC}"
      fi
    done
  fi
}

check_binaries() {
  files=$(run_cmd "ls /data/local/tmp 2>/dev/null || true")
  if echo "$files" | grep -Ei "frida|xposed|magisk|supersu|\.so|\.sh" >/dev/null 2>&1; then
    bypass_hits=$((bypass_hits + W_BYPASS))
    echo -e "${RED}▸ Binários/suspeitos em /data/local/tmp${NC}"
  fi
}

check_permissions() {
  if run_cmd "dumpsys package | grep -Ei 'SYSTEM_ALERT_WINDOW|WRITE_SECURE_SETTINGS|READ_LOGS|BIND_ACCESSIBILITY_SERVICE|PACKAGE_USAGE_STATS' >/dev/null 2>&1"; then
    app_hits=$((app_hits + W_APP/2))
    echo -e "${YELLOW}▸ Permissões críticas encontradas em pacotes${NC}"
  fi
}

check_props() {
  if run_cmd "getprop ro.debuggable | grep -q 1" >/dev/null 2>&1; then
    system_hits=$((system_hits + W_SYSTEM))
    echo -e "${YELLOW}▸ Sistema em modo DEBUGGABLE${NC}"
  fi
  if run_cmd "getprop ro.secure | grep -q 0" >/dev/null 2>&1; then
    system_hits=$((system_hits + W_SYSTEM))
    echo -e "${YELLOW}▸ ro.secure=0 (inseguro)${NC}"
  fi
  if run_cmd "getprop ro.build.tags | grep -qi test-keys" >/dev/null 2>&1; then
    system_hits=$((system_hits + W_SYSTEM))
    echo -e "${YELLOW}▸ build tags = test-keys${NC}"
  fi
}

check_env() {
  if get_ports | grep -E "5555" >/dev/null 2>&1; then
    env_hits=$((env_hits + W_ENV))
    echo -e "${YELLOW}▸ ADB via rede detectado (porta 5555)${NC}"
  fi
  if run_cmd "getprop ro.product.model | grep -qi emulator" >/dev/null 2>&1; then
    env_hits=$((env_hits + W_ENV))
    echo -e "${YELLOW}▸ Ambiente emulador detectado${NC}"
  fi
}

check_adb_root() {
  if run_cmd "getprop service.adb.root | grep -q 1" >/dev/null 2>&1; then
    root_hits=$((root_hits + W_ROOT))
    echo -e "${RED}▸ ADB com root habilitado${NC}"
  fi
}

check_logs() {
  logs=$(get_logcat)
  if [ -z "$logs" ]; then
    echo -e "${YELLOW}⚠ Sem acesso completo ao logcat (permissão)${NC}"
    env_hits=$((env_hits + W_ENV/2))
    return
  fi

  # Só considerar "buffer apagado" se tivermos acesso real e poucas linhas
  count=$(echo "$logs" | wc -l)
  if [ "$count" -lt 100 ]; then
    echo -e "${YELLOW}⚠ Logcat curto (${count} linhas) — cuidado ao interpretar${NC}"
    env_hits=$((env_hits + W_ENV/2))
  fi

  if echo "$logs" | grep -Ei "magisk|frida|xposed|zygisk" >/dev/null 2>&1; then
    bypass_hits=$((bypass_hits + W_BYPASS))
    echo -e "${RED}▸ Indicadores suspeitos nos logs${NC}"
  fi
}

check_busybox() {
  if run_cmd "which busybox >/dev/null 2>&1 || which toybox >/dev/null 2>&1"; then
    root_hits=$((root_hits + W_ROOT/3))
    echo -e "${YELLOW}▸ Busybox/toybox detectado${NC}"
  fi
}

check_build_tags() {
  if run_cmd "getprop ro.build.tags | grep -qi test-keys" >/dev/null 2>&1; then
    system_hits=$((system_hits + W_SYSTEM))
    echo -e "${YELLOW}▸ ro.build.tags = test-keys${NC}"
  fi
}

check_mounts() {
  if run_cmd "mount | grep ' /system ' | grep -q rw" >/dev/null 2>&1; then
    root_hits=$((root_hits + W_ROOT))
    echo -e "${RED}▸ /system montado como RW${NC}"
  fi
  if run_cmd "mount | grep ' /vendor ' | grep -q rw" >/dev/null 2>&1; then
    root_hits=$((root_hits + W_ROOT/2))
    echo -e "${YELLOW}▸ /vendor montado como RW${NC}"
  fi
}

check_packages() {
  if run_cmd "pm list packages | grep -Ei 'supersu|magisk|chainfire' >/dev/null 2>&1"; then
    root_hits=$((root_hits + W_ROOT))
    echo -e "${RED}▸ Pacotes de root conhecidos instalados${NC}"
  fi
}

check_selinux() {
  if run_cmd "getenforce | grep -qi permissive" >/dev/null 2>&1; then
    system_hits=$((system_hits + W_SYSTEM))
    echo -e "${YELLOW}▸ SELinux permissivo${NC}"
  fi
}

check_overlay() {
  if run_cmd "dumpsys window windows | grep -i overlay >/dev/null 2>&1"; then
    app_hits=$((app_hits + W_APP/2))
    echo -e "${YELLOW}▸ Overlay suspeito detectado${NC}"
  fi
}

# ===== Novos checks solicitados =====
check_partitions() {
  prod=$(run_cmd "getprop ro.product.name || true" | tr -d '\r')
  sysprod=$(run_cmd "getprop ro.system.product || true" | tr -d '\r')
  buildprod=$(run_cmd "getprop ro.build.product || true" | tr -d '\r')
  if [ -n "$prod" ] && [ -n "$sysprod" ] && [ "$prod" != "$sysprod" ]; then
    env_hits=$((env_hits + W_ENV))
    echo -e "${YELLOW}⚠ Product name difere entre partições: $prod vs $sysprod${NC}"
  fi
  if [ -n "$buildprod" ] && [ "$buildprod" != "$prod" ] && [ -n "$prod" ]; then
    env_hits=$((env_hits + W_ENV/2))
    echo -e "${YELLOW}⚠ build.product difere: $buildprod vs $prod${NC}"
  fi
}

check_tmpfiles() {
  files=$(run_cmd "ls -A /data/local/tmp 2>/dev/null || true")
  if [ -n "$files" ]; then
    echo -e "${YELLOW}⚠ Arquivos em /data/local/tmp:${NC}"
    echo "$files"
    if echo "$files" | grep -Ei "frida|xposed|magisk|supersu|\.so|\.sh" >/dev/null 2>&1; then
      bypass_hits=$((bypass_hits + W_BYPASS))
      echo -e "${RED}▸ Arquivos suspeitos em /data/local/tmp${NC}"
    fi
  fi
}

check_hidden_apps() {
  echo -e "${CYAN}✔ Verificando apps com permissões críticas${NC}"
  # Procura por pacotes que declaram permissões perigosas
  if run_cmd "dumpsys package | grep -Ei 'requested permissions|grantedPermissions' >/dev/null 2>&1"; then
    # Extrair linhas relevantes e avaliar
    if run_cmd "dumpsys package | grep -Ei 'SYSTEM_ALERT_WINDOW|WRITE_SECURE_SETTINGS|READ_LOGS|BIND_ACCESSIBILITY_SERVICE|PACKAGE_USAGE_STATS' >/dev/null 2>&1"; then
      app_hits=$((app_hits + W_APP))
      echo -e "${YELLOW}▸ Permissões críticas encontradas em pacotes${NC}"
    fi
  fi

  # Apps "hidden" (sem launcher) - listar pacotes e checar se têm activity MAIN enabled
  pkgs=$(run_cmd "pm list packages -3 -f 2>/dev/null || pm list packages -f 2>/dev/null")
  # procurar pacotes sem atividade launcher (heurística)
  while IFS= read -r line; do
    pkg=$(echo "$line" | sed -n 's/.*=//p')
    if [ -n "$pkg" ]; then
      has_launcher=$(run_cmd "cmd package resolve-activity --brief $pkg 2>/dev/null || true")
      if [ -z "$has_launcher" ]; then
        # pacote sem launcher visível
        # checar se tem permissões críticas
        if run_cmd "dumpsys package $pkg | grep -Ei 'SYSTEM_ALERT_WINDOW|WRITE_SECURE_SETTINGS|READ_LOGS|BIND_ACCESSIBILITY_SERVICE|PACKAGE_USAGE_STATS' >/dev/null 2>&1"; then
          echo -e "${RED}▸ App escondido com permissões críticas: $pkg${NC}"
          app_hits=$((app_hits + W_APP))
        fi
      fi
    fi
  done <<< "$pkgs"
}

check_bugreport() {
  file="$1"
  if [ -z "$file" ]; then
    return
  fi
  if [ ! -f "$file" ]; then
    echo -e "${YELLOW}⚠ Bugreport não encontrado: $file${NC}"
    return
  fi
  echo -e "${CYAN}✔ Analisando bugreport: $file${NC}"
  if grep -Ei "magisk|zygisk" "$file" >/dev/null 2>&1; then
    bypass_hits=$((bypass_hits + W_BYPASS))
    echo -e "${RED}▸ Magisk/zygisk no bugreport${NC}"
  fi
  if grep -Ei "frida|gadget|gum" "$file" >/dev/null 2>&1; then
    hook_hits=$((hook_hits + W_HOOK))
    echo -e "${MAGENTA}▸ Frida/instrumentação no bugreport${NC}"
  fi
  if grep -Ei "test-keys|ro.build.tags" "$file" >/dev/null 2>&1; then
    system_hits=$((system_hits + W_SYSTEM))
    echo -e "${YELLOW}▸ Indícios de build test-keys no bugreport${NC}"
  fi
  if grep -Ei "rw /system|/system .*rw" "$file" >/dev/null 2>&1; then
    root_hits=$((root_hits + W_ROOT))
    echo -e "${RED}▸ /system montado como RW no bugreport${NC}"
  fi
  if grep -Ei "getenforce: permissive|SELinux: Permissive" "$file" >/dev/null 2>&1; then
    system_hits=$((system_hits + W_SYSTEM))
    echo -e "${YELLOW}▸ SELinux permissivo no bugreport${NC}"
  fi
}

check_rom_integrity() {
  build_fp=$(run_cmd "getprop ro.build.fingerprint || true" | tr -d '\r')
  sys_fp=$(run_cmd "getprop ro.system.build.fingerprint || true" | tr -d '\r')
  if [ -n "$sys_fp" ] && [ "$build_fp" != "$sys_fp" ]; then
    env_hits=$((env_hits + W_ENV + W_SYSTEM/2))
    echo -e "${YELLOW}⚠ Fingerprint divergente entre build e system${NC}"
  fi

  rel=$(run_cmd "getprop ro.build.version.release || true" | tr -d '\r')
  sdk=$(run_cmd "getprop ro.build.version.sdk || true" | tr -d '\r')
  if [ -n "$rel" ] && [ -n "$sdk" ]; then
    # heurística simples: mapear versões conhecidas (ajuste conforme necessário)
    case "$rel" in
      14) expected_sdk=35;;
      13) expected_sdk=33;;
      12) expected_sdk=31;;
      11) expected_sdk=30;;
      *) expected_sdk=0;;
    esac
    if [ "$expected_sdk" -ne 0 ] && [ "$sdk" -ne "$expected_sdk" ]; then
      env_hits=$((env_hits + W_ENV + W_SYSTEM/2))
      echo -e "${YELLOW}⚠ Inconsistência versão/SDK: release=$rel sdk=$sdk (esperado $expected_sdk)${NC}"
    fi
  fi

  # checar pacotes OEM duplicados/estranhos
  if run_cmd "pm list packages | grep -Ei 'oem|vendor' >/dev/null 2>&1"; then
    env_hits=$((env_hits + W_ENV/2))
    echo -e "${YELLOW}▸ Pacotes OEM suspeitos detectados${NC}"
  fi
}

# ===== Execução principal (rodar em background e capturar PID) =====
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
  check_adb_root; step
  check_logs; step
  check_dev; step
  check_busybox; step
  check_build_tags; step
  check_mounts; step
  check_packages; step
  check_selinux; step
  check_overlay; step
  check_partitions; step
  check_tmpfiles; step
  check_hidden_apps; step
  check_rom_integrity; step
  # Se houver bugreport.txt no diretório atual, analisa
  check_bugreport "bugreport.txt"; step
}

# Inicia checks em background e spinner com PID explícito
(
  main_checks
) &
pid=$!
spinner "$pid"
wait "$pid" 2>/dev/null || true

echo ""

# ===== Resultado e scoring =====
score=$((root_hits + bypass_hits + hook_hits + system_hits + app_hits + env_hits))
runtime=$(( $(date +%s) - start_time ))

# Limites por categoria para evitar desbalanceamento
cat_status="OK"
if [ "$root_hits" -ge $W_ROOT ]; then
  cat_status="ROOT"
fi
if [ "$hook_hits" -ge $W_HOOK ]; then
  cat_status="HOOK"
fi

if [ "$root_hits" -ge $W_ROOT ]; then status="ROOT DETECTADO"; color=$RED
elif [ "$hook_hits" -ge $W_HOOK ]; then status="INSTRUMENTAÇÃO DETECTADA"; color=$RED
elif [ "$score" -ge 2*W_ROOT ]; then status="COMPROMETIDO"; color=$RED
elif [ "$score" -ge W_ROOT ]; then status="SUSPEITO"; color=$YELLOW
else status="SEGURO"; color=$GREEN
fi

echo -e "\n${MAGENTA}Scanner Randol - Resultado${NC}"

section "INFORMAÇÕES"
echo -e "Status      : ${color}$status${NC}"
echo -e "Android     : $(run_cmd "getprop ro.build.version.release || echo unknown" | tr -d '\r')"
echo -e "Dispositivo : $(run_cmd "getprop ro.product.model || echo unknown" | tr -d '\r')"
echo -e "HWID        : $device_hash"
echo -e "Tempo       : ${runtime}s"

section "SCORE"
echo -e "root_hits   : $root_hits"
echo -e "bypass_hits : $bypass_hits"
echo -e "hook_hits   : $hook_hits"
echo -e "system_hits : $system_hits"
echo -e "app_hits    : $app_hits"
echo -e "env_hits    : $env_hits"
echo -e "Total score : $score"

section "DETECÇÕES"
[ "$root_hits" -gt 0 ] && echo -e "${RED}▸ Root/BYPASS detectado${NC}"
[ "$bypass_hits" -gt 0 ] && echo -e "${RED}▸ Magisk/Zygisk detectado${NC}"
[ "$hook_hits" -gt 0 ] && echo -e "${MAGENTA}▸ Hooks/Frida detectados${NC}"
[ "$system_hits" -gt 0 ] && echo -e "${YELLOW}▸ Sistema em modo DEBUG/INSEGURO${NC}"
[ "$env_hits" -gt 0 ] && echo -e "${YELLOW}▸ Ambiente suspeito (emulador/ports/partições)${NC}"
[ "$app_hits" -gt 0 ] && echo -e "${YELLOW}▸ Permissões ou apps suspeitos detectados${NC}"

echo -e "\n${CYAN}Dica:${NC} Se quiser análise de um bugreport específico, coloque o arquivo 'bugreport.txt' no mesmo diretório e rode novamente."
