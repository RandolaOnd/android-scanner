#!/data/data/com.termux/files/usr/bin/bash

RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
CYAN="\e[36m"
RESET="\e[0m"

banner() {
  clear
  echo -e "${CYAN}╔════════════════════════════════════╗${RESET}"
  echo -e "${CYAN}║      SCANNER LOGCAT FORENSE        ║${RESET}"
  echo -e "${CYAN}║   ADB • USB • SHELL • FREE FIRE    ║${RESET}"
  echo -e "${CYAN}╚════════════════════════════════════╝${RESET}"
  echo
}

pause() {
  echo
  read -p "Pressione ENTER para voltar..."
}

critico_log_vazia() {
  banner
  echo -e "${RED}╔══════════════════════════════════════╗${RESET}"
  echo -e "${RED}║ [CRÍTICO] LOGCAT VAZIA / 0 MB        ║${RESET}"
  echo -e "${RED}╚══════════════════════════════════════╝${RESET}"
  echo
  echo -e "${RED}A logcat não foi gerada ou veio vazia.${RESET}"
  echo
  echo "Possíveis causas:"
  echo "- Termux sem permissão para ler logcat"
  echo "- logcat bloqueada pelo Android"
  echo "- pareamento/acesso elevado não ativo"
  echo "- arquivo informado está vazio"
  echo
  if [ -f /tmp/logcat_erro.txt ]; then
    echo -e "${YELLOW}Erro capturado:${RESET}"
    cat /tmp/logcat_erro.txt
  fi
  echo
  exit 1
}

gerar_logcat() {
  banner
  echo -e "${YELLOW}[+] Gerando logcat...${RESET}"
  echo

  OUT="/storage/emulated/0/Download/logcat_$(date +%Y%m%d_%H%M%S).txt"

  logcat -d > "$OUT" 2>/tmp/logcat_erro.txt &
  PID=$!

  SPIN='|/-\'
  i=0

  while kill -0 "$PID" 2>/dev/null; do
    i=$(( (i+1) %4 ))
    printf "\r${CYAN}Gerando logcat... ${SPIN:$i:1}${RESET}"
    sleep 0.2
  done

  wait "$PID"
  echo

  if [ ! -s "$OUT" ]; then
    LOG="$OUT"
    critico_log_vazia
  fi

  echo -e "${GREEN}[✓] Logcat gerada com sucesso!${RESET}"
  echo -e "${CYAN}Arquivo:${RESET} $OUT"
  sleep 2

  LOG="$OUT"
}

risco_linha() {
  CONTENT="$1"
  LOWER=$(echo "$CONTENT" | tr '[:upper:]' '[:lower:]')

  RISCO="INFO"
  COR="$CYAN"

  if echo "$LOWER" | grep -qE "adbd|wireless debugging|wirelessdebugging|pairing|pareamento|adb_keys|adbkey|uid 2000|uid=2000|com.android.shell|input keyevent|input swipe|input tap|scrcpy|minitouch|shizuku|rikka|tcpip|5555|shell@"; then
    RISCO="SUSPEITO"
    COR="$RED"
  elif echo "$LOWER" | grep -qE "input event injection|keycode 3|launch_home|go to home|floatingwindow|floatassistant|gamebooster|overlay|termux|brevent|piebridge|keystore|keymint|error::km"; then
    RISCO="ATENÇÃO"
    COR="$YELLOW"
  elif echo "$LOWER" | grep -qE "battery_changed|wallpaper|vibrator|smartpower"; then
    RISCO="NORMAL"
    COR="$GREEN"
  fi

  echo "$RISCO|$COR"
}

show_matches() {
  TITLE="$1"
  PATTERN="$2"
  FILE="$3"

  banner
  echo -e "${YELLOW}[$TITLE]${RESET}"
  echo

  if [ ! -s "$FILE" ]; then
    critico_log_vazia
  fi

  MATCHES=$(grep -iEn "$PATTERN" "$FILE")

  if [ -z "$MATCHES" ]; then
    echo -e "${GREEN}[✓] Nenhum rastro encontrado.${RESET}"
    pause
    return
  fi

  echo "$MATCHES" | while IFS=: read -r LINE CONTENT; do
    DATAHORA=$(echo "$CONTENT" | grep -oE '^[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}')
    [ -z "$DATAHORA" ] && DATAHORA=$(echo "$CONTENT" | awk '{print $1" "$2}')

    INFO=$(risco_linha "$CONTENT")
    RISCO=$(echo "$INFO" | cut -d'|' -f1)
    COR=$(echo "$INFO" | cut -d'|' -f2)

    echo -e "${COR}╔══════════════════════════════════════╗${RESET}"
    echo -e "${COR}║ [$RISCO] $DATAHORA${RESET}"
    echo -e "${COR}║ Linha: $LINE${RESET}"
    echo -e "${COR}╚══════════════════════════════════════╝${RESET}"
    echo "$CONTENT"
    echo "--------------------------------------------------"
  done

  echo
  echo -e "${CYAN}Total encontrado: $(echo "$MATCHES" | wc -l)${RESET}"
  pause
}

resumo() {
  banner
  echo -e "${YELLOW}[RESUMO GERAL]${RESET}"
  echo

  if [ ! -s "$SCANFILE" ]; then
    critico_log_vazia
  fi

  echo "Arquivo analisado: $LOG"
  echo

  echo -e "${CYAN}Primeira log analisada:${RESET}"
  grep -m1 -E '^[0-9]{2}-[0-9]{2} ' "$SCANFILE"

  echo
  echo -e "${CYAN}Última log analisada:${RESET}"
  grep -E '^[0-9]{2}-[0-9]{2} ' "$SCANFILE" | tail -n 1

  echo
  echo "ADB / adbd....................: $(grep -icE 'adb|adbd|adb_keys|adbkey|android debug' "$SCANFILE")"
  echo "Wireless Debugging............: $(grep -icE 'wireless debugging|wirelessdebugging|pairing|pareamento|tcpip|5555' "$SCANFILE")"
  echo "Shell / UID 2000..............: $(grep -icE 'uid 2000|uid=2000|com.android.shell|shell@|/system/bin/sh' "$SCANFILE")"
  echo "Portas TCP / localhost........: $(grep -icE 'localhost|127.0.0.1|tcp|socket|listen|port|5555' "$SCANFILE")"
  echo "Developer Settings............: $(grep -icE 'development_settings_enabled|adb_enabled|wireless_debugging_enabled|developer' "$SCANFILE")"
  echo "CMD / Input remoto............: $(grep -icE 'cmd activity|cmd package|settings put|settings get|input keyevent|input tap|input swipe' "$SCANFILE")"
  echo "Shizuku.......................: $(grep -icE 'shizuku|rikka|moe.shizuku|privileged.api' "$SCANFILE")"
  echo "USB / MTP / OTG...............: $(grep -icE 'usb|UsbManager|UsbDevice|mtp|ptp|otg|charging' "$SCANFILE")"
  echo "Input Injection / HOME........: $(grep -icE 'Input event injection|MiuiInput|KeyEventLog|keycode 3|launch_home|go to home' "$SCANFILE")"
  echo "Free Fire.....................: $(grep -icE 'freefire|com.dts.freefire|FFMainActivity' "$SCANFILE")"
  echo "Serviços iniciados............: $(grep -icE 'Starting service|startService|bindService|ServiceRecord|Foreground service' "$SCANFILE")"
  echo "System Server anormal.........: $(grep -icE 'system_server|Slow Binder|Watchdog|ANR|SecurityException|dead object' "$SCANFILE")"
  echo "Reboot / Boot.................: $(grep -icE 'BOOT_COMPLETED|boot completed|reboot|shutdown|sys.boot_completed|init:' "$SCANFILE")"
  echo "Log cortada / limpa...........: $(grep -icE 'beginning of|logd|clear|buffer|dropped|truncated|pruned' "$SCANFILE")"
  echo "Keystore / chaves.............: $(grep -icE 'keystore|keymint|IKeystore|SecurityLevel|Error::Km|invalidate key|key blob' "$SCANFILE")"

  pause
}

banner
echo "1) Gerar logcat automaticamente"
echo "2) Usar logcat já salva"
echo
read -p "Escolha: " MODO

if [ "$MODO" = "1" ]; then
  gerar_logcat
else
  read -p "Caminho da logcat: " LOG
fi

if [ ! -f "$LOG" ]; then
  echo -e "${RED}[CRÍTICO] Arquivo não encontrado.${RESET}"
  exit 1
fi

if [ ! -s "$LOG" ]; then
  critico_log_vazia
fi

SCANFILE="/tmp/logcat_scanner_filtrada.txt"

PRIMEIRA_LOG=$(grep -m1 -E '^[0-9]{2}-[0-9]{2} ' "$LOG")
PRIMEIRO_HORARIO=$(echo "$PRIMEIRA_LOG" | awk '{print $1" "$2}')

banner
echo -e "${CYAN}Logcat gerada a partir de:${RESET}"
echo -e "${YELLOW}$PRIMEIRO_HORARIO${RESET}"
echo
echo "1) Sim, analisar a partir de outro horário"
echo "2) Não, analisar desde o início da logcat"
echo
read -p "Escolha: " OP_HORA

if [ "$OP_HORA" = "1" ]; then
  echo
  read -p "Qual horário? Ex: 20:06 ou 20:06:30: " HINI

  if echo "$HINI" | grep -qE '^[0-9]{2}:[0-9]{2}$'; then
    HINI="${HINI}:00"
  fi

  awk -v ini="$HINI" '
  match($0, /^[0-9]{2}-[0-9]{2} ([0-9]{2}:[0-9]{2}:[0-9]{2})/, a) {
    if (a[1] >= ini) print
  }
  ' "$LOG" > "$SCANFILE"
else
  cp "$LOG" "$SCANFILE"
fi

if [ ! -s "$SCANFILE" ]; then
  critico_log_vazia
fi

while true; do
  banner
  echo "1) Resumo geral"
  echo "2) Horários do Free Fire"
  echo "3) ADB / adbd / depuração"
  echo "4) Wireless Debugging / pareamento"
  echo "5) Shell / UID 2000"
  echo "6) Portas TCP locais"
  echo "7) Developer Settings"
  echo "8) CMD / input remoto"
  echo "9) USB / MTP / OTG"
  echo "10) Shizuku"
  echo "11) Termux / Brevent / Scrcpy"
  echo "12) Input Injection / HOME"
  echo "13) Serviços iniciados"
  echo "14) System Server anormal"
  echo "15) Reboot / Boot"
  echo "16) Log cortada / limpa"
  echo "17) Keystore / chaves"
  echo "0) Sair"
  echo

  read -p "Escolha: " MENU

  case "$MENU" in
    1) resumo ;;
    2) show_matches "HORÁRIOS DO FREE FIRE" "freefire|com.dts.freefire|FFMainActivity|Garena" "$SCANFILE" ;;
    3) show_matches "ADB / adbd / depuração" "adb|adbd|adb_keys|adbkey|android debug|debugging" "$SCANFILE" ;;
    4) show_matches "Wireless Debugging / pareamento" "wireless debugging|wirelessdebugging|pairing|pareamento|tcpip|5555|rsa|fingerprint" "$SCANFILE" ;;
    5) show_matches "Shell / UID 2000" "uid 2000|uid=2000|com.android.shell|shell@|/system/bin/sh|toybox|toolbox|sh -c" "$SCANFILE" ;;
    6) show_matches "Portas TCP locais" "localhost|127.0.0.1|tcp|socket|listen|listening|port|5555|37099" "$SCANFILE" ;;
    7) show_matches "Developer Settings" "development_settings_enabled|adb_enabled|wireless_debugging_enabled|developer|DevelopmentSettings" "$SCANFILE" ;;
    8) show_matches "CMD / input remoto" "cmd activity|cmd package|cmd appops|settings put|settings get|am start|am force-stop|pm list|input keyevent|input tap|input swipe" "$SCANFILE" ;;
    9) show_matches "USB / MTP / OTG" "usb|UsbDevice|UsbHost|UsbManager|mtp|ptp|otg|accessory|charging|charger" "$SCANFILE" ;;
    10) show_matches "Shizuku" "shizuku|rikka|moe.shizuku|privileged.api" "$SCANFILE" ;;
    11) show_matches "Termux / Brevent / Scrcpy" "termux|brevent|piebridge|scrcpy|minitouch|uiautomator|tasker|macrodroid" "$SCANFILE" ;;
    12) show_matches "Input Injection / HOME" "Input event injection|MiuiInput|KeyEventLog|keycode 3|launch_home|go to home|ACTION_DOWN|ACTION_UP" "$SCANFILE" ;;
    13) show_matches "Serviços iniciados" "Starting service|startService|bindService|ServiceRecord|Foreground service|service started" "$SCANFILE" ;;
    14) show_matches "System Server anormal" "system_server|Slow Binder|Watchdog|ANR|SecurityException|dead object|PerfMonitor" "$SCANFILE" ;;
    15) show_matches "Reboot / Boot" "BOOT_COMPLETED|boot completed|reboot|shutdown|sys.boot_completed|init:" "$SCANFILE" ;;
    16) show_matches "Log cortada / limpa" "beginning of|logd|clear|buffer|dropped|truncated|pruned" "$SCANFILE" ;;
    17) show_matches "Keystore / chaves" "keystore|keymint|IKeystore|SecurityLevel|Error::Km|invalidate key|key blob" "$SCANFILE" ;;
    0) clear; exit ;;
    *) echo "Opção inválida"; sleep 1 ;;
  esac
done