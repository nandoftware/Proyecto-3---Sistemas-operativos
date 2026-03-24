#!/bin/bash
#
# test_basic.sh
# CI3825 - Sistemas de Operacion I — Proyecto 3 SafeBox
# ARCHIVO PROVISTO POR EL PROFESOR - NO MODIFICAR

set -e

PASSWORD="sbx2026"
BOVEDA="./test_boveda_$$"
DAEMON="./safebox-daemon"
SHELL="./safebox-shell"
TEST_FILE="/tmp/safebox_test_$$.txt"
LOG="/tmp/safebox.log"
DAEMON_PID=""
PASS=0
FAIL=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

ok()   { echo -e "  ${GREEN}[OK]${NC}   $1"; PASS=$((PASS+1)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); }

# Ejecutar comandos en el cliente con el password preacordado
run_cli() { printf "%s\n%s\nexit\n" "$PASSWORD" "$1" | "$SHELL" 2>&1 || true; }

cleanup() {
    [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null && \
        kill -TERM "$DAEMON_PID" 2>/dev/null && sleep 0.4
    rm -f "$TEST_FILE" /tmp/safebox_test2_$$.txt
    rm -rf "$BOVEDA"
    rm -f /tmp/safebox.sock /tmp/safebox.pid
}
trap cleanup EXIT

echo ""; echo "=========================================="
echo " SafeBox — Test de Evaluacion Basica"
echo "=========================================="; echo ""

[ -x "$DAEMON" ] || { echo -e "${RED}ERROR: $DAEMON no encontrado. Ejecute make primero.${NC}"; exit 1; }
[ -x "$SHELL"    ] || { echo -e "${RED}ERROR: $SHELL no encontrado. Ejecute make primero.${NC}"; exit 1; }

# archivo de prueba
cat > "$TEST_FILE" << 'EOF'
Hola SafeBox! Este es el contenido de prueba.
Segunda linea del archivo.
CI3825 - Sistemas de Operacion I.
EOF

mkdir -p "$BOVEDA"

# ── Test 1: Arranque ──────────────────────────────
echo "--- Test 1: Arranque del daemon ---"
echo "$PASSWORD" | "$DAEMON" "$BOVEDA" 2>/dev/null
sleep 0.8

if [ -f /tmp/safebox.pid ]; then
    DAEMON_PID=$(cat /tmp/safebox.pid)
    kill -0 "$DAEMON_PID" 2>/dev/null && ok "daemon corriendo pid=$DAEMON_PID" \
        || { fail "daemon no esta corriendo"; exit 1; }
else
    fail "no se creo /tmp/safebox.pid"; exit 1
fi

[ -S /tmp/safebox.sock ] && ok "socket creado" || fail "socket no existe"
[ -f "$LOG" ] && ok "log creado" || fail "log no creado"

# ── Test 2: PUT ───────────────────────────────────
echo ""; echo "--- Test 2: PUT ---"
OUT=$(run_cli "put prueba.txt $TEST_FILE")
echo "$OUT" | grep -q "ok" && ok "PUT exitoso" || fail "PUT fallo"
[ -f "$BOVEDA/prueba.txt" ] && ok "archivo en disco" || fail "archivo no en disco"

# cifrado: texto plano NO visible
strings "$BOVEDA/prueba.txt" 2>/dev/null | grep -q "Hola SafeBox" \
    && fail "archivo en disco NO esta cifrado" \
    || ok "contenido cifrado en disco"

# header: version = 0x01
V=$(od -A n -t x1 -N 1 "$BOVEDA/prueba.txt" | tr -d ' \n')
[ "$V" = "01" ] && ok "version 0x01 en header" || fail "version incorrecta: 0x$V"

# ── Test 3: LIST ──────────────────────────────────
echo ""; echo "--- Test 3: LIST ---"
OUT=$(run_cli "list")
echo "$OUT" | grep -q "prueba.txt" && ok "LIST muestra prueba.txt" \
    || fail "LIST no muestra prueba.txt"

# ── Test 4: GET ───────────────────────────────────
echo ""; echo "--- Test 4: GET ---"
OUT=$(run_cli "get prueba.txt")
echo "$OUT" | grep -q "Hola SafeBox" && ok "GET retorna contenido correcto" \
    || fail "GET no retorna el contenido esperado"

# archivo en disco no debe cambiar tras GET
strings "$BOVEDA/prueba.txt" 2>/dev/null | grep -q "Hola SafeBox" \
    && fail "GET altero el archivo en disco" \
    || ok "archivo en disco intacto tras GET"

# ── Test 5: GET inexistente ───────────────────────
echo ""; echo "--- Test 5: GET archivo inexistente ---"
OUT=$(run_cli "get noexiste.txt")
echo "$OUT" | grep -qi "error\|no se pudo" && ok "GET inexistente retorna error" \
    || fail "GET inexistente no retorna error"

# ── Test 6: Password incorrecto ───────────────────
echo ""; echo "--- Test 6: Password incorrecto ---"
OUT=$(printf "clave_mala\nlist\nexit\n" | "$SHELL" 2>&1 || true)
echo "$OUT" | grep -qi "error\|no se pudo" && ok "password incorrecto rechazado" \
    || fail "password incorrecto NO rechazado"

# ── Test 7: Multiples archivos ────────────────────
echo ""; echo "--- Test 7: Multiples archivos en LIST ---"
echo "segundo archivo" > "/tmp/safebox_test2_$$.txt"
OUT=$(printf "%s\nput segundo.txt /tmp/safebox_test2_%s.txt\nlist\nexit\n" \
    "$PASSWORD" "$$" | "$SHELL" 2>&1)
echo "$OUT" | grep -q "prueba.txt" && echo "$OUT" | grep -q "segundo.txt" \
    && ok "LIST muestra ambos archivos" \
    || fail "LIST no muestra ambos archivos"

# ── Test 8: DEL ───────────────────────────────────
echo ""; echo "--- Test 8: DEL ---"
OUT=$(run_cli "del prueba.txt")
echo "$OUT" | grep -q "ok" && ok "DEL exitoso" || fail "DEL fallo"
[ ! -f "$BOVEDA/prueba.txt" ] && ok "archivo eliminado del disco" \
    || fail "archivo permanece en disco tras DEL"

OUT=$(run_cli "list")
echo "$OUT" | grep -q "prueba.txt" \
    && fail "prueba.txt todavia en LIST tras DEL" \
    || ok "prueba.txt no aparece en LIST tras DEL"

# ── Test 9: Log ───────────────────────────────────
echo ""; echo "--- Test 9: Log de operaciones ---"
if [ -f "$LOG" ]; then
    grep -q "autenticacion exitosa"    "$LOG" && ok "log: auth exitosa"    || fail "log: sin auth exitosa"
    grep -q "autenticacion fallida"    "$LOG" && ok "log: auth fallida"    || fail "log: sin auth fallida"
    grep -q "PUT.*cifrado y guardado"  "$LOG" && ok "log: PUT registrado"  || fail "log: sin PUT"
    grep -q "GET.*entregado"           "$LOG" && ok "log: GET registrado"  || fail "log: sin GET"
    grep -q "DEL.*eliminado"           "$LOG" && ok "log: DEL registrado"  || fail "log: sin DEL"
    # Formato: [YYYY-MM-DD HH:MM:SS] [NIVEL ]
    grep -qE '^\[20[0-9]{2}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\] \[(INFO |OK   |WARN |ERROR)\]' \
        "$LOG" && ok "formato de log correcto" || fail "formato de log incorrecto"
else
    fail "archivo de log no encontrado"
fi

# ── Test 10: SIGTERM ──────────────────────────────
echo ""; echo "--- Test 10: Terminacion con SIGTERM ---"
if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill -TERM "$DAEMON_PID"; sleep 0.8; DAEMON_PID=""

    kill -0 "$(cat /tmp/safebox.pid 2>/dev/null)" 2>/dev/null \
        && fail "daemon sigue corriendo tras SIGTERM" \
        || ok "daemon termino correctamente"

    [ ! -f /tmp/safebox.pid ] && ok "archivo .pid eliminado" || fail ".pid no eliminado"
    [ ! -S /tmp/safebox.sock ] && ok "socket eliminado" || fail "socket no eliminado"

    grep -q "terminado limpiamente\|cerrando daemon" "$LOG" 2>/dev/null \
        && ok "log registra cierre" || fail "log sin cierre"
fi

# ── Resumen ───────────────────────────────────────
echo ""; echo "=========================================="
TOTAL=$((PASS + FAIL))
echo " Resultado: $PASS/$TOTAL pruebas pasadas"
[ $FAIL -eq 0 ] \
    && echo -e " ${GREEN}TODOS LOS TESTS PASARON${NC}" \
    || echo -e " ${RED}$FAIL TESTS FALLARON${NC}"
echo "=========================================="; echo ""
exit $FAIL
