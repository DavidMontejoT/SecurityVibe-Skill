#!/usr/bin/env bash
# quick-scan.sh — Auditoría rápida de seguridad para webs vibecodeadas (1 minuto).
# Uso: bash quick-scan.sh https://www.ejemplo.com
# No destructivo: máx. 10 peticiones por endpoint, solo lectura.
set -u
TARGET="${1:?Uso: bash quick-scan.sh https://<target>}"
PASS=0; WARN=0; FAIL=0
say()  { printf "%-6s %s\n" "$1" "$2"; }

echo "== quick-scan de $TARGET =="

# 1. Cabeceras de seguridad
H=$(curl -sI --max-time 15 "$TARGET/" 2>/dev/null)
for hdr in "strict-transport-security" "content-security-policy" "x-frame-options" "x-content-type-options"; do
  if echo "$H" | grep -qi "$hdr"; then say PASS "header $hdr"; PASS=$((PASS+1));
  else say WARN "FALTA header $hdr"; WARN=$((WARN+1)); fi
done

# 2. CORS (preflight con origen arbitrario sobre rutas API comunes)
for p in /wp-json/ /api/ /api/v1/ /rest/v1/; do
  C=$(curl -sI --max-time 12 "${TARGET}${p}" -H "Origin: https://evil.example.com" 2>/dev/null | grep -i "access-control-allow-origin" | head -1)
  if echo "$C" | grep -qi "evil.example.com"; then
    say FAIL "CORS refleja origen arbitrario en $p → $C"; FAIL=$((FAIL+1))
  fi
done
[ "$(echo "$C" | wc -c)" -le 1 ] && { say PASS "CORS sin reflejo de origen arbitrario"; PASS=$((PASS+1)); }

# 3. Enumeración de usuarios (WordPress REST)
U=$(curl -s --max-time 12 "${TARGET}/wp-json/wp/v2/users" 2>/dev/null | head -c 200)
if echo "$U" | grep -q '"slug"'; then say FAIL "user enum: /wp-json/wp/v2/users lista usuarios"; FAIL=$((FAIL+1));
else say PASS "sin user enum vía REST"; PASS=$((PASS+1)); fi

# 4. Dotfiles y backups
for p in .git/HEAD .env .htaccess wp-config.php.bak readme.html license.txt; do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${TARGET}/$p" 2>/dev/null)
  if [ "$code" = "200" ]; then say FAIL "$p responde 200 (fuga posible)"; FAIL=$((FAIL+1));
  elif [ "$code" = "403" ]; then say PASS "$p bloqueado (403)"; PASS=$((PASS+1));
  else say PASS "$p no expuesto ($code)"; PASS=$((PASS+1)); fi
done
for p in wp-content/ai1wm-backups/ wp-content/uploads/backups/ backup.zip db.sql; do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${TARGET}/$p" 2>/dev/null)
  if [ "$code" = "200" ]; then say FAIL "backup/ruta sensible responde 200: /$p"; FAIL=$((FAIL+1));
  else say PASS "/$p no expuesto ($code)"; PASS=$((PASS+1)); fi
done

# 5. Rate limit en login (10 peticiones — solo si existe wp-login)
code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${TARGET}/wp-login.php" 2>/dev/null)
if [ "$code" = "200" ]; then
  RL=$(for i in $(seq 1 10); do curl -s -o /dev/null -w "%{http_code}" --max-time 8 -X POST \
    "${TARGET}/wp-login.php" -d "log=vibecode-audit-nonexistent&pwd=test$i&wp-submit=Acceder&testcookie=1" \
    -H "Cookie: wordpress_test_cookie=WP%20Cookie%20check" 2>/dev/null; done | tr -d ' ' | grep -c 429)
  if [ "$RL" -ge 1 ]; then say PASS "login con rate limit (429 detectado)"; PASS=$((PASS+1));
  else say FAIL "login SIN rate limit (10 intentos sin 429)"; FAIL=$((FAIL+1)); fi
else say PASS "sin wp-login expuesto"; PASS=$((PASS+1)); fi

# 6. DNS/seguridad de correo
SPF=$(dig TXT "$(echo "$TARGET" | sed -E 's|https?://||;s|/.*||')" +short 2>/dev/null | grep -i "v=spf1")
DMARC=$(dig TXT "_dmarc.$(echo "$TARGET" | sed -E 's|https?://||;s|/.*||')" +short 2>/dev/null | grep -i "v=DMARC1")
[ -n "$SPF" ] && { say PASS "SPF presente"; PASS=$((PASS+1)); } || { say WARN "sin SPF"; WARN=$((WARN+1)); }
[ -n "$DMARC" ] && { say PASS "DMARC presente ($DMARC)"; PASS=$((PASS+1)); } || { say WARN "sin DMARC"; WARN=$((WARN+1)); }

# 7. security.txt
SEC=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${TARGET}/.well-known/security.txt" 2>/dev/null)
[ "$SEC" = "200" ] && { say PASS "security.txt publicado"; PASS=$((PASS+1)); } || { say WARN "sin security.txt ($SEC)"; WARN=$((WARN+1)); }

echo ""
echo "== RESUMEN: $PASS PASS · $WARN WARN · $FAIL FAIL =="
[ "$FAIL" -gt 0 ] && echo "Hay hallazgos que corregir. Detalle y remediación: skill vibecode-web-hardening."
exit 0
