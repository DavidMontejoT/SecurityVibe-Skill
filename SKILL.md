---
name: vibecode-web-hardening
description: Auditar y endurecer webs/apps creadas con vibecoding (Lovable, Bolt, Cursor, v0, Replit) y stacks modernos (Supabase, WordPress, Next.js/Vercel). Checklist de hardening por stack, auditoría rápida de 12 checks con comandos reales, disciplina de severidad calibrada y entrega con formato de reporte profesional (resumen ejecutivo + matriz + retest).
---

# Vibecode Web Hardening

Auditoría rápida + endurecimiento para aplicaciones web creadas con vibecoding (Lovable, Bolt, Cursor, v0, Replit) o con generación de código asistida por IA. Convierte el patrón de vulnerabilidades observado en pentests reales en un checklist accionable.

## Cuándo usar

- Antes de llevar a producción una web/app hecha con vibecoding
- Cuando un cliente o colega pregunta "qué tan segura está mi app"
- Como diagnóstico previo a un pentest completo (abre la venta del servicio)

## Contexto: el patrón observado en pentests reales (evidencia)

En 3 pentests reales (2026) el error común fue el mismo: **seguridad post-hoc** — la app funciona, nadie endureció defaults ni límites, y todo lo que el framework no protege por defecto quedó abierto:

| Caso (anonimizado) | Stack | Hallazgos representativos |
|---|---|---|
| App de IA (Lovable + Supabase) | SPA React/Vite + Supabase + Cloudflare | CRÍTICO: acceso B2B con email falso (mailer_autoconfirm + join por dominio); sin rate limit login/OTP; cambio de password sin verificación; submissions abiertos + stored XSS; sin CSP/XFO |
| Web corporativa (WordPress) | WP + Elementor Pro + CloudFront/EC2 | 982 intentos de login sin bloqueo; nonce de formulario NO validado (15 emails en 1.5s); CORS refleja cualquier origen con credentials; backups desprotegidos en nginx; .htaccess legible |
| Ecosistema legaltech (CMS) | HubSpot CMS + Cloudflare + AWS | Sin XFO/X-Content-Type-Options, CSP mínimo, Server header + Portal ID expuestos |

**Mensaje clave:** "el pentest puntual encuentra los síntomas; el problema es que no hay requisitos de ciberseguridad en el desarrollo". El servicio recurrente (matriz de autorización post-deploy) corrige la causa.

## Los 3 pilares del problema en vibecoding

1. **Control de acceso y autenticación** (categoría #1 OWASP): RLS no verificado, signup/auto-confirm abiertos, claims del JWT en los que no se puede confiar, cambio de password sin verificación, endpoints sin auth.
2. **Configuración por defecto**: CORS abierto, headers ausentes, backups en el webroot, directorios listables, DNS wildcard, origen expuesto detrás del CDN.
3. **Límites y validación**: sin rate limiting en login/formularios/OTP, nonces que no se validan, CAPTCHA ausente, uploads sin restricciones.

## Auditoría rápida (30-60 min) — 12 checks

Ejecutar TODOS en paralelo. Usar `curl` con `-s` y timeouts; para ráfagas usar Python requests con Session (10-50x más rápido que curl en bucle).

### 1. Cabeceras de seguridad
```bash
curl -sI https://<target>/ | grep -iE "strict-transport|content-security|x-frame|x-content-type|referrer-policy|permissions-policy"
# Esperado: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
# Ausencia de HSTS/CSP = hallazgo BAJO/MEDIO (3/3 de los pentests reales lo tenían)
```

### 2. CORS (NO asumir por ausencia de ACAO en GET)
```bash
curl -sI "https://<target>/wp-json/" -H "Origin: https://evil.example.com" | grep -i access-control
# y el preflight:
curl -s -X OPTIONS "https://<target>/api/" -H "Origin: https://evil.example.com" \
  -H "Access-Control-Request-Method: POST" -H "Access-Control-Request-Headers: authorization,content-type"
# ACAO reflejando el origen arbitrario + allow-credentials:true = severidad según el
# MECANISMO DE AUTH (ver "Disciplina de severidad"): cookie-auth sin nonce = ALTO;
# cookie-auth con nonce (WP REST) o Bearer (Supabase) = MEDIO/BAJO. Probar también Origin: null.
```

### 3. Rate limiting (10 peticiones rápidas)
```bash
for i in $(seq 1 10); do
  curl -s -o /dev/null -w "%{http_code} " -X POST "https://<target>/wp-login.php" \
    -d "log=vibecode-audit-nonexistent&pwd=test$i&wp-submit=Acceder&testcookie=1" -H "Cookie: wordpress_test_cookie=WP%20Cookie%20check"
done
# 10x200 sin 429 = sin rate limit (ALTO si hay user enum; MEDIO en formularios)
# Usar un USUARIO INEXISTENTE (nunca log=admin ni cuentas reales): evita lockouts/blacklist
# de la cuenta real (Wordfence/iThemes) y ruido en los logs del cliente. El limiter suele
# actuar antes de la verificación de usuario → mismo resultado medible.
# OJO: los límites están SPLIT — send-side (/recover, /otp) suele tener cooldown,
# verify/token NO. Probar cada uno por separado.
```

### 4. Enumeración de usuarios
```bash
# WordPress:
curl -s "https://<target>/wp-json/wp/v2/users" | python3 -c "import json,sys; print([(u['id'],u['slug']) for u in json.load(sys.stdin)])"
curl -s -o /dev/null -w "%{redirect_url}\n" "https://<target>/?author=2"
# Supabase: el endpoint /auth/v1/settings es público y revela política de signup
curl -s "https://<ref>.supabase.co/auth/v1/settings"
```

### 5. Archivos sensibles / dotfiles
```bash
for p in .git/HEAD .env .htaccess wp-config.php.bak wp-config.php~ debug.log; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://<target>/$p"); echo "$code $p"
done
# 200 en .htaccess = nginx sirviendo dotfiles (MEDIO, info disclosure)
# OJO: wp-config.php 200 con body vacío = PHP lo ejecutó, NO es fuga
# 404 vs 403: 404 = no existe, 403 = bloqueado (bien)
```

### 6. Backups
```bash
# AI1WM / WP:
curl -s "https://<target>/wp-content/ai1wm-backups/" && curl -s "https://<target>/wp-content/ai1wm-backups/.htaccess"
# .wpress en nginx = descargable aunque exista .htaccess (Apache-only). location ~* \.wpress$ { deny all; }
# Genérico: /backups, /backup.zip, /db.sql, /wp-content/uploads/backwpup-*, /wp-content/ai1wm-backups/
```

### 7. Secretos en el bundle JS (SPAs)
```bash
curl -s "https://<target>/" | grep -oE '/assets/index-[a-zA-Z0-9_-]+\.js' | sort -u | while read c; do
  curl -s "https://<target>$c" | grep -oE 'eyJ[A-Za-z0-9_-]{30,}|sk-[A-Za-z0-9]{20,}|NEXT_PUBLIC_[A-Z_]+|SUPABASE_[A-Z_]+|api[_-]?key["\x27:=][^,}]{5,}' | sort -u
done
# anon key de Supabase en bundle = INFO (pública por diseño); lo REAL es si las políticas RLS permiten algo indebido
# sk-* / secret / service_role = CRÍTICO
```

### 8. Supabase: settings + RLS triage (alta prioridad si hay Supabase)
```bash
# 8a. Política de auth pública:
curl -s "https://<ref>.supabase.co/auth/v1/settings"
# mailer_autoconfirm:true + RPC que confía en dominio/claims = broken access control (ALTO/CRÍTICO)

# 8b. RLS triage — GET de cada tabla con la anon key (OMITIR el header Authorization; nunca Bearer vacío = PGRST301):
curl -s "https://<ref>.supabase.co/rest/v1/<tabla>?select=*&limit=2" -H "apikey: <anon>"
# [] = tabla con RLS (fila filtrada) · filas = pública · 42501 = bloqueada · PGRST205 = tabla no existe (usar hint)
# POST/PATCH con Prefer: return=representation → 42501 "violates row-level security policy" = RLS bloquea (bien)

# 8c. RPC: PGRST202 = oráculo de firma ("Perhaps you meant claim_reward(_reward_id)") — reintentar con esos nombres
```

### 9. Formularios (nonce + spam)
```bash
# Probar el envío con un NONCE INVENTADO (0000000000):
curl -s -X POST "https://<target>/wp-admin/admin-ajax.php" -H "X-Requested-With: XMLHttpRequest" \
  --data-urlencode "action=elementor_pro_forms_send_form" --data-urlencode "nonce=0000000000" \
  --data-urlencode "post_id=52" --data-urlencode "form_id=88a178e" \
  --data-urlencode "form_fields[name]=Test" --data-urlencode "form_fields[email]=t@example.com"
# success:true con nonce inventado = nonce NO validado (ALTO: flooding automatizable sin visitar la página)
# Los errores de validación revelan el esquema de campos (info disclosure)
```

### 10. DNS / infraestructura
```bash
dig <dominio> A MX TXT NS +short
dig TXT _dmarc.<dominio> +short          # ausente o p=none = BAJO (spoofing)
for sub in www app api admin dev staging mail; do dig +short $sub.<dominio> CNAME; done
dig +short random123.<dominio> A         # wildcard = superficie ampliada (BAJO)
# Origen expuesto: si hay CDN, probar acceso directo a la IP con --resolve:
curl -sk --resolve www.<dominio>:443:<IP_ORIGEN> https://www.<dominio>/  # 200 = bypass de CDN (ALTO)
```

### 11. robots.txt / sitemap / security.txt
```bash
curl -s "https://<target>/robots.txt"; curl -s "https://<target>/wp-sitemap.xml"
curl -s -o /dev/null -w "%{http_code}\n" "https://<target>/.well-known/security.txt"   # 404 = recomendar publicarlo
# robots Disallow = mapa de rutas para el atacante (anotar, no alarmar)
```

### 12. WordPress específico (si aplica)
```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST "https://<target>/xmlrpc.php" -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
# 403 = bien (bloqueado). 200 = amplificación de brute force
curl -s "https://<target>/readme.html" -o /dev/null -w "%{http_code}\n"   # 200 = versión expuesta
for p in elementor elementor-pro elementskit-lite essential-addons-for-elementor-lite; do
  curl -s "https://<target>/wp-content/plugins/$p/readme.txt" | grep -iE "^stable tag" | head -1
done   # versiones exactas → correlación con CVEs (validar con WPScan)
curl -s -o /dev/null -w "%{http_code}\n" "https://<target>/wp-login.php?action=register"  # 302 registration=disabled = bien
```

## Disciplina de severidad (calibración)

- **anon key / claves públicas en SPA = INFO** (públicas por diseño). El hallazgo real es si RLS/RPC permiten operaciones indebidas.
- **Ausencia de ACAO en un GET ≠ "no hay CORS"** — probar OPTIONS preflight, orígenes arbitrarios y cada endpoint.
- **Ausencia de SPF/DMARC ≠ spoofing demostrado = BAJO** ("protección anti-spoofing ausente").
- **Formulario roto por RLS = disponibilidad/funcional, no vulnerabilidad de seguridad.**
- **CORS: la severidad depende del MECANISMO DE AUTH, no solo de las cabeceras:**
  - ACAO reflejado + credentials + API con **cookie-auth SIN nonce/CSRF** que devuelve datos sensibles → **ALTO** (exfiltración autenticada real: un sitio malicioso lee la API con las cookies de la víctima)
  - ACAO reflejado + credentials + cookie-auth CON nonce (WP REST exige X-WP-Nonce, inobtenible cross-origin) → **MEDIO** (no explotable directo; amplificador si se combina con otro fallo)
  - ACAO reflejado + credentials + auth por **Bearer token** (Supabase: el token vive en localStorage, no viaja cross-origin) → **MEDIO/BAJO**
  - ACAO reflejado sin credentials → **BAJO** (solo configuración)
  Documentar con precisión, no alarmismo: el "robo de sesión por CORS" requiere cookie-auth sin anti-CSRF, y ninguno de los stacks auditados (WP REST con nonce, Supabase con Bearer) lo permite.
- **Rate limit: probar cada endpoint por separado** (send vs verify) antes de afirmar ausencia.
- **No enviar `Authorization: Bearer ` vacío** en probes RLS: PGRST301 corrompe la clasificación. Omitir el header para probar como anon.
- **Límites de peticiones en pruebas:** ≤30 por endpoint, datos sintéticos, nada destructivo, emails solo a buzones controlados.

## Entrega (formato de reporte)

1. **Resumen ejecutivo** (1 página, no técnico)
2. **Hallazgos por severidad** con: CVSS-like, URL, descripción, impacto, evidencia reproducible (comando + salida), recomendación concreta
3. **Cadenas de ataque** (cómo se encadenan los hallazgos: enum → bypass CDN → brute force; nonce → flooding)
4. **Matriz de riesgo** (probabilidad × impacto)
5. **Plan de remediación priorizado** (Inmediato / Corto / Medio plazo) con comandos exactos (snippets nginx, security group, etc.)
6. **Lo que NO se pudo explotar** (muestra rigor)
7. **Nota de limpieza**: cuentas creadas, emails de prueba enviados, archivos generados
8. **Checklist de retest** — re-ejecutable fix por fix (el retest cierra el ciclo y es el argumento del servicio recurrente)

## Pitfalls aprendidos

- **Curl en bucle es LENTO** (TLS handshake por request): usar Python requests.Session + HTTPAdapter(pool) para ráfagas (25 hilos ≈ 7+ req/s a través de CDN).
- **macOS grep no tiene -P**: usar `grep -oE`.
- **PGRST202 = oráculo de esquema**: cada error revela la firma exacta de la RPC; reintentar con los nombres filtrados.
- **Lovable ofusca claves con "..." literales** — cosmético: el JWT completo (role=anon) existe intacto en el mismo bundle; regex de JWT de 3 partes y decodificar payload.
- **Nonces que no se validan**: probar siempre con nonce inventado antes de asumir que el token protege.
- **.htaccess no aplica en nginx**: una "protección" que funciona en Apache puede ser decorativa (AI1WM, Options -Indexes, AddType).
- **install.php "Ya está instalado"** = sin riesgo; **wp-config.php 200 body vacío** = PHP ejecutando, no fuga; **404 vs 403** distinguen "no existe" de "bloqueado".
- **xmlrpc 403 puede venir del origen o del CDN** — probar ambos (--resolve a la IP) para saber dónde está la protección real.
- **Documentar SIEMPRE las cuentas/emails de prueba** en la sección de limpieza del reporte.

## Archivos

- `templates/checklist-cliente.md` — checklist exportable en lenguaje simple para entregar al cliente
- `scripts/quick-scan.sh` — escáner de 1 minuto: headers + CORS + rate limit + enum + dotfiles + backups. Uso: `bash quick-scan.sh https://<target>`
