# SecurityVibe-Skill

Auditoría y endurecimiento de aplicaciones web creadas con **vibecoding** (Lovable, Bolt, Cursor, v0, Replit) o con generación de código asistida por IA.

Basado en pentests reales a aplicaciones en producción (WordPress, Supabase/Lovable, HubSpot CMS): convierte el patrón de vulnerabilidades más común en un checklist accionable.

## El problema que resuelve

Las apps vibecodeadas comparten el mismo patrón de riesgo: **seguridad post-hoc**. La aplicación funciona, nadie endureció la configuración por defecto, y todo lo que el framework no protege queda abierto. Los hallazgos más repetidos en auditorías reales:

- Autenticación sin límite de intentos (fuerza bruta viable) y tokens que no se validan
- Control de acceso roto: registros auto-confirmados, claims de JWT en los que no se puede confiar, datos visibles entre usuarios
- Configuración por defecto: CORS abierto, cabeceras de seguridad ausentes, backups en el webroot, servidor original accesible detrás del CDN
- Formularios sin CAPTCHA ni límites (email flooding)

## Qué contiene

| Archivo | Descripción |
|---|---|
| `vibecode-web-hardening/SKILL.md` | Metodología completa: 12 checks de auditoría rápida con comandos reales, hardening por stack (Supabase, WordPress, Next.js/Vercel), disciplina de severidad calibrada, entrega con formato de reporte profesional + retest |
| `vibecode-web-hardening/templates/checklist-cliente.md` | Checklist de seguridad en lenguaje simple, exportable y entregable al cliente final |
| `vibecode-web-hardening/scripts/quick-scan.sh` | Escáner de 1 minuto: cabeceras, CORS, enumeración de usuarios, rate limiting, archivos sensibles, backups, SPF/DMARC |

## Instalación (Hermes Agent)

La skill se instala copiando la carpeta a la ruta de skills de Hermes:

```bash
cp -r vibecode-web-hardening ~/.hermes/skills/security/
```

El agente la detecta automáticamente. Luego se activa con frases como "protegé mi web" o "auditá esta app".

## Uso rápido

```bash
# Escaneo inicial (1 minuto, no destructivo):
bash vibecode-web-hardening/scripts/quick-scan.sh https://www.ejemplo.com

# Auditoría completa: seguir los 12 checks de SKILL.md
# Salida: resumen ejecutivo + hallazgos por severidad con evidencia reproducible
# + matriz de riesgo + plan de remediación priorizado + checklist de retest
```

## Los 12 checks (resumen)

1. Cabeceras de seguridad (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)
2. CORS: preflight con origen arbitrario en cada backend
3. Rate limiting: 10 peticiones rápidas a login/formularios/OTP
4. Enumeración de usuarios (REST API, ?author=, /auth/v1/settings)
5. Archivos sensibles y dotfiles (.env, .git, .htaccess, wp-config backups)
6. Backups accesibles (AI1WM .wpress, /backups, /db.sql)
7. Secretos en el bundle JS (claves de API, tokens)
8. Supabase: política de signup, RLS triage tabla por tabla, RPC
9. Formularios: nonces que se validan de verdad + protección anti-spam
10. DNS e infraestructura: origen expuesto (bypass de CDN), wildcard, SPF/DMARC
11. robots.txt / sitemap / security.txt
12. WordPress específico: xmlrpc, versiones expuestas, registro

## Principios de severidad

- Las claves públicas en el bundle (anon key de Supabase) son **información**, no vulnerabilidad: el hallazgo real es si las políticas de acceso permiten operaciones indebidas
- "No hay cabecera CORS en un GET" ≠ "no hay CORS": probar preflights OPTIONS con orígenes arbitrarios
- Sin SPF/DMARC = riesgo de suplantación de correo, no suplantación demostrada
- Límites de peticiones en pruebas: ≤30 por endpoint, datos sintéticos, nada destructivo

## Metodología de entrega

Cada auditoría entrega: resumen ejecutivo (1 página, no técnico) → hallazgos por severidad con evidencia reproducible (comando + salida) → cadenas de ataque → matriz de riesgo → plan de remediación priorizado (inmediato / corto / medio plazo) → lo que NO se pudo explotar → nota de limpieza → checklist de retest re-ejecutable.

## Cómo se construyó

Metodología derivada de pentests externos reales (black-box, sin credenciales) sobre aplicaciones en producción: una SPA React + Supabase (Lovable), un WordPress + Elementor detrás de CloudFront/EC2, y un ecosistema CMS (HubSpot) + AWS. El patrón común de los tres es la base del checklist.

## Licencia

**CC BY-NC 4.0** (Creative Commons Attribution-NonCommercial 4.0 International): puedes compartir, citar y usar este material internamente; **no está permitido el uso comercial** sin autorización por escrito del autor. Texto legal completo en `LICENSE`.

## Aviso

Esta guía cubre lo básico de aplicaciones web. Para aplicaciones con datos sensibles (datos personales, pagos, expedientes) se requiere además una auditoría completa y revisión de cumplimiento normativo según aplique (Ley 1581 / GDPR). Uso únicamente sobre sistemas con autorización.
