# Checklist de Seguridad para tu Web (guía práctica)

**Para quién:** equipos que crean webs y apps con generación de código por IA (Lovable, Bolt, Cursor, v0, Replit) o con WordPress/Supabase/Next.js.
**Cómo usar:** repasa cada punto. Si no sabes responder "¿cómo verifico?" o el check falla, ese es un punto a corregir antes de producción — o a pedir ayuda.

---

## 1. Acceso y cuentas (lo más importante)

- [ ] **El registro de usuarios está deshabilitado** si tu web no necesita cuentas públicas. (WP: `wp-login.php?action=register` debe redirigir a "registration disabled").
- [ ] **Los emails NO se auto-confirman.** Si usas Supabase: `mailer_autoconfirm` debe estar en **false**. Un usuario debe verificar su email antes de tener privilegios.
- [ ] **Cambiar contraseña exige la contraseña actual.** (Supabase: `secure_password_change` = true).
- [ ] **Doble factor (2FA) activado** para todos los que administran la web.
- [ ] **Límite de intentos de acceso**: tras 3-5 fallos, bloquear la IP al menos 20 minutos. Si no tienes esto, cualquiera puede probar millones de contraseñas.
- [ ] **Los usuarios no se pueden enumerar**: la API no debe listar usuarios ni sus nombres de usuario (en WordPress: `/wp-json/wp/v2/users` debe dar 401/403; `?author=2` no debe revelar el nombre).

## 2. Bases de datos y datos de clientes

- [ ] **Cada usuario solo ve SUS datos** (RLS en Supabase / permisos por fila). Prueba con 2 cuentas: la cuenta A no debe poder leer ni modificar datos de la B cambiando IDs en la URL.
- [ ] **Ningún endpoint acepta escribir datos sin autenticación** (prueba un POST sin sesión: debe fallar).
- [ ] **El "rol" o nivel de permisos no se puede cambiar desde el cliente** (no debe haber campos tipo `role`, `is_admin` en formularios o API pública).

## 3. Formularios y bots

- [ ] **Todos los formularios tienen CAPTCHA** (Cloudflare Turnstile o reCAPTCHA v3, invisibles para el usuario normal).
- [ ] **Los formularios tienen límite de envíos** (máx. ~5/minuto por IP). Sin esto, cualquiera puede inundar tu correo con miles de mensajes.
- [ ] **Los tokens de seguridad (nonces) se validan de verdad**: un formulario no debe aceptar un token inventado. Prueba cambiando el token por "0000000000" — si el envío se procesa, está mal.

## 4. Configuración del servidor

- [ ] **El servidor original NO es accesible directamente** (si usas Cloudflare/CloudFront, la IP real del servidor debe estar bloqueada para todo el mundo menos el CDN). Prueba: `curl https://TU-IP-REAL/` con el dominio en la cabecera — debe fallar, no mostrar tu web.
- [ ] **Los backups NO están en la carpeta pública de la web** (no en `wp-content/`, `/backups`, `/db.sql`...). Un backup accesible = toda tu web descargable, incluida la base de datos.
- [ ] **Archivos sensibles bloqueados**: `.env`, `.git`, `.htaccess`, `wp-config.php.bak` deben dar 403/404.
- [ ] **Cabeceras de seguridad presentes**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options. (Se revisan en una línea con tu navegador o con curl).

## 5. CORS y navegador

- [ ] **La API solo acepta peticiones desde TU dominio** (no debe responder "sí" a cualquier web). Si un sitio externo puede leer tu API con las cookies del usuario logueado, está mal configurado.

## 6. Correo y DNS

- [ ] **SPF, DKIM y DMARC configurados** (DMARC al menos en `p=quarantine`). Sin esto, cualquiera puede enviar correos "desde" tu dominio.
- [ ] **DNS limpio**: sin registros wildcard innecesarios, sin subdominios viejos apuntando a servidores que ya no usas.

## 7. Visibilidad

- [ ] **No se exponen versiones**: WordPress/plugins no deben anunciar su versión (ni en el código de la página ni en `readme.txt`). Las versiones exactas permiten buscar ataques conocidos.
- [ ] **`security.txt` publicado** (`https://tudominio/.well-known/security.txt`) con un contacto para reportar fallos.

---

## Si algo falla: prioridades

1. **Hoy mismo**: registro/auto-confirm cerrado, 2FA, límite de intentos, backups fuera del webroot, origen bloqueado, CAPTCHA en formularios.
2. **Esta semana**: CORS restringido, headers de seguridad, enumeración bloqueada, nonces validados.
3. **Este mes**: DMARC/SPF, limpiar versiones expuestas, security.txt, y una auditoría completa con retest después de cada cambio grande.

> Nota: esta guía cubre lo básico de aplicaciones web. Si manejas datos sensibles de clientes (datos personales, pagos, expedientes), necesitas además una auditoría completa y revisión de cumplimiento (Ley 1581/GDPR según aplique).
