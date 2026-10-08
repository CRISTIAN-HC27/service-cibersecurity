# Política de seguridad del servicio de autenticación

Marco de referencia: **NIST CSF 2.0** (funciones GV, ID, PR, DE, RS, RO) y
NIST SP 800-63B (autenticación y gestión de contraseñas).

## 1. Autenticación (PR.AA)

- **Veredicto de identidad único**: el login devuelve un JWT de acceso
  (HS256, secreto ≥ 32 caracteres, `sub` = id de usuario) con vida corta
  (15 min por defecto) y un refresh token **opaco** en cookie `HttpOnly`.
- **MFA**: fuera del alcance actual; anotado como riesgo residual
  (`docs/risk-assessment.md`).
- **Sesiones**: el refresh token es de un solo uso (rotación en cada canje)
  y se agrupa en familias; la reutilización de un token ya canjeado revoca la
  familia completa y genera el evento `REUSE_DETECTED`.
- **Expiración**: access 15 min, refresh 7 días; logout revoca el token
  vigente.

## 2. Gestión de contraseñas (SP 800-63B / PR.AA-03)

| Regla | Implementación |
| --- | --- |
| Longitud mínima 12 caracteres | `IsStrongPassword` + `PasswordPolicyService` |
| Longitud máxima 128 | evita DoS por hashing de cadenas gigantes |
| Fuerte pero no impredecible | zxcvbn con score ≥ 3; el email entra como contexto |
| Almacenamiento | argon2id, m=64 MiB, t=3, p=4, sal aleatorio por usuario |
| Reutilización del email como contraseña | detectada por zxcvbn en contexto |
| Timing | hash argon2id simulado cuando el usuario no existe |

Las contraseñas nunca se registran en logs (pino redacta `authorization`,
`cookie` y `set-cookie`).

## 3. Control de acceso (PR.AA-01/02/05)

- `JwtAuthGuard` global con **denegación por defecto**; las rutas públicas
  se marcan `@Public()` de forma explícita y revisable.
- `@RateLimitKey('LOGIN' | 'REGISTER' | 'REFRESH')` acota cada ruta crítica.
- `OriginGuard` valida `Origin`/`Sec-Fetch-Site` en las rutas con cookie
  (CSRF).
- Recurso autenticado de ejemplo: `GET /users/me`.

## 4. Rate limiting y bloqueo (DE.CM / PR.AA-03)

| Capa | Umbral (defecto) | Clave |
| --- | --- | --- |
| nginx `limit_req` | 1 r/s (`auth`), 10 r/s (`api`) | IP |
| `ThrottlerGuard` | 100/60 s global | IP |
| `RateLimitGuard` login | 5 intentos / 900 s | IP **y** email |
| `RateLimitGuard` registro | 5 / 60 s | IP **y** email |
| `RateLimitGuard` refresh | 30 / 60 s | IP **y** cookie implícita |
| Bloqueo de cuenta | 5 fallos → 15 min | cuenta |

Respuesta `429` con `Retry-After` y cabeceras `RateLimit-*`.
Todo es configurable por entorno y validado con zod.

## 5. Protección en la superficie (PR.PS)

- **Cabeceras** (helmet): CSP `default-src 'self'`, `X-Content-Type-Options:
  nosniff`, `X-Frame-Options`, `Referrer-Policy: no-referrer`, HSTS
  (`max-age=63072000; includeSubDomains; preload`), `X-Powered-By` eliminado.
- **TLS** obligatorio en nginx (TLS 1.2/1.3, cipher suite AEAD, tickets
  desactivados) + redirect 80→443.
- **Cookies**: `HttpOnly`, `SameSite=Strict`, `Secure` (`COOKIE_SECURE`,
  obligatorio en producción), `Path=/auth/refresh` (el refresh solo viaja
  a su endpoint).
- **Body limit 10 kB**, `ValidationPipe` con `whitelist` y
  `forbidNonWhitelisted` (rechazo de campos desconocidos).
- **CORS**: whitelist explícita con `credentials: true`; `*` rechazado en la
  validación de entorno.
- **Errores**: `HttpExceptionFilter` responde mensajes genéricos; nunca
  expone stack traces, mensajes de Prisma ni detalles internos (los ≥500 se
  registran en el log).

## 6. Datos y registros (PR.DS / DE.CM)

- Tablas: `users`, `refresh_tokens` (solo hash SHA-256 del token),
  `auth_events` (índices por `type+createdAt` y `userId+createdAt`).
- Eventos auditados: `REGISTER_OK/FAIL`, `LOGIN_OK/FAIL/BLOCKED`,
  `TOKEN_REFRESH`, `REFRESH_INVALID`, `REUSE_DETECTED`, `LOGOUT`, con IP,
  user-agent y metadatos (`familyId`, motivos).
- Logs JSON con pino y redacción de credenciales.

## 7. Gestión de configuración y secretos (GV.PO / ID.RM)

- `.env` y `.env.*` (salvo `.env.example`) están en `.gitignore`;
  `.dockerignore` impide llevar secretos a la imagen.
- El arranque **falla temprano** si el entorno es inválido: secreto corto,
  `JWT_ACCESS_SECRET` de ejemplo, `CORS_ORIGINS: '*'`, `DATABASE_URL` que no
  sea PostgreSQL, `COOKIE_SECURE=false` en producción, `TRUST_PROXY=true`
  sin TLS.
- `npm audit --audit-level=high --omit=dev` en CI; *overrides* de
  `mysql2`/`deepmerge-ts` mantienen 0 vulnerabilidades.

## 8. Cadena de suministro (ID.IM / PR.IR)

- Bloqueo con `package-lock.json` + `npm ci` en CI.
- Dependencias de seguridad: helmet, zod, zxcvbn, argon2, throttler, pino.
- Build multi-stage en `Dockerfile`: la imagen final solo contiene `dist`,
  `node_modules` de producción y `prisma`; corre como usuario no root con
  migraciones aplicadas en `entrypoint.sh`.

## 9. Respuesta y recuperación (RS / RO)

Ver `docs/incident-response.md`. La política clave: ante sospecha de robo de
sesión, la **revocación de la familia de refresh tokens** es inmediata y
automática (`REUSE_DETECTED`), y los eventos en `auth_events` son la evidencia
auditable.
