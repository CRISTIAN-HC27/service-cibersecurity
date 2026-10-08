# Evaluación de riesgos (GV.RM)

Metodología: identificación de activos → amenazas → controles actuales →
riesgo residual, alineada con la categoría **GV.RM** (gestión de riesgos) y
**ID.RA** (evaluación de riesgos) de NIST CSF 2.0. Escala: impacto y
probabilidad en {Bajo, Medio, Alto}; riesgo = combinación de ambas.

## 1. Activos

| Activo | Importancia |
| --- | --- |
| Credenciales de usuario (contraseñas) | Alta: compromiso = acceso a todas las cuentas |
| Sesiones activas (refresh tokens) | Alta: equivalen a acceso persistente |
| `JWT_ACCESS_SECRET` | Crítica: permite firmar tokens de cualquier usuario |
| Base de datos (`users`, `refresh_tokens`, `auth_events`) | Alta |
| Disponibilidad del servicio de login | Media: bloquea el acceso de todos los usuarios |

## 2. Amenazas, controles y riesgo residual

| # | Amenaza (vector) | Impacto | Prob. | Control actual | Residual |
| --- | --- | --- | --- | --- | --- |
| 1 | Fuerza bruta de contraseñas (login) | Alto | Alto | Rate limit por IP **y** por email (5/900 s), bloqueo de cuenta 5 fallos/15 min, nginx 1 r/s, contraseñas ≥12 con zxcvbn | **Bajo-Medio** |
| 2 | Credential stuffing (pares válidos filtrados) | Alto | Medio | Rate limit por identificador, bloqueo de cuenta, argon2id resistente a GPU, mensaje genérico 401 | **Medio** (sin MFA) |
| 3 | Enumeración de usuarios | Medio | Medio | Timing uniforme (hash simulado), respuestas 401/409 genéricas | **Bajo-Medio** (409 de registro revela existencia, mitigado con mensaje genérico) |
| 4 | Robo de refresh token (XSS/robo de red) | Alto | Bajo | Cookie `HttpOnly` + `SameSite=Strict` + `Secure`, rotación de un solo uso, revocación de familia ante reutilización (`REUSE_DETECTED`), TLS obligatorio | **Bajo** |
| 5 | Replay de refresh token | Alto | Bajo | Reclamo CAS atómico + detección de reuso → revocación total de la familia | **Bajo** |
| 6 | CSRF (forzar login/logout/refresh desde otro origen) | Medio | Bajo | `SameSite=Strict`, `OriginGuard` con whitelist y `Sec-Fetch-Site`, CORS sin wildcard | **Bajo** |
| 7 | Inyección SQL (campos del login/registro) | Alto | Bajo | Prisma con *prepared statements*, DTOs con whitelist y validación de formato de email | **Bajo** |
| 8 | Payload gigante / DoS por parsing | Medio | Medio | Límite 10 kB (413), rate limiting en nginx y app, timeouts de pool | **Bajo** |
| 9 | Extracción de información interna en errores | Medio | Medio | `HttpExceptionFilter` con mensajes genéricos, sin stack traces, ≥500 solo en log | **Bajo** |
| 10 | Fuga de secretos al repositorio/imagen | Crítico | Bajo | `.gitignore`/`.dockerignore`, validación que rechaza el valor de ejemplo, secretos solo en entorno | **Bajo** |
| 11 | Arranque con configuración inválida (p. ej. sin TLS) | Alto | Bajo | Fallo temprano con zod: `COOKIE_SECURE` obligatorio en producción, `TRUST_PROXY` exige TLS, `CORS_ORIGINS` sin `*` | **Bajo** |
| 12 | Falsificación de IP para evadir rate limit | Medio | Bajo | `TRUST_PROXY=false` por defecto; `true` solo con `COOKIE_SECURE=true` (nginx sobrescribe XFF) | **Bajo** |
| 13 | Abuso de registro (creación masiva de cuentas) | Bajo | Medio | Rate limit registro 5/60 s por IP y email, nginx 1 r/s | **Bajo** |
| 14 | Compromiso de dependencias | Alto | Medio | `npm ci` + `npm audit` en CI, overrides con 0 vulnerabilidades, dependencias mínimas | **Bajo-Medio** |
| 15 | Indisponibilidad de la BD | Medio | Bajo | `pg_isready` en compose, `/health/ready`, reintentos del pool de Prisma | **Medio** |
| 16 | Ferralla de auditoría (negar un ataque) | Medio | Bajo | Eventos en tabla indexada con IP/UA/metadatos, logs JSON en stdout | **Bajo** |

## 3. Riesgos residuales asumidos (y plan)

1. **Sin MFA / verificación de email** (amenaza 2): recomendación de fase
   futura: TOTP o passkeys + flujo de verificación por email.
2. **Rate limit en memoria por instancia** (amenaza 1): al escalar a varias
   réplicas migrar `RateLimitStore` a Redis con ventana deslizante compartida.
3. **Enumeración residual por 409 de registro** (amenaza 3): aceptado en
   contexto académico; en producción considerar respuesta 202 con email
   diferido.
4. **Disponibilidad de la BD** (amenaza 15): fuera del alcance del código;
   cubrir con backups y réplica en operación real.

## 4. Indicadores de seguimiento (DE.CM)

- Tasa de `LOGIN_FAIL` por cuenta/IP en ventanas de 5 min.
- Aparición de `REUSE_DETECTED` → incidente de sesión.
- Volumen de `429` y de `LOGIN_BLOCKED`.
- `npm audit` en cada ejecución de CI (debe ser 0).

Ver `docs/incident-response.md` para la respuesta ante estos indicadores.
