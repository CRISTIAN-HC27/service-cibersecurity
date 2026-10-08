# Arquitectura del servicio de autenticación

Servicio de login seguro construido con NestJS 12, Prisma 7 y PostgreSQL 18,
diseñado como evidencia práctica del **NIST Cybersecurity Framework 2.0**.

## Vista general

```
                 HTTPS (TLS 1.2/1.3, HSTS)
 Cliente ──────────────────────────────► nginx (docker/nginx/nginx.conf)
                                            │  limit_req: auth 1 r/s, api 10 r/s
                                            │  X-Forwarded-For (proxy de confianza)
                                            ▼
                                     NestJS :3000 (Docker)
                                     ┌──────────────────────────────┐
                                     │ helmet · cookie-parser       │
                                     │ json/urlencoded 10 kB        │
                                     │ CORS (whitelist)             │
                                     │ ThrottlerGuard (global)      │
                                     │ RateLimitGuard (por ruta)    │
                                     │ JwtAuthGuard (denegación     │
                                     │   por defecto, @Public)      │
                                     │ ValidationPipe (whitelist)   │
                                     │ HttpExceptionFilter          │
                                     │ Logger estructurado (pino)   │
                                     └──────────────────────────────┘
                                            │ Prisma (pool pg)
                                            ▼
                                       PostgreSQL 18
                                  users · refresh_tokens · auth_events
```

Las tres piezas se levantan con `docker compose up` (`docker-compose.yml`);
nginx termina TLS con el certificado autogenerado en `docker/nginx/generate-cert.sh`.
La interfaz web (`web/`) se sirve como estáticos en `/app/` desde ese mismo
nginx, por lo que sus llamadas a la API van al mismo origen (sin CORS).

## Módulos de la aplicación

| Módulo | Responsabilidad |
| --- | --- |
| `auth` | Registro, login, rotación de refresh, logout, guards (`JwtAuthGuard`, `OriginGuard`) y servicios (`AuthService`, `SessionService`, `PasswordPolicyService`) |
| `users` | `GET /users/me` (recurso protegido de ejemplo) |
| `health` | `GET /health` (liveness) y `GET /health/ready` (DB) |
| `audit` | Escritura de eventos de autenticación en `AuthEvent` |
| `common` | Rate limiting en memoria, decoradores (`@Public`, `@RateLimitKey`), filtro de excepciones |
| `admin` | Panel de solo lectura (logs y usuarios activos) con `AdminGuard` (whitelist `ADMIN_EMAILS`) |
| `prisma` | Cliente y conexión a la base de datos |
| `config` | Esquema zod de variables de entorno con fallo temprano |

## Endpoints

| Método | Ruta | Control de acceso | Límite de tasa propio |
| --- | --- | --- | --- |
| POST | `/auth/register` | Público | `RATE_LIMIT_REGISTER_*` |
| POST | `/auth/login` | Público | `RATE_LIMIT_LOGIN_*` |
| POST | `/auth/refresh` | Cookie `refresh_token` + `OriginGuard` | `RATE_LIMIT_REFRESH_*` |
| POST | `/auth/logout` | Cookie `refresh_token` | `RATE_LIMIT_REFRESH_*` |
| GET | `/users/me` | JWT de acceso | global |
| GET | `/admin/overview` | JWT + `AdminGuard` (`ADMIN_EMAILS`) | global |
| GET | `/admin/active-users` | JWT + `AdminGuard` (`ADMIN_EMAILS`) | global |
| GET | `/admin/events?limit=&type=` | JWT + `AdminGuard` (`ADMIN_EMAILS`) | global |
| GET | `/health`, `/health/ready` | Público | global |

Todo lo demás está **denegado por defecto** (el `JwtAuthGuard` es global y las
rutas públicas se marcan explícitamente con `@Public()`).

## Flujo de autenticación

### Registro
1. `ValidationPipe` (whitelist) + zod descartan campos extra o mal formados.
2. Se calcula zxcvbn **antes** de tocar la base de datos; se exige score ≥ 3,
   longitud 12–128 y se usa el email como contexto.
3. Se hashea con **argon2id** (m=64 MiB, t=3, p=4) *siempre*, también si la
   cuenta ya existe, para no revelar existencia de cuentas mediante tiempos.
4. Duplicado → `409` con mensaje genérico.

### Login
1. Rate limit por IP y por email (`RateLimitGuard`).
2. Búsqueda del usuario; si no existe se compara contra un hash argon2id
   simulado (**timing uniforme**).
3. Verificación argon2id; fallo → `401` con mensaje genérico
   `Credenciales inválidas` (no distingue usuario/contraseña/lockout).
4. Bloqueo progresivo de cuenta: `ACCOUNT_MAX_FAILED_ATTEMPTS` fallos
   consecutivos → `lockedUntil = now + ACCOUNT_LOCK_MINUTES` (`LOGIN_BLOCKED`).
5. Éxito → JWT de acceso (15 min por defecto) + refresh opaco en cookie
   `HttpOnly; SameSite=Strict; Path=/auth/refresh; Secure` (nunca en el body).

### Refresh con rotación (one-time use)
1. El refresh es un token opaco de 32 bytes; en BD solo se guarda su
   **hash SHA-256**, agrupado en familias (`familyId`).
2. Cada canje usa un reclamo atómico CAS (`updateMany` con `revokedAt: null`):
   solo una petición puede consumirlo.
3. Se emite un token nuevo **de la misma familia** y se enlaza `replacedBy`.
4. **Reutilización de un token ya canjeado** → alguien lo robó: se revoca
   *toda la familia* y se registra `REUSE_DETECTED` (mitigación de robo de
   refresh token).
5. `OriginGuard` exige `Origin` dentro de la whitelist (o `Sec-Fetch-Site`
   distinto de `cross-site`) en las rutas con cookie, como defensa CSRF.

### Logout
Revoca el token presente en la cookie (`LOGOUT` en auditoría) y borra la cookie.

## Rate limiting en dos capas

1. **nginx** (`limit_req`): 1 r/s por IP en `/auth/*`, 10 r/s en el resto;
   responde `429` antes de llegar a la aplicación (protección de capacidad).
2. **`ThrottlerGuard` global**: techo amplio (`RATE_LIMIT_GLOBAL_*`) para
   toda la API.
3. **`RateLimitGuard`** por ruta (`@RateLimitKey`): ventana deslizante en
   memoria con **dos contadores**: uno por IP (`request.ip`, respeta
   `TRUST_PROXY`) y otro por identificador (email del body), para que un
   atacante con IPs rotativas no pueda fuerza-brutear una cuenta.

`TRUST_PROXY=true` solo se permite junto con `COOKIE_SECURE=true` (validado
en `env.validation.ts`): detrás de TLS/nginx, nunca expuesto directamente.

## Configuración

Toda la configuración sale del entorno y se valida con zod al arrancar
(`src/config/env.validation.ts`); un valor inválido impide el arranque.
Ver `.env.example` para el listado completo. Resumen:

| Variable | Defecto | Nota |
| --- | --- | --- |
| `JWT_ACCESS_TTL_SECONDS` | 900 | vida corta del access token |
| `JWT_REFRESH_TTL_SECONDS` | 604800 (7 d) | rotativo; el robo detectable lo revoca |
| `RATE_LIMIT_LOGIN_ATTEMPTS/WINDOW` | 5 / 900 s | por IP y por email |
| `ACCOUNT_MAX_FAILED_ATTEMPTS` / `ACCOUNT_LOCK_MINUTES` | 5 / 15 min | bloqueo de cuenta |
| `COOKIE_SECURE` | `true` | obligatorio en producción |
| `TRUST_PROXY` | `false` | solo detrás de nginx |
| `CORS_ORIGINS` | `http://localhost:5173` | whitelist, sin `*` (incluir el origen de la interfaz, p. ej. `https://localhost`) |
| `ADMIN_EMAILS` | vacío (panel deshabilitado) | whitelist de admins del panel `/admin/*`, sin vía auto-registro |

## Desarrollo y pruebas

- **Producción local**: `docker compose up --build` → API en https://localhost
  e interfaz web en https://localhost/app/.
- **Desarrollo**: PostgreSQL en `127.0.0.1:5433` (cluster de usuario),
  `npm run start:dev`, `npm run prisma:migrate`.
- **Pruebas**: `npm run lint`, `npm run typecheck`, `npm test` (17 unit),
  `npm run test:e2e` (35 e2e contra `login_service_test`,
  migraciones aplicadas en `test/global-setup.ts`), `npm run audit`.
- **CI**: `.github/workflows/ci.yml` ejecuta lint/tipos/build/audit,
  unitarias y e2e con servicio PostgreSQL.

## Límites conocidos

- El rate limit en memoria es **por instancia**: para despliegues
  multi-réplica debe migrarse a un almacén compartido (p. ej. Redis).
- No hay verificación de email ni MFA en el alcance actual.
