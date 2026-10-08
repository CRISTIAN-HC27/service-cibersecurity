# Servicio de login seguro — NIST CSF 2.0

Servicio de autenticación construido con **NestJS + Prisma + PostgreSQL** como
ejercicio práctico de la asignatura de Seguridad de la Información, alineado
al **NIST Cybersecurity Framework 2.0**.

## Alcance acordado

- **JWT + refresh tokens rotativos** (el refresh es opaco, de un solo uso y se
  agrupa en familias; la reutilización revoca la sesión completa).
- **Registro + Login + Refresh** (con logout incluido).
- **ORM:** Prisma · **Contexto:** académico con despliegue real (Docker) y
  documentación NIST fuerte.

## Fases del plan

| # | Fase | Estado |
| --- | --- | --- |
| 1 | Scaffold NestJS, esquema Prisma (`users`, `refresh_tokens`, `auth_events`), migración inicial, `.env.example`, Dockerfile + compose | ✅ |
| 2 | Seguridad base: helmet, CORS con whitelist, `ValidationPipe` con whitelist, logs JSON con pino y redacción de credenciales, ThrottlerGuard, validación de entorno con zod (fallo temprano) | ✅ |
| 3 | Registro y login: zxcvbn + política de contraseñas, argon2id (m=64 MiB, t=3, p=4), timing uniforme, bloqueo de cuenta progresivo, auditoría de eventos | ✅ |
| 4 | Sesiones: rotación de refresh token con reclamo atómico, detección de reuso → revocación de familia, cookie `HttpOnly; SameSite=Strict`, `OriginGuard` (CSRF) | ✅ |
| 5 | Despliegue: nginx con TLS 1.2/1.3, HSTS, redirect HTTP→HTTPS, rate limit en el borde (1 r/s en `/auth/*`), certificados autogenerados | ✅ |
| 6 | Pruebas: 17 unit (env, política de contraseñas, ventana deslizante) + 35 e2e (flujos de auth y controles de seguridad) con PostgreSQL de pruebas | ✅ |
| 7 | CI: lint, tipos, build, `npm audit`, unitarias y e2e con servicio PostgreSQL (`.github/workflows/ci.yml`) | ✅ |
| 8 | Documentación NIST: arquitectura, política de seguridad, evaluación de riesgos, mapeo CSF 2.0, respuesta a incidentes | ✅ |

## Puesta en marcha

### Con Docker (recomendado)

```bash
# Requiere Docker + Docker Compose; genera el certificado TLS la primera vez
docker compose up --build
```

- API: `https://localhost` (redirige desde `http://localhost`; certificado
  autogenerado → usar `-k` en curl o aceptar el aviso en el navegador)
- Interfaz web (cliente del servicio): **`https://localhost/app/`**
- PostgreSQL: `127.0.0.1:${POSTGRES_PORT:-5433}` (solo para desarrollo local)

### Interfaz web

`web/` es un cliente HTML/CSS/JS sin build (sin frameworks ni dependencias)
que nginx sirve como estáticos en `/app/`. Tiene dos vistas con navegación:

- **Acceso** (`#/acceso`): registrarse, iniciar sesión, consultar `/users/me`,
  renovar la sesión y cerrar sesión contra la API real.
- **Panel de seguridad** (`#/panel`): usuarios con sesión vigente y los
  últimos eventos de autenticación (`/admin/*`). Solo para los correos de
  `ADMIN_EMAILS`; si no eres admin verás `403`.

- Mismo origen que la API → sin CORS entre medias y la cookie
  `SameSite=Strict` funciona sin problemas.
- El access token se guarda **solo en memoria** (nada en `localStorage`); el
  refresh es una cookie `HttpOnly` que el JavaScript nunca lee.
- `CORS_ORIGINS` debe incluir el origen con el que abres la interfaz
  (p. ej. `https://localhost`) para que `OriginGuard` acepte refresh y logout.
- Se puede abrir también sin Docker (`web/index.html`), apuntando a la API con
  `CORS_ORIGINS` configurado; en ese caso usa un servidor local, no `file://`.


### Desarrollo local

```bash
npm install
npm run prisma:migrate     # aplica migraciones a la BD de desarrollo
npm run start:dev          # watch mode en :3000
```

Requiere PostgreSQL accesible y `.env` (copiar de `.env.example`).
Toda la configuración se valida con zod al arrancar: un valor inválido
impide el arranque con un mensaje concreto.

## Endpoints

| Método | Ruta | Acceso | Rate limit propio |
| --- | --- | --- | --- |
| POST | `/auth/register` | público | 5 / 60 s |
| POST | `/auth/login` | público | 5 / 900 s (por IP **y** email) |
| POST | `/auth/refresh` | cookie `refresh_token` + `Origin` | 30 / 60 s |
| POST | `/auth/logout` | cookie `refresh_token` | 30 / 60 s |
| GET | `/users/me` | JWT de acceso | global |
| GET | `/admin/overview`, `/admin/active-users`, `/admin/events` | JWT + `ADMIN_EMAILS` | global |
| GET | `/health`, `/health/ready` | público | global |

Todo lo demás está **denegado por defecto** (`JwtAuthGuard` global + `@Public()`
explícito). El panel `/admin/*` es de **solo lectura** y solo accesible para
los correos listados en `ADMIN_EMAILS` (vacío = deshabilitado); cada vista se
audita como evento `ADMIN_VIEW`.

Ejemplo:

```bash
curl -k -c jar -X POST https://localhost/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"alguien@ejemplo.com","password":"Tr0p-S3gura!2026"}'

curl -k -c jar -b jar -X POST https://localhost/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"alguien@ejemplo.com","password":"Tr0p-S3gura!2026"}'
# → accessToken (JSON) + refresh_token (cookie HttpOnly)
```

## Pruebas y calidad

```bash
npm run lint               # oxlint (type-aware)
npm run typecheck          # tsc --noEmit
npm test                   # unitarias (vitest)
npm run test:e2e           # e2e contra login_service_test
npm run audit              # 0 vulnerabilidades (high, producción)
npm run build
```

Las e2e levantan la **misma aplicación real** (`configureApp` compartido con
`main.ts`) y aplican migraciones en `test/global-setup.ts`.

## Documentación

| Documento | Contenido |
| --- | --- |
| [`docs/architecture.md`](docs/architecture.md) | Componentes, flujos de auth, rate limiting en dos capas, configuración |
| [`docs/security-policy.md`](docs/security-policy.md) | Política de contraseñas, sesiones, cabeceras, cookies, registros |
| [`docs/risk-assessment.md`](docs/risk-assessment.md) | Activos, amenazas, controles y riesgo residual (GV.RM / ID.RA) |
| [`docs/nist-csf-mapping.md`](docs/nist-csf-mapping.md) | Subcategorías CSF 2.0 → control → evidencia y prueba automatizada |
| [`docs/incident-response.md`](docs/incident-response.md) | Detección, contención, análisis, comunicación y recuperación |

## Estructura

```
src/
├── auth/          registro, login, sesión (rotación), guards, política
├── admin/         panel de solo lectura (logs, usuarios activos) + AdminGuard
├── audit/         eventos de autenticación (evidencia DE.CM)
├── common/        rate limit, decoradores @Public/@RateLimitKey, filtros
├── config/        esquema zod de entorno (fallo temprano)
├── users/         GET /users/me (recurso protegido)
├── health/        liveness y readiness
├── prisma/        cliente y conexión
└── configure-app.ts  seguridad compartida entre prod y tests
prisma/            esquema + migraciones
docker/            nginx, entrypoint, generación de certificados
web/               interfaz web (cliente del servicio, servida en /app/)
test/              e2e (auth, security) + utilidades
docs/              entregables NIST
```

## Límites conocidos

- Rate limit **en memoria por instancia**: para multi-réplica migrar
  `RateLimitStore` a Redis.
- Sin MFA ni verificación de email (riesgo residual documentado).
- Residual: el 409 de registro puede revelar existencia de cuenta (mensaje
  genérico; alternativa futura: respuesta 202 diferida).
