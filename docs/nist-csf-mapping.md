# Mapeo NIST CSF 2.0 → implementación y evidencia

Cada subcategoría relevante del alcance apunta al control concreto y a su
evidencia verificable (código, configuración o prueba).

## GOVERN (GV)

| Subcategoría | Implementación | Evidencia |
| --- | --- | --- |
| GV.PO-05 | Políticas de seguridad escritas y aplicadas en código (denegación por defecto, cookies, TLS, contraseñas) | `docs/security-policy.md`, `src/app.module.ts` (APP_GUARD) |
| GV.RM-02 | Riesgos identificados, valorados y con plan de tratamiento | `docs/risk-assessment.md` |
| GV.SC-03 | Proveedores/dependencias evaluadas y actualizadas | `package-lock.json`, `npm run audit` en CI (`.github/workflows/ci.yml`) |
| GV.RR-02 | Roles y responsabilidades de respuesta definidos | `docs/incident-response.md` (sección de roles) |

## IDENTIFY (ID)

| Subcategoría | Implementación | Evidencia |
| --- | --- | --- |
| ID.AM-01/02 | Inventario de activos de red y software: servicios Docker, módulos Nest, tablas Prisma | `docker-compose.yml`, `prisma/schema.prisma`, `docs/architecture.md` |
| ID.AM-05 | Priorización según riesgo de los componentes del servicio | `docs/risk-assessment.md` §1 |
| ID.RA-01/05 | Evaluación de vulnerabilidades: amenazas y vulnerabilidades conocidas | `docs/risk-assessment.md`, `npm audit` (0 hallazgos) |
| ID.IM-01 | Mejoras identificadas a partir del análisis | `docs/risk-assessment.md` §3 (riesgos residuales) |

## PROTECT (PR)

| Subcategoría | Implementación | Evidencia |
| --- | --- | --- |
| PR.AA-01 | Acceso identificado y gestionado: usuarios con credenciales únicas, JWT con `sub` | `src/auth/auth.service.ts`, `src/auth/strategies/*` |
| PR.AA-03 | Gestión segura de autenticadores: argon2id, zxcvbn, política 12–128, rotación de refresh, revocación en logout | `src/auth/password-policy.service.ts`, `src/auth/session.service.ts` |
| PR.AA-05 | Sesión protegida: expiración, `SameSite=Strict`, `HttpOnly`, origen validado | `src/auth/session.service.ts`, `src/auth/guards/origin.guard.ts` |
| PR.PS-01 | Acceso de red permitido y gestionado: CORS whitelist, rutas públicas explícitas | `src/configure-app.ts`, `@Public()` |
| PR.PS-02 | Protecciones de seguridad en la infraestructura: helmet, TLS 1.2/1.3, HSTS, nginx | `docker/nginx/nginx.conf`, `src/configure-app.ts` |
| PR.DS-01/02 | Protección de datos en reposo/tránsito: hashes argon2id y SHA-256, TLS, cookies `Secure` | `prisma/schema.prisma`, `src/auth/session.service.ts` |
| PR.DS-10 | Integridad de datos: prepared statements de Prisma, migraciones versionadas | `prisma/migrations/` |
| PR.IR-01 | Gestión de la cadena de suministro: `npm ci`, auditoría en CI, build multi-stage no root | `.github/workflows/ci.yml`, `Dockerfile` |

## DETECT (DE)

| Subcategoría | Implementación | Evidencia |
| --- | --- | --- |
| DE.CM-01 | La red se monitorea: logs JSON de acceso/error con pino + acceso log de nginx | `src/app.module.ts` (LoggerModule), `docker/nginx/nginx.conf` |
| DE.CM-03 | El servicio se monitorea para actividad no autorizada: eventos de auditoría de autenticación | `src/audit/audit.service.ts`, tabla `auth_events` |
| DE.CM-09 | Intentos de acceso anómalos computados: `LOGIN_FAIL`, `LOGIN_BLOCKED`, `REUSE_DETECTED`, contadores de rate limit | `test/auth.e2e-spec.ts`, `test/security.e2e-spec.ts` |
| DE.AE-03 | Análisis de eventos para correlacionarlos | índices `[type, createdAt]`, `[userId, createdAt]` en `AuthEvent` |

## RESPOND (RS)

| Subcategoría | Implementación | Evidencia |
| --- | --- | --- |
| RS.MA-01 | Incidente confirmado se ejecuta un plan | `docs/incident-response.md` |
| RS.MA-02 | El plan se comunica según procedimiento definido | `docs/incident-response.md` §4 (escalado) |
| RS.CO-02 | Información de incidente compartida con las partes según criterios | `docs/incident-response.md` §4 |
| RS.AN-03 | Causa raíz analizada con la evidencia de auditoría | `auth_events` + logs JSON |
| RS.MI-01 | Contención: revocación automática de la familia de sesiones ante reuso | `src/auth/session.service.ts` (rotación/reuso) |

## RECOVER (RO)

| Subcategoría | Implementación | Evidencia |
| --- | --- | --- |
| RO.RP-01 | Recuperación ejecuta un plan: restaurar sesiones (re-login) y verificar integridad de cuentas | `docs/incident-response.md` §5 |
| RO.CV-01 | Lecciones aprendidas se integran en la política | `docs/incident-response.md` §6, `docs/risk-assessment.md` §3 |

## Cobertura por pruebas automatizadas

| Control | Prueba |
| --- | --- |
| Registro/login/refresh/logout, rotación, reuso → revocación | `test/auth.e2e-spec.ts` (22) |
| Cabeceras, CORS, validación, 413, ausencia de stack traces, rate limit por IP e identificador | `test/security.e2e-spec.ts` (13) |
| Validez del entorno (fallo temprano) | `src/config/env.validation.spec.ts` |
| Política de contraseñas/zxcvbn | `src/auth/password-policy.service.spec.ts` |
| Ventana deslizante del rate limit | `src/common/rate-limit/rate-limit.store.spec.ts` |
