# Plan de respuesta a incidentes (RS.MA / RS.CO / RO.RP)

Alcance: incidentes de autenticación y sesión del servicio de login
(compromiso de credenciales, robo o replay de refresh token, abuso de
registro, denegación de servicio en el endpoint de login).

## 1. Detección (DE.CM / DE.AE)

Señales generadas por el propio sistema:

| Señales | Origen | Severidad |
| --- | --- | --- |
| Evento `REUSE_DETECTED` | rotación de refresh con token ya canjeado | **Alta** (sesión comprometida en curso) |
| Pico de `LOGIN_FAIL` o de `LOGIN_BLOCKED` de una misma cuenta | tabla `auth_events` | Media-Alta |
| Respuestas `429` masivas desde una IP (nginx o app) | logs de nginx / JSON de la app | Media |
| `LOGIN_FAIL` desde geolocalización/IP inusual | `auth_events.ip` | Media |
| Fallo de arranque por validación de entorno | log de arranque | Baja (operativa) |

Consulta base (índices `[type, createdAt]` y `[userId, createdAt]`):

```sql
SELECT type, "userId", ip, "userAgent", meta, "createdAt"
FROM auth_events
WHERE "createdAt" > now() - interval '1 hour'
ORDER BY "createdAt" DESC;
```

## 2. Contención (RS.MI)

1. **Sesión comprometida (reuso de refresh):** automático — la rotación
   revoca toda la familia de tokens (`familyId`) y responde 401. No requiere
   intervención manual.
2. **Cuenta bajo ataque:** bloqueo automático tras 5 fallos (15 min);
   si persiste, revocar manualmente todas las sesiones y forzar cambio de
   contraseña:

   ```sql
   UPDATE refresh_tokens SET "revokedAt" = now()
   WHERE "userId" = '<id>' AND "revokedAt" IS NULL;
   -- y, si procede:
   UPDATE users SET "lockedUntil" = now() + interval '24 hours'
   WHERE id = '<id>';
   ```

3. **Abuso desde una IP:** bloquear en nginx (`deny` o subir `limit_req`) y,
   si el ataque es distribuido, endurecer `RATE_LIMIT_LOGIN_*`.
4. **Indisponibilidad:** verificar `/health/ready`, estado de PostgreSQL y
   contenedores (`docker compose ps`); escalar a restauración si la BD está
   dañada (RO.RP).

## 3. Análisis (RS.AN)

- Reconstruir la secuencia con `auth_events` (IP, user-agent, metadatos) y
  logs JSON (pino) + `docker/nginx/logs`.
- Determinar vectores posibles: credential stuffing, robo de cookie, XSS,
  fuga de `JWT_ACCESS_SECRET`, o falsificación de `X-Forwarded-For`.
- Si se sospecha del secreto JWT: **rotarlo** (`JWT_ACCESS_SECRET` +
  reinicio). Como el access token dura 15 min, el impacto se limita a esa
  ventana; los refresh son opacos y no dependen del secreto.

## 4. Comunicación y escalado (RS.CO)

1. **Rol responsable** (a definir según el despliegue): técnico de guardia /
   responsable del repositorio.
2. Registrar el incidente con: fecha/hora, señales, cuentas afectadas,
   acciones tomadas y estado.
3. Comunicar a los usuarios afectados cuando haya compromiso de credenciales:
   obligar a restablecer contraseña y cerrar todas sus sesiones.
4. Si hay datos personales comprometidos, valorar la notificación exigida
   por la normativa aplicable (RGPD/Ley Orgánica de Protección de Datos).

## 5. Recuperación (RO.RP)

1. Restaurar el servicio verificando `/health` y un flujo completo
   registro → login → refresh → logout.
2. Validar la integridad de las cuentas afectadas (hashes intactos,
   `revokedAt` coherentes, bloqueos aplicados).
3. Confirmar que las variables de entorno siguen siendo válidas
   (el arranque con zod falla temprano ante cualquier regresión).
4. Verificar con `npm audit` que no hay vulnerabilidades introducidas.

## 6. Lecciones aprendidas (RO.CV)

- Tras cada incidente: actualizar `docs/risk-assessment.md` (nueva amenaza o
  cambio de probabilidad), `docs/security-policy.md` si cambia una regla y
  las pruebas asociadas (`test/security.e2e-spec.ts`).
- Criterios de éxito: tiempo desde la señal (`REUSE_DETECTED`) hasta la
  contención; cobertura de auditoría (ningún evento de login sin registro).

## 7. Prevención continua

- CI en cada *push*/PR: lint, tipos, unit, e2e con PostgreSQL, build y
  `npm audit` (debe mantenerse en 0 vulnerabilidades).
- Revisión periódica de `auth_events` y de los umbrales de rate limit.
