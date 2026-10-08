import type { INestApplication } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import type { NestExpressApplication } from '@nestjs/platform-express';
import type { Response } from 'supertest';

export const TEST_DATABASE_URL =
  process.env['TEST_DATABASE_URL'] ??
  'postgresql://app:JQhWXsB241mubc1Wyyr4x9k5VffYFf-x@127.0.0.1:5433/login_service_test';

/**
 * Entorno base de pruebas. Los límites de tasa se suben para no interferir
 * entre tests; los tests de rate limit los sobreescriben con valores bajos.
 */
const TEST_ENV: Record<string, string> = {
  NODE_ENV: 'test',
  DATABASE_URL: TEST_DATABASE_URL,
  JWT_ACCESS_SECRET: 'test-secret-for-e2e-only-0123456789abcdefghijklmnop',
  JWT_ACCESS_TTL_SECONDS: '900',
  JWT_REFRESH_TTL_SECONDS: '604800',
  CORS_ORIGINS: 'http://localhost:5173,https://app.test',
  COOKIE_SECURE: 'false',
  TRUST_PROXY: 'false',
  LOG_LEVEL: 'fatal',
  RATE_LIMIT_ENABLED: 'true',
  RATE_LIMIT_GLOBAL_ATTEMPTS: '100000',
  RATE_LIMIT_GLOBAL_WINDOW_SECONDS: '60',
  RATE_LIMIT_LOGIN_ATTEMPTS: '1000',
  RATE_LIMIT_LOGIN_WINDOW_SECONDS: '900',
  RATE_LIMIT_REGISTER_ATTEMPTS: '1000',
  RATE_LIMIT_REGISTER_WINDOW_SECONDS: '60',
  RATE_LIMIT_REFRESH_ATTEMPTS: '1000',
  RATE_LIMIT_REFRESH_WINDOW_SECONDS: '60',
  ACCOUNT_MAX_FAILED_ATTEMPTS: '5',
  ACCOUNT_LOCK_MINUTES: '15',
};

export interface TestApp {
  app: INestApplication;
  close: () => Promise<void>;
}

/**
 * Crea una instancia de la aplicación real (mismo bootstrap que producción)
 * con el entorno de pruebas aplicado.
 *
 * Nota: `ConfigModule.forRoot()` se evalúa una sola vez (al importar
 * AppModule) y fija la validación de env, así que los `overrides` se aplican
 * de nuevo vía `ConfigService.set()` tras init, que tiene prioridad máxima.
 */
export async function createTestApp(
  overrides: Record<string, string> = {},
): Promise<TestApp> {
  Object.assign(process.env, TEST_ENV, overrides);

  // Import dinámico DESPUÉS de fijar las variables de entorno.
  const { AppModule } = await import('../../src/app.module.js');
  const { configureApp } = await import('../../src/configure-app.js');

  const moduleRef = await Test.createTestingModule({
    imports: [AppModule],
  }).compile();

  const app = moduleRef.createNestApplication<NestExpressApplication>({
    bodyParser: false,
  });
  await configureApp(app);
  await app.init();

  const config = app.get(ConfigService);
  for (const [key, value] of Object.entries(overrides)) {
    config.set(key, value);
  }
  if (overrides['TRUST_PROXY'] === 'true') {
    app.set('trust proxy', true);
  }

  return {
    app,
    close: async () => {
      await app.close();
      await moduleRef.close();
    },
  };
}

export function extractRefreshCookie(res: Response): string {
  const raw = res.headers['set-cookie'];
  const cookies = Array.isArray(raw) ? raw : raw ? [raw] : [];
  const refresh = cookies.find((c) => c.startsWith('refresh_token='));
  if (!refresh) {
    throw new Error('No se recibió cookie refresh_token');
  }
  return refresh.split(';')[0]!.split('=')[1]!;
}

export function randomEmail(prefix = 'user'): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 10)}@test.local`;
}

export const STRONG_PASSWORD = 'Tr0p-S3gura!2026';
