import { describe, expect, it } from 'vitest';
import { validateEnv } from './env.validation.js';

const base = {
  DATABASE_URL: 'postgresql://user:pass@localhost:5432/db',
  JWT_ACCESS_SECRET: 'a'.repeat(48),
  CORS_ORIGINS: 'http://localhost:5173',
};

describe('validación de entorno', () => {
  it('acepta una configuración válida y aplica valores por defecto', () => {
    const env = validateEnv({ ...base });
    expect(env.NODE_ENV).toBe('development');
    expect(env.PORT).toBe(3000);
    expect(env.JWT_ACCESS_TTL_SECONDS).toBe(900);
    expect(env.CORS_ORIGINS).toEqual(['http://localhost:5173']);
    expect(env.RATE_LIMIT_LOGIN_ATTEMPTS).toBe(5);
  });

  it('falla temprano si falta el secreto JWT', () => {
    expect(() => validateEnv({ ...base, JWT_ACCESS_SECRET: undefined })).toThrow(
      /JWT_ACCESS_SECRET/,
    );
  });

  it('rechaza secretos demasiado cortos', () => {
    expect(() => validateEnv({ ...base, JWT_ACCESS_SECRET: 'corto' })).toThrow(
      /32 caracteres/,
    );
  });

  it('rechaza el secreto de ejemplo del .env.example', () => {
    expect(() =>
      validateEnv({
        ...base,
        JWT_ACCESS_SECRET: 'change_me_with_a_random_secret_of_at_least_32_bytes',
      }),
    ).toThrow(/ejemplo/);
  });

  it('rechaza wildcard en CORS_ORIGINS', () => {
    expect(() =>
      validateEnv({ ...base, CORS_ORIGINS: '*' }),
    ).toThrow();
  });

  it('exige DATABASE_URL de PostgreSQL', () => {
    expect(() =>
      validateEnv({ ...base, DATABASE_URL: 'mysql://localhost/db' }),
    ).toThrow(/PostgreSQL/);
  });

  it('en producción exige cookies seguras (HTTPS)', () => {
    expect(() =>
      validateEnv({ ...base, NODE_ENV: 'production', COOKIE_SECURE: 'false' }),
    ).toThrow(/COOKIE_SECURE/);
  });

  it('TRUST_PROXY solo con TLS', () => {
    expect(() =>
      validateEnv({ ...base, TRUST_PROXY: 'true', COOKIE_SECURE: 'false' }),
    ).toThrow(/TRUST_PROXY/);
    expect(() =>
      validateEnv({ ...base, TRUST_PROXY: 'true', COOKIE_SECURE: 'true' }),
    ).not.toThrow();
  });
});
