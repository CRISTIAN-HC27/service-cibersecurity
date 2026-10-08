import { z } from 'zod';

const PLACEHOLDER_SECRET =
  'change_me_with_a_random_secret_of_at_least_32_bytes';

const asBoolean = z.enum(['true', 'false']);

export const envSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
    PORT: z.coerce.number().int().min(1).max(65535).default(3000),
    DATABASE_URL: z
      .url()
      .refine((v) => v.startsWith('postgres://') || v.startsWith('postgresql://'), {
        message: 'DATABASE_URL debe ser una URL de PostgreSQL',
      }),
    JWT_ACCESS_SECRET: z
      .string()
      .min(32, 'JWT_ACCESS_SECRET debe tener al menos 32 caracteres')
      .refine((v) => v !== PLACEHOLDER_SECRET, {
        message: 'JWT_ACCESS_SECRET no puede ser el valor de ejemplo',
      }),
    JWT_ACCESS_TTL_SECONDS: z.coerce.number().int().min(60).max(86400).default(900),
    JWT_REFRESH_TTL_SECONDS: z.coerce
      .number()
      .int()
      .min(300)
      .max(2592000)
      .default(604800),
    CORS_ORIGINS: z
      .string()
      .default('http://localhost:5173')
      .transform((v) =>
        v
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
      )
      .refine((origins) => origins.length > 0, { message: 'CORS_ORIGINS vacío' })
      .refine((origins) => !origins.includes('*'), {
        message: 'CORS_ORIGINS no admite el wildcard "*"',
      }),
    COOKIE_SECURE: asBoolean.default('true'),
    // Correos con acceso al panel de administración (/admin/*). Vacío = panel
    // deshabilitado. Nunca se concede el rol por auto-registro (PR.AA).
    ADMIN_EMAILS: z
      .string()
      .default('')
      .transform((v) =>
        v
          .split(',')
          .map((s) => s.trim().toLowerCase())
          .filter(Boolean),
      ),
    // Solo true cuando hay un proxy (nginx) que sobrescribe X-Forwarded-For.
    // Si se activa sin proxy, un atacante puede falsear la IP y evadir el rate limit.
    TRUST_PROXY: asBoolean.default('false'),
    RATE_LIMIT_ENABLED: asBoolean.default('true'),
    RATE_LIMIT_GLOBAL_ATTEMPTS: z.coerce.number().int().min(1).default(100),
    RATE_LIMIT_GLOBAL_WINDOW_SECONDS: z.coerce.number().int().min(1).default(60),
    RATE_LIMIT_LOGIN_ATTEMPTS: z.coerce.number().int().min(1).default(5),
    RATE_LIMIT_LOGIN_WINDOW_SECONDS: z.coerce.number().int().min(1).default(900),
    RATE_LIMIT_REGISTER_ATTEMPTS: z.coerce.number().int().min(1).default(5),
    RATE_LIMIT_REGISTER_WINDOW_SECONDS: z.coerce.number().int().min(1).default(60),
    RATE_LIMIT_REFRESH_ATTEMPTS: z.coerce.number().int().min(1).default(30),
    RATE_LIMIT_REFRESH_WINDOW_SECONDS: z.coerce.number().int().min(1).default(60),
    ACCOUNT_MAX_FAILED_ATTEMPTS: z.coerce.number().int().min(1).default(5),
    ACCOUNT_LOCK_MINUTES: z.coerce.number().int().min(1).default(15),
    LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
  })
  .superRefine((config, ctx) => {
    if (config.NODE_ENV === 'production' && config.COOKIE_SECURE !== 'true') {
      ctx.addIssue({
        code: 'custom',
        path: ['COOKIE_SECURE'],
        message: 'En producción COOKIE_SECURE debe ser "true" (exige HTTPS)',
      });
    }
    if (config.TRUST_PROXY === 'true' && config.COOKIE_SECURE !== 'true') {
      ctx.addIssue({
        code: 'custom',
        path: ['TRUST_PROXY'],
        message:
          'TRUST_PROXY solo debe usarse detrás de TLS (COOKIE_SECURE=true); si no, X-Forwarded-For es falsificable',
      });
    }
  });

export type Env = z.infer<typeof envSchema>;

export function validateEnv(config: Record<string, unknown>): Env {
  const parsed = envSchema.safeParse(config);
  if (!parsed.success) {
    const details = parsed.error.issues
      .map((issue) => `${issue.path.join('.')}: ${issue.message}`)
      .join('\n  ');
    throw new Error(
      `Configuración de entorno inválida (fallo temprano - ID.AM/GV.PO):\n  ${details}`,
    );
  }
  return parsed.data;
}
