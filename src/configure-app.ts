import { ValidationPipe } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { NestExpressApplication } from '@nestjs/platform-express';
import cookieParser from 'cookie-parser';
import { json, urlencoded } from 'express';
import helmet from 'helmet';

/**
 * Configuración de seguridad compartida entre la aplicación de producción
 * (main.ts) y los tests e2e: lo que se prueba es exactamente lo que corre.
 */
export async function configureApp(
  app: NestExpressApplication,
): Promise<void> {
  const config = app.get(ConfigService);

  // Cabeceras de seguridad HTTP: HSTS, CSP, X-Frame-Options, no-sniff... (PR.PS)
  // HSTS y frameguard con valores idénticos a los de nginx: sin duplicados
  // contradictorios entre el proxy y la aplicación.
  app.use(
    helmet({
      hsts: { maxAge: 63072000, includeSubDomains: true, preload: true },
      frameguard: { action: 'deny' },
      referrerPolicy: { policy: 'no-referrer' },
    }),
  );
  app.use(cookieParser());

  // Límites de payload: mitigación de DoS por cuerpo gigante (PR.PS).
  app.use(json({ limit: '10kb' }));
  app.use(urlencoded({ extended: false, limit: '10kb' }));

  const express = app.getHttpAdapter().getInstance() as {
    disable(name: string): void;
    set(name: string, value: unknown): void;
  };
  express.disable('x-powered-by');

  // Solo detrás de nginx (que sobrescribe X-Forwarded-For); si no, el header
  // es falsificable y el rate limit por IP se evadiría (ver validación de env).
  express.set('trust proxy', config.get<string>('TRUST_PROXY') === 'true');

  const origins = config.get<string[]>('CORS_ORIGINS') ?? [];
  app.enableCors({
    origin: origins,
    credentials: true,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 600,
  });

  // Validación estricta: whitelist de campos y rechazo de extras (PR.PS).
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      stopAtFirstError: true,
    }),
  );
}
