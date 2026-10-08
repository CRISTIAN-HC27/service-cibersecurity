import type { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PrismaService } from '../src/prisma/prisma.service.js';
import {
  STRONG_PASSWORD,
  createTestApp,
  randomEmail,
  type TestApp,
} from './utils/test-app.js';

/**
 * Controles de seguridad perimetrales y de aplicación:
 * cabeceras, CORS, rate limiting, límites de payload e inyección SQL.
 */
describe('Controles de seguridad (e2e)', () => {
  let testApp: TestApp;
  let app: INestApplication;
  let prisma: PrismaService;

  beforeAll(async () => {
    testApp = await createTestApp();
    app = testApp.app;
    prisma = app.get(PrismaService);
  });

  afterAll(async () => {
    await prisma.user.deleteMany({ where: { email: { contains: 'test.local' } } });
    await testApp.close();
  });

  describe('Cabeceras de seguridad (helmet)', () => {
    it('aplica las cabeceras de seguridad HTTP', async () => {
      const res = await request(app.getHttpServer())
        .get('/health')
        .expect(200);

      expect(res.headers['content-security-policy']).toContain("default-src 'self'");
      expect(res.headers['x-content-type-options']).toBe('nosniff');
      expect(res.headers['x-frame-options']).toBeDefined();
      expect(res.headers['referrer-policy']).toBe('no-referrer');
      expect(res.headers['x-powered-by']).toBeUndefined();
    });

    it('envía HSTS cuando la conexión es HTTPS', async () => {
      // helmet lo configura en todas las respuestas (útil detrás de TLS).
      const res = await request(app.getHttpServer()).get('/health');
      expect(res.headers['strict-transport-security']).toContain('max-age=');
    });
  });

  describe('CORS', () => {
    it('permite solo orígenes de la whitelist', async () => {
      const allowed = await request(app.getHttpServer())
        .get('/health')
        .set('Origin', 'http://localhost:5173')
        .expect(200);

      expect(allowed.headers['access-control-allow-origin']).toBe(
        'http://localhost:5173',
      );
      expect(allowed.headers['access-control-allow-credentials']).toBe('true');
    });

    it('no concede cabeceras CORS a orígenes no permitidos', async () => {
      const res = await request(app.getHttpServer())
        .get('/health')
        .set('Origin', 'https://evil.example')
        .expect(200);

      expect(res.headers['access-control-allow-origin']).toBeUndefined();
    });
  });

  describe('Validación estricta de entrada', () => {
    it('bloquea intentos de inyección SQL en el email', async () => {
      const before = await prisma.user.count();

      const res = await request(app.getHttpServer())
        .post('/auth/register')
        .send({
          email: "'; DROP TABLE users; --@evil.test",
          password: STRONG_PASSWORD,
        })
        .expect(400);

      expect(JSON.stringify(res.body)).not.toContain('DROP TABLE');
      expect(await prisma.user.count()).toBe(before);
      // La tabla sigue consultable: ninguna query fue interpretada.
      const rows = await prisma.user.findMany({ take: 1 });
      expect(Array.isArray(rows)).toBe(true);
    });

    it('rechaza payloads con campos desconocidos', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/login')
        .send({ email: 'a@b.co', password: 'x', role: 'admin' })
        .expect(400);

      expect(JSON.stringify(res.body)).toContain('role');
    });

    it('limita el tamaño del cuerpo (10kb)', async () => {
      const big = 'a'.repeat(20_000);
      await request(app.getHttpServer())
        .post('/auth/register')
        .set('Content-Type', 'application/json')
        .send(JSON.stringify({ email: 'big@test.local', password: big }))
        .expect(413);
    });

    it('no filtra trazas internas en las respuestas de error', async () => {
      const loginRes = await request(app.getHttpServer())
        .post('/auth/login')
        .send({ email: 'nope@test.local', password: 'x' })
        .expect(401);

      const registerRes = await request(app.getHttpServer())
        .post('/auth/register')
        .send({ email: 'bad@test.local', password: 'short' })
        .expect(400);

      for (const res of [loginRes, registerRes]) {
        const body = JSON.stringify(res.body);
        expect(body).not.toContain('at Object.');
        expect(body).not.toContain('node_modules');
        expect(body).not.toContain('PrismaClient');
        expect(res.headers['x-powered-by']).toBeUndefined();
      }
    });
  });

  describe('Rate limiting de autenticación', () => {
    let limited: TestApp;

    beforeAll(async () => {
      limited = await createTestApp({
        RATE_LIMIT_LOGIN_ATTEMPTS: '3',
        RATE_LIMIT_LOGIN_WINDOW_SECONDS: '60',
        // Necesario para que X-Forwarded-For determine req.ip (detrás de nginx).
        TRUST_PROXY: 'true',
        COOKIE_SECURE: 'true',
      });
    });

    afterAll(async () => {
      await limited.close();
    });

    it('bloquea tras superar el límite de intentos por IP y responde 429', async () => {
      const srv = limited.app.getHttpServer();
      const email = randomEmail('ratelimit');
      const payload = { email, password: 'Clave-Que-No-Es!1' };

      const codes: number[] = [];
      for (let i = 0; i < 5; i++) {
        const res = await request(srv).post('/auth/login').send(payload);
        codes.push(res.status);
        if (res.status === 429) {
          expect(res.headers['retry-after']).toBeDefined();
          expect(res.body.message).toContain('Demasiadas solicitudes');
        }
      }

      expect(codes.filter((c) => c === 429).length).toBeGreaterThan(0);
      expect(codes[0]).not.toBe(429);
    });

    it('limita también por identificador (email) aunque cambie la IP', async () => {
      const srv = limited.app.getHttpServer();
      const email = randomEmail('per-id');
      const payload = { email, password: 'Otra-Clave!222' };

      // Misma cuenta desde IPs distintas (trust proxy simula el XFF real).
      for (let i = 0; i < 4; i++) {
        const res = await request(srv)
          .post('/auth/login')
          .set('X-Forwarded-For', `10.0.0.${i + 1}`)
          .send(payload);

        if (i >= 3) {
          // El contador por email ya se agotó (límite 3) pese a nueva IP.
          expect(res.status).toBe(429);
        } else {
          expect(res.status).toBe(401);
        }
      }
    });
  });

  describe('Endpoints públicos', () => {
    it('GET /health responde sin autenticación', async () => {
      await request(app.getHttpServer()).get('/health').expect(200);
    });

    it('GET /health/ready valida la conexión a la BD', async () => {
      await request(app.getHttpServer()).get('/health/ready').expect(200);
    });

    it('todo lo demás está denegado por defecto', async () => {
      await request(app.getHttpServer()).get('/users').expect(404);
      await request(app.getHttpServer()).get('/admin').expect(404);
      await request(app.getHttpServer()).post('/auth/admin').expect(404);
    });
  });
});
