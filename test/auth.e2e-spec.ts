import type { INestApplication } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PrismaService } from '../src/prisma/prisma.service.js';
import {
  STRONG_PASSWORD,
  createTestApp,
  extractRefreshCookie,
  randomEmail,
  type TestApp,
} from './utils/test-app.js';

describe('Flujos de autenticación (e2e)', () => {
  let testApp: TestApp;
  let app: INestApplication;
  let prisma: PrismaService;

  const email = randomEmail('alice');

  beforeAll(async () => {
    testApp = await createTestApp();
    app = testApp.app;
    prisma = app.get(PrismaService);

    // Estado limpio en la BD de pruebas (los tests son autoritativos).
    await prisma.authEvent.deleteMany({});
    await prisma.refreshToken.deleteMany({});
    await prisma.user.deleteMany({ where: { email: { contains: 'test.local' } } });
  });

  afterAll(async () => {
    await prisma.user.deleteMany({ where: { email: { contains: 'test.local' } } });
    await testApp.close();
  });

  describe('POST /auth/register', () => {
    it('crea un usuario con contraseña fuerte y no expone el hash', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/register')
        .send({ email, password: STRONG_PASSWORD })
        .expect(201);

      expect(res.body).toEqual({
        id: expect.any(String),
        email,
      });
      expect(JSON.stringify(res.body)).not.toContain('password');

      const stored = await prisma.user.findUnique({ where: { email } });
      expect(stored?.passwordHash).toMatch(/^\$argon2id\$/);
      expect(stored?.passwordHash).not.toContain(STRONG_PASSWORD);
    });

    it('rechaza contraseñas débiles (regla de complejidad)', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/register')
        .send({ email: randomEmail('weak'), password: 'password123' })
        .expect(400);

      expect(JSON.stringify(res.body)).toContain('mayúsculas');
    });

    it('rechaza contraseñas predecibles aunque cumplan la complejidad', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/register')
        .send({ email: randomEmail('common'), password: 'Password1!2026' })
        .expect(400);

      expect(JSON.stringify(res.body)).toContain('débil');
    });

    it('no admite campos extra (whitelist estricta)', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/register')
        .send({
          email: randomEmail('extra'),
          password: STRONG_PASSWORD,
          isAdmin: true,
        })
        .expect(400);

      expect(JSON.stringify(res.body)).toContain('isAdmin');
    });

    it('rechaza emails inválidos', async () => {
      await request(app.getHttpServer())
        .post('/auth/register')
        .send({ email: 'not-an-email', password: STRONG_PASSWORD })
        .expect(400);
    });

    it('no revela si el email ya está registrado (respuesta genérica)', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/register')
        .send({ email, password: STRONG_PASSWORD })
        .expect(409);

      expect(res.body.message).toBe('No se pudo completar el registro');
      expect(JSON.stringify(res.body)).not.toContain('existe');
      expect(JSON.stringify(res.body)).not.toContain('registrado');
    });
  });

  describe('POST /auth/login', () => {
    it('devuelve access token y cookie HttpOnly en login correcto', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/login')
        .send({ email, password: STRONG_PASSWORD })
        .expect(200);

      expect(res.body.accessToken).toEqual(expect.any(String));
      expect(res.body.expiresIn).toBe(900);
      expect(res.body.user).toEqual({ id: expect.any(String), email });
      expect(res.body.refreshToken).toBeUndefined();

      const cookie = res.headers['set-cookie'];
      expect(cookie).toBeDefined();
      const refresh = (Array.isArray(cookie) ? cookie : [cookie]).find((c) =>
        c.startsWith('refresh_token='),
      );
      expect(refresh).toBeDefined();
      expect(refresh).toContain('HttpOnly');
      expect(refresh).toContain('SameSite=Strict');
      expect(refresh).toContain('Path=/auth/refresh');
    });

    it('respuesta idéntica para contraseña incorrecta y usuario inexistente', async () => {
      const wrongPassword = await request(app.getHttpServer())
        .post('/auth/login')
        .send({ email, password: 'N0n-Ex1ste!9999' })
        .expect(401);

      const unknownUser = await request(app.getHttpServer())
        .post('/auth/login')
        .send({ email: randomEmail('ghost'), password: 'N0n-Ex1ste!9999' })
        .expect(401);

      expect(wrongPassword.body).toEqual(unknownUser.body);
      expect(wrongPassword.body.message).toBe('Credenciales inválidas');
    });

    it('bloquea la cuenta tras 5 fallos y responde genérico', async () => {
      const victim = randomEmail('lockout');
      await request(app.getHttpServer())
        .post('/auth/register')
        .send({ email: victim, password: STRONG_PASSWORD })
        .expect(201);

      for (let i = 0; i < 5; i++) {
        await request(app.getHttpServer())
          .post('/auth/login')
          .send({ email: victim, password: 'Intento-Err0neo!1' })
          .expect(401);
      }

      // Incluso con la contraseña correcta la cuenta sigue bloqueada,
      // y la respuesta NO confirma que la cuenta exista ni que esté bloqueada.
      const res = await request(app.getHttpServer())
        .post('/auth/login')
        .send({ email: victim, password: STRONG_PASSWORD })
        .expect(401);

      expect(res.body.message).toBe('Credenciales inválidas');

      const user = await prisma.user.findUnique({ where: { email: victim } });
      expect(user?.failedAttempts).toBeGreaterThanOrEqual(5);
      expect(user?.lockedUntil).not.toBeNull();

      const blocked = await prisma.authEvent.findFirst({
        where: { type: 'LOGIN_BLOCKED' },
        orderBy: { createdAt: 'desc' },
      });
      expect(blocked).not.toBeNull();
    });

    it('registra los eventos de autenticación en la auditoría', async () => {
      const events = await prisma.authEvent.findMany({
        where: { type: { in: ['REGISTER_OK', 'LOGIN_OK', 'LOGIN_FAIL'] } },
      });
      expect(events.length).toBeGreaterThan(0);

      // Nunca debe quedar una contraseña o token en la auditoría.
      expect(JSON.stringify(events)).not.toContain(STRONG_PASSWORD);
      expect(JSON.stringify(events)).not.toContain('refresh_token=');
    });
  });

  describe('Rutas protegidas', () => {
    let accessToken: string;

    beforeAll(async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/login')
        .send({ email, password: STRONG_PASSWORD })
        .expect(200);
      accessToken = res.body.accessToken as string;
    });

    it('GET /users/me con token válido', async () => {
      const res = await request(app.getHttpServer())
        .get('/users/me')
        .set('Authorization', `Bearer ${accessToken}`)
        .expect(200);

      expect(res.body).toEqual({
        id: expect.any(String),
        email,
        createdAt: expect.any(String),
      });
      expect(JSON.stringify(res.body)).not.toContain('passwordHash');
    });

    it('rechaza peticiones sin token', async () => {
      await request(app.getHttpServer()).get('/users/me').expect(401);
    });

    it('rechaza token con firma manipulada', async () => {
      const [header, payload] = accessToken.split('.');
      const forged = `${header}.${payload}.c2lnbmF0dXJlLWZhbHNh`;
      await request(app.getHttpServer())
        .get('/users/me')
        .set('Authorization', `Bearer ${forged}`)
        .expect(401);
    });

    it('rechaza JWT con algoritmo "none" (confusión de algoritmo)', async () => {
      const b64 = (o: object) =>
        Buffer.from(JSON.stringify(o)).toString('base64url');
      const unsigned = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({
        sub: 'alg-none-attack',
        type: 'access',
      })}.`;

      await request(app.getHttpServer())
        .get('/users/me')
        .set('Authorization', `Bearer ${unsigned}`)
        .expect(401);
    });

    it('rechaza un access token expirado', async () => {
      const signer = new JwtService({});
      const expired = await signer.signAsync(
        { sub: 'expired-user', type: 'access' },
        {
          secret: process.env['JWT_ACCESS_SECRET']!,
          algorithm: 'HS256',
          expiresIn: -60,
        },
      );

      await request(app.getHttpServer())
        .get('/users/me')
        .set('Authorization', `Bearer ${expired}`)
        .expect(401);
    });

    it('rechaza un refresh token usado como access token', async () => {
      const login = await request(app.getHttpServer())
        .post('/auth/login')
        .send({ email, password: STRONG_PASSWORD })
        .expect(200);
      const refreshCookie = extractRefreshCookie(login);

      await request(app.getHttpServer())
        .get('/users/me')
        .set('Authorization', `Bearer ${refreshCookie}`)
        .expect(401);
    });
  });

  describe('POST /auth/refresh', () => {
    it('rota el refresh token y emite un nuevo access token', async () => {
      const login = await request(app.getHttpServer())
        .post('/auth/login')
        .send({ email, password: STRONG_PASSWORD })
        .expect(200);
      const cookie1 = extractRefreshCookie(login);

      const refreshed = await request(app.getHttpServer())
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${cookie1}`)
        .expect(200);

      expect(refreshed.body.accessToken).toEqual(expect.any(String));
      const cookie2 = extractRefreshCookie(refreshed);
      expect(cookie2).not.toBe(cookie1);

      // El token rotado sigue siendo válido.
      await request(app.getHttpServer())
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${cookie2}`)
        .expect(200);
    });

    it('detecta reutilización de un token rotado y revoca la familia', async () => {
      const login = await request(app.getHttpServer())
        .post('/auth/login')
        .send({ email, password: STRONG_PASSWORD })
        .expect(200);
      const cookie1 = extractRefreshCookie(login);

      const first = await request(app.getHttpServer())
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${cookie1}`)
        .expect(200);
      const cookie2 = extractRefreshCookie(first);

      // Reutilizar el token ya canjeado => reuso detectado.
      const reuse = await request(app.getHttpServer())
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${cookie1}`)
        .expect(401);
      expect(reuse.body.message).toBe('Sesión revocada');

      // Toda la familia queda invalidada (incluida la cookie vigente).
      await request(app.getHttpServer())
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${cookie2}`)
        .expect(401);

      const reuseEvent = await prisma.authEvent.findFirst({
        where: { type: 'REUSE_DETECTED' },
      });
      expect(reuseEvent).not.toBeNull();

      const familyId = (reuseEvent!.meta as { familyId?: string } | null)
        ?.familyId;
      expect(familyId).toBeTruthy();

      const active = await prisma.refreshToken.count({
        where: { familyId: familyId!, revokedAt: null },
      });
      expect(active).toBe(0);
    });

    it('rechaza refresh sin cookie', async () => {
      const res = await request(app.getHttpServer())
        .post('/auth/refresh')
        .expect(401);
      expect(res.body.message).toBe('Sesión inválida o expirada');
    });

    it('rechaza refresh con cookie inexistente', async () => {
      await request(app.getHttpServer())
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${'a'.repeat(64)}`)
        .expect(401);
    });

    it('rechaza refresh con Origin no permitido (CSRF)', async () => {
      await request(app.getHttpServer())
        .post('/auth/refresh')
        .set('Origin', 'https://evil.example')
        .set('Cookie', 'refresh_token=abc')
        .expect(403);
    });
  });

  describe('POST /auth/logout', () => {
    it('revoca el refresh token y limpia la cookie', async () => {
      const login = await request(app.getHttpServer())
        .post('/auth/login')
        .send({ email, password: STRONG_PASSWORD })
        .expect(200);
      const cookie = extractRefreshCookie(login);

      const logout = await request(app.getHttpServer())
        .post('/auth/logout')
        .set('Cookie', `refresh_token=${cookie}`)
        .expect(200);

      expect(
        (Array.isArray(logout.headers['set-cookie'])
          ? logout.headers['set-cookie']
          : [logout.headers['set-cookie']])
          .join(';'),
      ).toContain('refresh_token=;');

      await request(app.getHttpServer())
        .post('/auth/refresh')
        .set('Cookie', `refresh_token=${cookie}`)
        .expect(401);
    });
  });
});
