import { Module } from '@nestjs/common';
import { APP_FILTER, APP_GUARD } from '@nestjs/core';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { LoggerModule } from 'nestjs-pino';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { randomUUID } from 'node:crypto';
import { AuditModule } from './audit/audit.module.js';
import { AdminModule } from './admin/admin.module.js';
import { AuthModule } from './auth/auth.module.js';
import { JwtAuthGuard } from './auth/guards/jwt-auth.guard.js';
import { HttpExceptionFilter } from './common/filters/http-exception.filter.js';
import { RateLimitGuard } from './common/rate-limit/rate-limit.guard.js';
import { RateLimitModule } from './common/rate-limit/rate-limit.module.js';
import { validateEnv } from './config/env.validation.js';
import { HealthModule } from './health/health.module.js';
import { PrismaModule } from './prisma/prisma.module.js';
import { UsersModule } from './users/users.module.js';

@Module({
  imports: [
    // Configuración validada con fallo temprano si falta un secreto (ID.AM).
    ConfigModule.forRoot({
      isGlobal: true,
      validate: validateEnv,
      envFilePath: ['.env'],
    }),

    // Log estructurado JSON con redacción de credenciales (DE.CM / PR.DS).
    LoggerModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        pinoHttp: {
          level: config.get<string>('LOG_LEVEL') ?? 'info',
          genReqId: () => randomUUID(),
          redact: [
            'req.headers.authorization',
            'req.headers.cookie',
            'res.headers["set-cookie"]',
          ],
        },
      }),
    }),

    // Límite de tasa global por IP (primera barrera de fuerza bruta).
    ThrottlerModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        throttlers: [
          {
            name: 'default',
            limit: config.getOrThrow<number>('RATE_LIMIT_GLOBAL_ATTEMPTS'),
            ttl:
              config.getOrThrow<number>('RATE_LIMIT_GLOBAL_WINDOW_SECONDS') *
              1000,
          },
        ],
        errorMessage: 'Demasiadas solicitudes. Intente más tarde.',
      }),
    }),

    // Access tokens: JWT HS256 de vida corta (PR.AA-04).
    JwtModule.registerAsync({
      global: true,
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.getOrThrow<string>('JWT_ACCESS_SECRET'),
        signOptions: {
          algorithm: 'HS256',
          expiresIn: config.getOrThrow<number>('JWT_ACCESS_TTL_SECONDS'),
        },
      }),
    }),

    RateLimitModule,
    PrismaModule,
    AuditModule,
    AuthModule,
    UsersModule,
    AdminModule,
    HealthModule,
  ],
  providers: [
    // Orden de defensa: rate limit global -> rate limit de auth -> JWT.
    { provide: APP_GUARD, useClass: ThrottlerGuard },
    { provide: APP_GUARD, useClass: RateLimitGuard },
    { provide: APP_GUARD, useClass: JwtAuthGuard },
    { provide: APP_FILTER, useClass: HttpExceptionFilter },
  ],
})
export class AppModule {}
