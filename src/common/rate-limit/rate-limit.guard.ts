import {
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Reflector } from '@nestjs/core';
import type { Request, Response } from 'express';
import { RATE_LIMIT_KEY_METADATA } from '../decorators/rate-limit-key.decorator.js';
import { RateLimitStore } from './rate-limit.store.js';

interface RateLimitRule {
  limit: number;
  windowMs: number;
}

/**
 * Límite de tasa por IP y por identificador (email) para rutas de
 * autenticación - NIST CSF PR.AA-03 / DE.CM.
 *
 * Ventana deslizante; claves configurables vía entorno
 * RATE_LIMIT_<KEY>_ATTEMPTS y RATE_LIMIT_<KEY>_WINDOW_SECONDS.
 */
@Injectable()
export class RateLimitGuard implements CanActivate {
  constructor(
    private readonly config: ConfigService,
    private readonly store: RateLimitStore,
    private readonly reflector: Reflector,
  ) {}

  canActivate(context: ExecutionContext): boolean {
    if (this.config.get<string>('RATE_LIMIT_ENABLED') === 'false') {
      return true;
    }

    const key = this.reflector.getAllAndOverride<string | undefined>(
      RATE_LIMIT_KEY_METADATA,
      [context.getHandler(), context.getClass()],
    );
    if (!key) {
      return true;
    }

    const rule = this.rule(key);
    if (!rule) {
      return true;
    }

    const request = context.switchToHttp().getRequest<Request>();
    const response = context.switchToHttp().getResponse<Response>();
    const ip = request.ip ?? 'unknown';
    const identifier = this.identifier(request);

    const keys = [`rl:${key}:ip:${ip}`];
    if (identifier) {
      keys.push(`rl:${key}:id:${identifier}`);
    }

    let retryAfterSeconds = 0;
    for (const storageKey of keys) {
      const result = this.store.hit(storageKey, rule.limit, rule.windowMs);
      if (!result.allowed) {
        retryAfterSeconds = Math.max(retryAfterSeconds, result.retryAfterSeconds);
      }
      response.setHeader('RateLimit-Limit', String(rule.limit));
      response.setHeader('RateLimit-Remaining', String(result.remaining));
      response.setHeader(
        'RateLimit-Reset',
        String(Math.ceil(result.retryAfterSeconds || rule.windowMs / 1000)),
      );
      if (retryAfterSeconds > 0) {
        break;
      }
    }

    if (retryAfterSeconds > 0) {
      response.setHeader('Retry-After', String(retryAfterSeconds));
      throw new HttpException(
        {
          statusCode: HttpStatus.TOO_MANY_REQUESTS,
          message:
            'Demasiadas solicitudes. Espere antes de volver a intentarlo.',
          error: 'Too Many Requests',
        },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    return true;
  }

  private rule(key: string): RateLimitRule | undefined {
    const limit = Number(this.config.get(`RATE_LIMIT_${key}_ATTEMPTS`));
    const windowSeconds = Number(
      this.config.get(`RATE_LIMIT_${key}_WINDOW_SECONDS`),
    );
    if (!Number.isFinite(limit) || !Number.isFinite(windowSeconds)) {
      return undefined;
    }
    return { limit, windowMs: windowSeconds * 1000 };
  }

  private identifier(request: Request): string | undefined {
    const body = request.body as { email?: unknown } | undefined;
    if (body && typeof body.email === 'string') {
      const email = body.email.trim().toLowerCase();
      if (email.length > 0 && email.length <= 254) {
        return email;
      }
    }
    return undefined;
  }
}
