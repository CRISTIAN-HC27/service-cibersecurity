import {
  ForbiddenException,
  Injectable,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Request } from 'express';

/**
 * Protección CSRF para rutas que dependen de cookies (refresh/logout).
 *
 * - Rechaza peticiones con Origin presente que no esté en la whitelist.
 * - Rechaza peticiones cross-site declaradas por el navegador
 *   (Sec-Fetch-Site: cross-site).
 * - SameSite=Strict en la cookie ya bloquea el envío cruzado; esta guarda
 *   es la segunda capa (defensa en profundidad - PR.AA-04).
 */
@Injectable()
export class OriginGuard implements CanActivate {
  private readonly allowed: string[];

  constructor(config: ConfigService) {
    this.allowed = config.get<string[]>('CORS_ORIGINS') ?? [];
  }

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<Request>();

    const origin = request.headers.origin;
    if (typeof origin === 'string' && origin.length > 0) {
      if (!this.allowed.includes(origin)) {
        throw new ForbiddenException('Origen no permitido');
      }
    }

    const fetchSite = request.headers['sec-fetch-site'];
    if (typeof fetchSite === 'string' && fetchSite === 'cross-site') {
      throw new ForbiddenException('Petición cross-site rechazada');
    }

    return true;
  }
}
