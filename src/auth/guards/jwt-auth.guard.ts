import {
  Injectable,
  UnauthorizedException,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import type { Request } from 'express';
import { IS_PUBLIC_METADATA } from '../../common/decorators/public.decorator.js';

interface AccessTokenPayload {
  sub: string;
  type: string;
}

/**
 * Guard global de acceso: toda ruta es privada salvo que esté marcada con
 * @Public() (mínimo privilegio / denegación por defecto - NIST PR.AA-05).
 */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean | undefined>(
      IS_PUBLIC_METADATA,
      [context.getHandler(), context.getClass()],
    );
    if (isPublic) {
      return true;
    }

    const request = context.switchToHttp().getRequest<Request>();
    const header = request.headers.authorization;
    if (typeof header !== 'string') {
      throw new UnauthorizedException('Token de acceso requerido');
    }

    const [scheme, token] = header.split(' ');
    if (scheme !== 'Bearer' || !token || token.length > 4096) {
      throw new UnauthorizedException('Token de acceso inválido');
    }

    try {
      const payload = await this.jwt.verifyAsync<AccessTokenPayload>(token, {
        secret: this.config.getOrThrow<string>('JWT_ACCESS_SECRET'),
        algorithms: ['HS256'],
      });
      if (payload.type !== 'access' || typeof payload.sub !== 'string') {
        throw new Error('payload inválido');
      }
      request.user = { id: payload.sub };
      return true;
    } catch {
      throw new UnauthorizedException('Sesión inválida o expirada');
    }
  }
}
