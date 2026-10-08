import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Request } from 'express';
import { PrismaService } from '../../prisma/prisma.service.js';

/**
 * Autorización del panel de administración (PR.AA-05, mínimo privilegio).
 *
 * El rol NO se concede por auto-registro ni viaja en el token: se resuelve
 * contra la lista blanca `ADMIN_EMAILS` en cada petición. Si la lista está
 * vacía, el panel queda deshabilitado por completo (denegación por defecto).
 */
@Injectable()
export class AdminGuard implements CanActivate {
  private readonly admins: Set<string>;

  constructor(
    config: ConfigService,
    private readonly prisma: PrismaService,
  ) {
    const allowed = config.get<string[]>('ADMIN_EMAILS') ?? [];
    this.admins = new Set(allowed);
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const id = request.user?.id;
    if (!id) {
      throw new UnauthorizedException('Token de acceso requerido');
    }

    if (this.admins.size === 0) {
      throw new ForbiddenException('Panel de administración deshabilitado');
    }

    const user = await this.prisma.user.findUnique({
      where: { id },
      select: { email: true },
    });

    if (!user || !this.admins.has(user.email.toLowerCase())) {
      throw new ForbiddenException('Se requiere rol de administrador');
    }

    return true;
  }
}
