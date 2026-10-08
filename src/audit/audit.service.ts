import { Injectable, Logger as NestLogger } from '@nestjs/common';
import { Prisma } from '../generated/client/client.js';
import { PrismaService } from '../prisma/prisma.service.js';

export type AuthEventType =
  | 'REGISTER_OK'
  | 'REGISTER_FAIL'
  | 'LOGIN_OK'
  | 'LOGIN_FAIL'
  | 'LOGIN_BLOCKED'
  | 'TOKEN_REFRESH'
  | 'REFRESH_INVALID'
  | 'REUSE_DETECTED'
  | 'LOGOUT'
  | 'RATE_LIMITED'
  | 'ADMIN_VIEW';

export interface AuthEventContext {
  userId?: string;
  ip?: string | null;
  userAgent?: string | null;
  meta?: Prisma.JsonObject;
}

/**
 * Auditoría de eventos de autenticación - NIST CSF DE.CM / DE.AE.
 *
 * Nunca se registran contraseñas, hashes ni tokens: solo metadatos.
 */
@Injectable()
export class AuditService {
  private readonly logger = new NestLogger(AuditService.name);

  constructor(private readonly prisma: PrismaService) {}

  async record(type: AuthEventType, context: AuthEventContext = {}): Promise<void> {
    try {
      await this.prisma.authEvent.create({
        data: {
          type,
          userId: context.userId ?? null,
          ip: context.ip ?? null,
          userAgent: context.userAgent ?? null,
          meta: context.meta ?? undefined,
        },
      });
    } catch (error) {
      // La auditoría no debe tumbar el flujo de autenticación, pero una
      // pérdida de eventos de seguridad debe quedar visible en el log.
      this.logger.error(
        { err: error, type },
        'No se pudo registrar el evento de autenticación',
      );
    }
  }
}
