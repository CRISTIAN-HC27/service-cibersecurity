import {
  ConflictException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { randomBytes } from 'node:crypto';
import argon2 from 'argon2';
import { Prisma } from '../generated/client/client.js';
import { AuditService } from '../audit/audit.service.js';
import { RateLimitStore } from '../common/rate-limit/rate-limit.store.js';
import type { RequestContext } from '../common/utils/request-context.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { PasswordPolicyService } from './password-policy.service.js';
import { SessionService, type SessionTokens } from './session.service.js';
import type { LoginDto, RegisterDto } from './dto/auth.dto.js';

// argon2id memory-hard: resiste ataques con GPU/ASIC (NIST PR.AA-03).
const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 65536, // 64 MiB
  timeCost: 3,
  parallelism: 4,
} as const;

export interface AuthResult {
  user: { id: string; email: string };
  session: SessionTokens;
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly maxFailedAttempts: number;
  private readonly lockMs: number;
  /** Hash simulado para igualar el coste cuando el usuario no existe. */
  private readonly simulatedHash: Promise<string> = argon2.hash(
    randomBytes(32).toString('hex'),
    ARGON2_OPTIONS,
  );

  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    private readonly passwordPolicy: PasswordPolicyService,
    private readonly sessions: SessionService,
    private readonly rateLimitStore: RateLimitStore,
    config: ConfigService,
  ) {
    this.maxFailedAttempts = config.getOrThrow<number>(
      'ACCOUNT_MAX_FAILED_ATTEMPTS',
    );
    this.lockMs =
      config.getOrThrow<number>('ACCOUNT_LOCK_MINUTES') * 60 * 1000;
  }

  async register(dto: RegisterDto, context: RequestContext): Promise<{ id: string; email: string }> {
    this.passwordPolicy.assert(dto.password, dto.email);

    // Coste de hashing uniforme exista o no la cuenta: evita enumerar
    // usuarios por tiempo de respuesta (ID.RA / PR.AA-03).
    const passwordHash = await argon2.hash(dto.password, ARGON2_OPTIONS);

    const existing = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    if (existing) {
      await this.audit.record('REGISTER_FAIL', {
        ip: context.ip,
        userAgent: context.userAgent,
        meta: { reason: 'email_taken' },
      });
      throw new ConflictException('No se pudo completar el registro');
    }

    let user: { id: string; email: string };
    try {
      user = await this.prisma.user.create({
        data: { email: dto.email, passwordHash },
        select: { id: true, email: true },
      });
    } catch (error) {
      // Carrera contra un registro simultáneo del mismo email (P2002).
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        await this.audit.record('REGISTER_FAIL', {
          ip: context.ip,
          userAgent: context.userAgent,
          meta: { reason: 'email_taken' },
        });
        throw new ConflictException('No se pudo completar el registro');
      }
      this.logger.error({ err: error }, 'Error inesperado en registro');
      throw error;
    }

    await this.audit.record('REGISTER_OK', {
      userId: user.id,
      ip: context.ip,
      userAgent: context.userAgent,
    });

    return user;
  }

  async login(dto: LoginDto, context: RequestContext): Promise<AuthResult> {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    let locked = false;
    if (user?.lockedUntil) {
      if (user.lockedUntil.getTime() > Date.now()) {
        locked = true;
      } else {
        // Reintento tras el bloqueo: reset perezoso del contador.
        await this.prisma.user.update({
          where: { id: user.id },
          data: { failedAttempts: 0, lockedUntil: null },
        });
        user.failedAttempts = 0;
        user.lockedUntil = null;
      }
    }

    // Verificación siempre con un hash (real o simulado): timing uniforme
    // entre usuario inexistente y contraseña incorrecta.
    const hashToVerify = user?.passwordHash ?? (await this.simulatedHash);
    const valid = await argon2.verify(hashToVerify, dto.password).catch(() => false);

    if (locked && user) {
      await this.audit.record('LOGIN_BLOCKED', {
        userId: user.id,
        ip: context.ip,
        userAgent: context.userAgent,
        meta: { reason: 'account_locked' },
      });
      // Respuesta genérica: no revela que la cuenta existe ni que está bloqueada.
      throw new UnauthorizedException('Credenciales inválidas');
    }

    if (!user || !valid) {
      if (user) {
        const failed = user.failedAttempts + 1;
        const shouldLock = failed >= this.maxFailedAttempts;
        await this.prisma.user.update({
          where: { id: user.id },
          data: {
            failedAttempts: failed,
            lockedUntil: shouldLock
              ? new Date(Date.now() + this.lockMs)
              : null,
          },
        });
        await this.audit.record(shouldLock ? 'LOGIN_BLOCKED' : 'LOGIN_FAIL', {
          userId: user.id,
          ip: context.ip,
          userAgent: context.userAgent,
          meta: shouldLock
            ? { reason: 'max_failed_attempts' }
            : { reason: 'bad_password', failedAttempts: failed },
        });
      } else {
        await this.audit.record('LOGIN_FAIL', {
          ip: context.ip,
          userAgent: context.userAgent,
          meta: { reason: 'unknown_user' },
        });
      }
      throw new UnauthorizedException('Credenciales inválidas');
    }

    if (user.failedAttempts > 0 || user.lockedUntil) {
      await this.prisma.user.update({
        where: { id: user.id },
        data: { failedAttempts: 0, lockedUntil: null },
      });
    }

    // Un login correcto limpia la ventana de rate limit del usuario legítimo.
    this.rateLimitStore.reset(`rl:LOGIN:id:${dto.email}`);
    if (context.ip) {
      this.rateLimitStore.reset(`rl:LOGIN:ip:${context.ip}`);
    }

    const session = await this.sessions.createSession(user.id);

    await this.audit.record('LOGIN_OK', {
      userId: user.id,
      ip: context.ip,
      userAgent: context.userAgent,
      meta: { familyId: session.familyId },
    });

    return {
      user: { id: user.id, email: user.email },
      session,
    };
  }
}
