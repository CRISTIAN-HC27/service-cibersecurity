import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import type { Response } from 'express';
import { AuditService } from '../audit/audit.service.js';
import type { RequestContext } from '../common/utils/request-context.js';
import { PrismaService } from '../prisma/prisma.service.js';

export const REFRESH_COOKIE = 'refresh_token';

export interface SessionTokens {
  accessToken: string;
  expiresIn: number;
  refreshToken: string;
  refreshExpiresAt: Date;
  familyId: string;
}

/**
 * Sesiones con refresh token opaco + rotación y detección de reutilización.
 *
 * - El refresh token se guarda SOLO como hash SHA-256 (PR.DS): si la BD se
 *   filtra, los tokens robados no son utilizables.
 * - Cada uso rota el token; si un token ya revocado vuelve a usarse, se
 *   revoca la familia entera (robo de refresh token detectado - RS.MI).
 * - El access token es un JWT de vida corta firmado HS256 (PR.AA-04).
 */
@Injectable()
export class SessionService {
  private readonly accessTtl: number;
  private readonly refreshTtl: number;
  private readonly cookieSecure: boolean;
  private readonly jwtSecret: string;

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly audit: AuditService,
    config: ConfigService,
  ) {
    this.accessTtl = config.getOrThrow<number>('JWT_ACCESS_TTL_SECONDS');
    this.refreshTtl = config.getOrThrow<number>('JWT_REFRESH_TTL_SECONDS');
    this.cookieSecure = config.get<string>('COOKIE_SECURE') !== 'false';
    this.jwtSecret = config.getOrThrow<string>('JWT_ACCESS_SECRET');
  }

  private hashToken(raw: string): string {
    return createHash('sha256').update(raw).digest('hex');
  }

  private async signAccessToken(userId: string): Promise<string> {
    return this.jwt.signAsync(
      { sub: userId, type: 'access' },
      { secret: this.jwtSecret, algorithm: 'HS256', expiresIn: this.accessTtl },
    );
  }

  private newRefreshToken(): { raw: string; hash: string } {
    const raw = randomBytes(48).toString('base64url');
    return { raw, hash: this.hashToken(raw) };
  }

  async createSession(
    userId: string,
    familyId?: string,
  ): Promise<SessionTokens> {
    const family = familyId ?? randomUUID();
    const { raw, hash } = this.newRefreshToken();
    const refreshExpiresAt = new Date(Date.now() + this.refreshTtl * 1000);

    await this.prisma.refreshToken.create({
      data: {
        tokenHash: hash,
        userId,
        familyId: family,
        expiresAt: refreshExpiresAt,
      },
    });

    return {
      accessToken: await this.signAccessToken(userId),
      expiresIn: this.accessTtl,
      refreshToken: raw,
      refreshExpiresAt,
      familyId: family,
    };
  }

  /**
   * Rota el refresh token presentado.
   *
   * Reutilización de un token revocado => se revoca toda la familia
   * (respuesta automatizada a incidente - NIST RS.MI).
   */
  async rotate(
    rawToken: string,
    context?: RequestContext,
  ): Promise<SessionTokens> {
    const now = new Date();
    const tokenHash = this.hashToken(rawToken);

    // Reclamo atómico (CAS): solo una petición puede consumir el token.
    const claimed = await this.prisma.refreshToken.updateMany({
      where: { tokenHash, revokedAt: null, expiresAt: { gt: now } },
      data: { revokedAt: now },
    });

    if (claimed.count === 0) {
      const existing = await this.prisma.refreshToken.findUnique({
        where: { tokenHash },
      });

      if (existing?.revokedAt) {
        // REUSE_DETECTED: el token ya se había canjeado. Alguien lo robó
        // (o una doble petición): se invalida toda la cadena de sesión.
        await this.prisma.refreshToken.updateMany({
          where: { familyId: existing.familyId, revokedAt: null },
          data: { revokedAt: new Date() },
        });
        await this.audit.record('REUSE_DETECTED', {
          userId: existing.userId,
          ip: context?.ip ?? null,
          userAgent: context?.userAgent ?? null,
          meta: { familyId: existing.familyId },
        });
        throw new UnauthorizedException('Sesión revocada');
      }

      await this.audit.record('REFRESH_INVALID', {
        ip: context?.ip ?? null,
        userAgent: context?.userAgent ?? null,
        meta: { reason: existing ? 'expired' : 'unknown_token' },
      });
      throw new UnauthorizedException('Sesión inválida o expirada');
    }

    const consumed = await this.prisma.refreshToken.findUniqueOrThrow({
      where: { tokenHash },
    });

    await this.audit.record('TOKEN_REFRESH', {
      userId: consumed.userId,
      ip: context?.ip ?? null,
      userAgent: context?.userAgent ?? null,
      meta: { familyId: consumed.familyId },
    });

    const { raw, hash } = this.newRefreshToken();
    const refreshExpiresAt = new Date(Date.now() + this.refreshTtl * 1000);

    const created = await this.prisma.refreshToken.create({
      data: {
        tokenHash: hash,
        userId: consumed.userId,
        familyId: consumed.familyId,
        expiresAt: refreshExpiresAt,
      },
    });

    await this.prisma.refreshToken.update({
      where: { id: consumed.id },
      data: { replacedBy: created.id },
    });

    return {
      accessToken: await this.signAccessToken(consumed.userId),
      expiresIn: this.accessTtl,
      refreshToken: raw,
      refreshExpiresAt,
      familyId: consumed.familyId,
    };
  }

  async revoke(rawToken: string, context?: RequestContext): Promise<void> {
    const tokenHash = this.hashToken(rawToken);
    const revoked = await this.prisma.refreshToken.updateMany({
      where: { tokenHash, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    if (revoked.count > 0) {
      const token = await this.prisma.refreshToken.findUnique({
        where: { tokenHash },
      });
      await this.audit.record('LOGOUT', {
        userId: token?.userId,
        ip: context?.ip ?? null,
        userAgent: context?.userAgent ?? null,
        meta: { familyId: token?.familyId },
      });
    }
  }

  setRefreshCookie(response: Response, session: SessionTokens): void {
    response.cookie(REFRESH_COOKIE, session.refreshToken, {
      httpOnly: true,
      secure: this.cookieSecure,
      sameSite: 'strict',
      path: '/auth/refresh',
      maxAge: this.refreshTtl * 1000,
      expires: session.refreshExpiresAt,
    });
  }

  clearRefreshCookie(response: Response): void {
    response.clearCookie(REFRESH_COOKIE, {
      httpOnly: true,
      secure: this.cookieSecure,
      sameSite: 'strict',
      path: '/auth/refresh',
    });
  }
}
