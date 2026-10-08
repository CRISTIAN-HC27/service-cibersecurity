import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service.js';

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;

export interface ActiveUser {
  id: string;
  email: string;
  sessions: number;
  lastSessionAt: Date | null;
  createdAt: Date;
  locked: boolean;
}

/**
 * Consultas de solo lectura para el panel de administración (DE.CM / DE.AE).
 *
 * No expone secretos: nunca devuelve contraseñas, hashes ni tokens.
 */
@Injectable()
export class AdminService {
  constructor(private readonly prisma: PrismaService) {}

  /** Métricas agregadas para la cabecera del panel. */
  async overview(): Promise<{
    generatedAt: string;
    totalUsers: number;
    activeUsers: number;
    lockedAccounts: number;
    eventsLast24h: Record<string, number>;
  }> {
    const now = new Date();
    const since = new Date(now.getTime() - 24 * 60 * 60 * 1000);

    const [totalUsers, lockedAccounts, activeGroups, byType] = await Promise.all(
      [
        this.prisma.user.count(),
        this.prisma.user.count({ where: { lockedUntil: { gt: now } } }),
        this.activeGroups(),
        this.prisma.authEvent.groupBy({
          by: ['type'],
          where: { createdAt: { gte: since } },
          _count: { _all: true },
        }),
      ],
    );

    const eventsLast24h: Record<string, number> = {};
    for (const row of byType) {
      eventsLast24h[row.type] = row._count._all;
    }

    return {
      generatedAt: now.toISOString(),
      totalUsers,
      activeUsers: activeGroups.length,
      lockedAccounts,
      eventsLast24h,
    };
  }

  /** Usuarios con al menos una sesión de refresh vigente (no revocada/expirada). */
  async activeUsers(): Promise<ActiveUser[]> {
    const groups = await this.activeGroups();
    const ids = groups.map((group) => group.userId);
    if (ids.length === 0) {
      return [];
    }

    const users = await this.prisma.user.findMany({
      where: { id: { in: ids } },
      select: {
        id: true,
        email: true,
        createdAt: true,
        lockedUntil: true,
      },
    });
    const byId = new Map(users.map((user) => [user.id, user]));
    const now = new Date();

    return groups
      .flatMap((group) => {
        const user = byId.get(group.userId);
        if (!user) {
          return [];
        }
        return [
          {
            id: user.id,
            email: user.email,
            sessions: group._count._all,
            lastSessionAt: group._max.createdAt,
            createdAt: user.createdAt,
            locked: Boolean(user.lockedUntil && user.lockedUntil > now),
          },
        ];
      })
      .sort(
        (a, b) =>
          (b.lastSessionAt?.getTime() ?? 0) -
          (a.lastSessionAt?.getTime() ?? 0),
      );
  }

  /** Últimos eventos de autenticación (logs de seguridad). */
  async events(options: { limit?: number; type?: string }): Promise<
    Array<{
      id: string;
      type: string;
      userId: string | null;
      email: string | null;
      ip: string | null;
      userAgent: string | null;
      meta: unknown;
      createdAt: Date;
    }>
  > {
    const limit = clamp(options.limit ?? DEFAULT_LIMIT, 1, MAX_LIMIT);
    const rows = await this.prisma.authEvent.findMany({
      where: options.type ? { type: options.type } : undefined,
      orderBy: { createdAt: 'desc' },
      take: limit,
      include: { user: { select: { email: true } } },
    });

    return rows.map((row) => ({
      id: row.id,
      type: row.type,
      userId: row.userId,
      email: row.user?.email ?? null,
      ip: row.ip,
      userAgent: row.userAgent,
      meta: row.meta,
      createdAt: row.createdAt,
    }));
  }

  private activeGroups() {
    return this.prisma.refreshToken.groupBy({
      by: ['userId'],
      where: { revokedAt: null, expiresAt: { gt: new Date() } },
      _count: { _all: true },
      _max: { createdAt: true },
    });
  }
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}
