import { Injectable } from '@nestjs/common';

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
}

const MAX_KEYS = 50_000;

/**
 * Ventana deslizante en memoria, instanciada por DI (una por aplicación).
 *
 * Alcance: instancia única de la API. Si se escala a varias réplicas, debe
 * sustituirse por almacenamiento compartido (p. ej. ThrottlerStorageRedis)
 * - NIST CSF PR.IR (resiliencia de la infraestructura).
 */
@Injectable()
export class RateLimitStore {
  private readonly windows = new Map<string, number[]>();
  private readonly timer: NodeJS.Timeout;

  constructor() {
    this.timer = setInterval(() => this.pruneAll(), 60_000);
    this.timer.unref();
  }

  hit(key: string, limit: number, windowMs: number): RateLimitResult {
    const now = Date.now();
    const cutoff = now - windowMs;

    let stamps = this.windows.get(key);
    if (!stamps) {
      if (this.windows.size >= MAX_KEYS) {
        this.evictOldest();
      }
      stamps = [];
      this.windows.set(key, stamps);
    }

    let start = 0;
    while (start < stamps.length && stamps[start]! <= cutoff) {
      start += 1;
    }
    if (start > 0) {
      stamps.splice(0, start);
    }

    if (stamps.length >= limit) {
      const retryAfterMs = stamps[0]! + windowMs - now;
      return {
        allowed: false,
        remaining: 0,
        retryAfterSeconds: Math.max(1, Math.ceil(retryAfterMs / 1000)),
      };
    }

    stamps.push(now);
    return {
      allowed: true,
      remaining: limit - stamps.length,
      retryAfterSeconds: 0,
    };
  }

  /** Borra la ventana de una clave (p. ej. tras un login correcto). */
  reset(key: string): void {
    this.windows.delete(key);
  }

  private pruneAll(): void {
    const now = Date.now();
    for (const [key, stamps] of this.windows) {
      const kept = stamps.filter((t) => t > now - 3_600_000);
      if (kept.length === 0) {
        this.windows.delete(key);
      } else {
        this.windows.set(key, kept);
      }
    }
  }

  private evictOldest(): void {
    const oldest = this.windows.keys().next();
    if (!oldest.done) {
      this.windows.delete(oldest.value);
    }
  }
}
