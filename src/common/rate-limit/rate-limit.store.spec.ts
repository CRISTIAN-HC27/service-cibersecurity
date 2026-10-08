import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { RateLimitStore } from './rate-limit.store.js';

describe('RateLimitStore (ventana deslizante)', () => {
  let store: RateLimitStore;

  beforeEach(() => {
    vi.useFakeTimers();
    store = new RateLimitStore();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('permite hasta el límite y bloquea el siguiente intento', () => {
    for (let i = 0; i < 3; i++) {
      const result = store.hit('k', 3, 60_000);
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(2 - i);
    }

    const blocked = store.hit('k', 3, 60_000);
    expect(blocked.allowed).toBe(false);
    expect(blocked.remaining).toBe(0);
    expect(blocked.retryAfterSeconds).toBeGreaterThan(0);
  });

  it('la ventana se desliza: tras expirar vuelve a permitir', () => {
    store.hit('k', 1, 1_000);
    expect(store.hit('k', 1, 1_000).allowed).toBe(false);

    vi.advanceTimersByTime(1_001);
    expect(store.hit('k', 1, 1_000).allowed).toBe(true);
  });

  it('mantiene claves independientes (por IP o por identificador)', () => {
    store.hit('ip:1.1.1.1', 1, 60_000);
    expect(store.hit('ip:1.1.1.1', 1, 60_000).allowed).toBe(false);
    expect(store.hit('ip:2.2.2.2', 1, 60_000).allowed).toBe(true);
    expect(store.hit('id:alguien@x.com', 1, 60_000).allowed).toBe(true);
  });

  it('reset limpia la ventana (login correcto)', () => {
    store.hit('k', 1, 60_000);
    store.reset('k');
    expect(store.hit('k', 1, 60_000).allowed).toBe(true);
  });
});
