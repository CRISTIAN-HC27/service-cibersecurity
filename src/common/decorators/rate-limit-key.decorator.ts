import { SetMetadata } from '@nestjs/common';

export const RATE_LIMIT_KEY_METADATA = 'rateLimitKey';

/**
 * Etiqueta una ruta con una clave de límite de tasa configurable por entorno
 * (RATE_LIMIT_<KEY>_ATTEMPTS / RATE_LIMIT_<KEY>_WINDOW_SECONDS).
 */
export const RateLimitKey = (key: string) =>
  SetMetadata(RATE_LIMIT_KEY_METADATA, key);
