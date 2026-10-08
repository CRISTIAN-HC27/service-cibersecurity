import { Global, Module } from '@nestjs/common';
import { RateLimitStore } from './rate-limit.store.js';

/**
 * Almacén global de rate limit: una sola instancia por aplicación para que
 * el guard global y los servicios compartan contadores.
 */
@Global()
@Module({
  providers: [RateLimitStore],
  exports: [RateLimitStore],
})
export class RateLimitModule {}
