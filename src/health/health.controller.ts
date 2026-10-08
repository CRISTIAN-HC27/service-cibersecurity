import { Controller, Get } from '@nestjs/common';
import { SkipThrottle } from '@nestjs/throttler';
import { Public } from '../common/decorators/public.decorator.js';
import { PrismaService } from '../prisma/prisma.service.js';

@Controller('health')
@Public()
export class HealthController {
  constructor(private readonly prisma: PrismaService) {}

  /** Liveness: la API responde. */
  @Get()
  @SkipThrottle()
  liveness() {
    return { status: 'ok' };
  }

  /** Readiness: la API puede consultar la base de datos. */
  @Get('ready')
  @SkipThrottle()
  async readiness() {
    await this.prisma.$queryRaw`SELECT 1`;
    return { status: 'ready' };
  }
}
