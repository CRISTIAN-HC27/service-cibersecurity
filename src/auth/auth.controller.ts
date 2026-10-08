import {
  Body,
  Controller,
  HttpCode,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { RateLimitKey } from '../common/decorators/rate-limit-key.decorator.js';
import { Public } from '../common/decorators/public.decorator.js';
import { requestContext } from '../common/utils/request-context.js';
import { AuthService } from './auth.service.js';
import { LoginDto, RegisterDto } from './dto/auth.dto.js';
import { OriginGuard } from './guards/origin.guard.js';
import { REFRESH_COOKIE, SessionService } from './session.service.js';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly sessionService: SessionService,
  ) {}

  @Public()
  @RateLimitKey('REGISTER')
  @Post('register')
  register(@Body() dto: RegisterDto, @Req() req: Request) {
    return this.authService.register(dto, requestContext(req));
  }

  @Public()
  @RateLimitKey('LOGIN')
  @HttpCode(200)
  @Post('login')
  async login(
    @Body() dto: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { user, session } = await this.authService.login(
      dto,
      requestContext(req),
    );
    this.sessionService.setRefreshCookie(res, session);
    return {
      accessToken: session.accessToken,
      expiresIn: session.expiresIn,
      user,
    };
  }

  @Public()
  @RateLimitKey('REFRESH')
  @UseGuards(OriginGuard)
  @HttpCode(200)
  @Post('refresh')
  async refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const cookies = (req.cookies ?? {}) as Record<string, string | undefined>;
    const raw = cookies[REFRESH_COOKIE];
    if (!raw) {
      // Se responde igual que un refresh inválido: no se filtra información.
      res.clearCookie(REFRESH_COOKIE, { path: '/auth/refresh' });
      throw new UnauthorizedException('Sesión inválida o expirada');
    }

    const session = await this.sessionService.rotate(raw, requestContext(req));
    this.sessionService.setRefreshCookie(res, session);
    return {
      accessToken: session.accessToken,
      expiresIn: session.expiresIn,
    };
  }

  @Public()
  @RateLimitKey('REFRESH')
  @UseGuards(OriginGuard)
  @HttpCode(200)
  @Post('logout')
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const cookies = (req.cookies ?? {}) as Record<string, string | undefined>;
    const raw = cookies[REFRESH_COOKIE];
    if (raw) {
      await this.sessionService.revoke(raw, requestContext(req));
    }
    this.sessionService.clearRefreshCookie(res);
    return { ok: true };
  }
}
