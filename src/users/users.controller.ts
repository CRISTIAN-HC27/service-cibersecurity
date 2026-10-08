import { Controller, Get, Req, UnauthorizedException } from '@nestjs/common';
import type { Request } from 'express';
import { UsersService } from './users.service.js';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  /** Ruta protegida por el guard global de JWT (denegación por defecto). */
  @Get('me')
  me(@Req() req: Request) {
    const id = req.user?.id;
    if (!id) {
      throw new UnauthorizedException('Token de acceso requerido');
    }
    return this.usersService.findProfile(id);
  }
}
