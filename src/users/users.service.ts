import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service.js';

@Injectable()
export class UsersService {
  constructor(private readonly prisma: PrismaService) {}

  async findProfile(id: string): Promise<{
    id: string;
    email: string;
    createdAt: Date;
  }> {
    const user = await this.prisma.user.findUnique({
      where: { id },
      // Nunca se selecciona passwordHash: los secretos no salen de la BD.
      select: { id: true, email: true, createdAt: true },
    });
    if (!user) {
      throw new NotFoundException('Usuario no encontrado');
    }
    return user;
  }
}
