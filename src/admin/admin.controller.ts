import { Controller, Get, Query, Req, UseGuards } from '@nestjs/common';
import type { Request } from 'express';
import { AuditService } from '../audit/audit.service.js';
import { requestContext } from '../common/utils/request-context.js';
import { AdminService } from './admin.service.js';
import { AdminGuard } from './guards/admin.guard.js';

/**
 * Panel de administración: solo lectura y protegido por AdminGuard.
 * Cada acceso queda auditado (ADMIN_VIEW) para su trazabilidad (DE.CM / RS).
 */
@Controller('admin')
@UseGuards(AdminGuard)
export class AdminController {
  constructor(
    private readonly adminService: AdminService,
    private readonly audit: AuditService,
  ) {}

  @Get('overview')
  async overview(@Req() req: Request) {
    await this.recordView(req, 'overview');
    return this.adminService.overview();
  }

  @Get('active-users')
  async activeUsers(@Req() req: Request) {
    await this.recordView(req, 'active-users');
    return this.adminService.activeUsers();
  }

  @Get('events')
  async events(
    @Req() req: Request,
    @Query('limit') limit?: string,
    @Query('type') type?: string,
  ) {
    await this.recordView(req, 'events');
    const parsed = Number.parseInt(limit ?? '', 10);
    return this.adminService.events({
      limit: Number.isFinite(parsed) ? parsed : undefined,
      type: type && type.length > 0 && type.length <= 40 ? type : undefined,
    });
  }

  private async recordView(req: Request, resource: string): Promise<void> {
    const context = requestContext(req);
    await this.audit.record('ADMIN_VIEW', {
      userId: req.user?.id,
      ip: context.ip,
      userAgent: context.userAgent,
      meta: { resource },
    });
  }
}
