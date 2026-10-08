import { Module } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module.js';
import { AdminController } from './admin.controller.js';
import { AdminService } from './admin.service.js';
import { AdminGuard } from './guards/admin.guard.js';

@Module({
  imports: [AuditModule],
  controllers: [AdminController],
  providers: [AdminService, AdminGuard],
})
export class AdminModule {}
