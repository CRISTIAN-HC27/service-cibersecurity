import { Module } from '@nestjs/common';
import { AuditModule } from '../audit/audit.module.js';
import { AuthController } from './auth.controller.js';
import { AuthService } from './auth.service.js';
import { OriginGuard } from './guards/origin.guard.js';
import { PasswordPolicyService } from './password-policy.service.js';
import { SessionService } from './session.service.js';

@Module({
  imports: [AuditModule],
  controllers: [AuthController],
  providers: [
    AuthService,
    SessionService,
    PasswordPolicyService,
    OriginGuard,
  ],
  exports: [SessionService],
})
export class AuthModule {}
