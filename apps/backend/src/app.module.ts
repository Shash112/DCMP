import { Module, NestModule, MiddlewareConsumer } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { LoggerModule } from 'nestjs-pino';
import configuration from './config/configuration';

// Common Middleware
import { RequestIdMiddleware } from './common/middleware/request-id.middleware';
import { TenantMiddleware } from './common/middleware/tenant.middleware';

// Health Module
import { HealthModule } from './modules/health/health.module';

// Domain Placeholder Modules
import { AuthModule } from './modules/auth/auth.module';
import { OrganizationsModule } from './modules/organizations/organizations.module';
import { UsersModule } from './modules/users/users.module';
import { RolesModule } from './modules/roles/roles.module';
import { LicensingModule } from './modules/licensing/licensing.module';
import { ChecklistsModule } from './modules/checklists/checklists.module';
import { InspectionsModule } from './modules/inspections/inspections.module';
import { AssignmentsModule } from './modules/assignments/assignments.module';
import { EvidenceModule } from './modules/evidence/evidence.module';
import { NotificationsModule } from './modules/notifications/notifications.module';
import { AuditModule } from './modules/audit/audit.module';
import { PlatformAdminModule } from './modules/platform-admin/platform-admin.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
    }),
    LoggerModule.forRoot({
      pinoHttp: {
        level: process.env.NODE_ENV !== 'production' ? 'debug' : 'info',
        transport:
          process.env.NODE_ENV !== 'production'
            ? {
                target: 'pino-pretty',
                options: {
                  colorize: true,
                  singleLine: true,
                },
              }
            : undefined,
        redact: [
          'req.headers.authorization',
          'req.headers["x-device-token"]',
          'body.password',
          'body.refreshToken',
          'body.activationKey',
        ],
      },
    }),
    HealthModule,
    AuthModule,
    OrganizationsModule,
    UsersModule,
    RolesModule,
    LicensingModule,
    ChecklistsModule,
    InspectionsModule,
    AssignmentsModule,
    EvidenceModule,
    NotificationsModule,
    AuditModule,
    PlatformAdminModule,
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(RequestIdMiddleware, TenantMiddleware).forRoutes('*');
  }
}
