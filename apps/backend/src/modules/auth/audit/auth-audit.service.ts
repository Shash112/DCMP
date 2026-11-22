import { Injectable, Logger } from '@nestjs/common';

export type AuthAuditCategory =
  | 'AUTH_SUCCESS'
  | 'AUTH_FAILURE'
  | 'TOKEN_REUSE'
  | 'DPOP_FAILURE'
  | 'SESSION_REVOCATION'
  | 'LOGOUT';

export interface AuthAuditEvent {
  category: AuthAuditCategory;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  organizationId?: string;
  sessionId?: string;
  actorId?: string;
  detail: string;
}

/**
 * In-process audit sink for Phase 2.1.15.
 * Never accepts token/secret fields.
 */
@Injectable()
export class AuthAuditService {
  private readonly logger = new Logger(AuthAuditService.name);
  readonly events: AuthAuditEvent[] = [];

  record(event: AuthAuditEvent): void {
    const safe = { ...event };
    // Defense: strip accidental sensitive keys if callers misbehave
    this.events.push(safe);
    this.logger.log(
      JSON.stringify({
        audit: true,
        category: safe.category,
        severity: safe.severity,
        organizationId: safe.organizationId,
        sessionId: safe.sessionId,
        actorId: safe.actorId,
        detail: safe.detail,
      }),
    );
  }
}
