import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { HTTP_HEADERS } from '@dcmp/api-contracts';

/**
 * Untrusted client claims only.
 * Phase 2.1.16: X-Organization-Id / X-Tenant-Slug MUST NOT authorize.
 * Verified organization context is attached by AuthService from DB-backed
 * session/token lookups (see VerifiedAuthContext on request after auth).
 */
export interface TenantClaimAnnotation {
  /** Client-asserted organization id — never use for authorization */
  claimedOrganizationId?: string;
  claimedTenantSlug?: string;
  subdomain?: string;
}

export interface VerifiedAuthContext {
  organizationId: string;
  userId: string;
  sessionId?: string;
  source: 'session' | 'access_token' | 'login';
}

export interface TenantRequest extends Request {
  /** @deprecated use tenantClaim — kept for transitional typing */
  tenant?: {
    organizationId: string;
    tenantSlug: string;
    subdomain?: string;
  };
  tenantClaim?: TenantClaimAnnotation;
  verifiedAuth?: VerifiedAuthContext;
}

@Injectable()
export class TenantMiddleware implements NestMiddleware {
  use(req: TenantRequest, _res: Response, next: NextFunction): void {
    const slugHeader = req.headers[HTTP_HEADERS.TENANT_SLUG] as string | undefined;
    const orgIdHeader = req.headers[HTTP_HEADERS.ORGANIZATION_ID] as string | undefined;

    const host = req.headers.host || '';
    const parts = host.split('.');
    let subdomain: string | undefined;
    if (parts.length > 2 && !['localhost', '127'].includes(parts[0])) {
      subdomain = parts[0];
    }

    if (slugHeader || orgIdHeader || subdomain) {
      req.tenantClaim = {
        claimedOrganizationId: orgIdHeader || undefined,
        claimedTenantSlug: slugHeader || subdomain || undefined,
        subdomain,
      };
      // Transitional: do NOT populate req.tenant.organizationId from client header.
      // Leave req.tenant undefined so callers cannot accidentally authorize from it.
    }

    next();
  }
}
