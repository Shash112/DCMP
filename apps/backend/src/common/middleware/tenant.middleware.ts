import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { HTTP_HEADERS } from '@dcmp/api-contracts';
import { TenantContext } from '@dcmp/shared-types';

export interface TenantRequest extends Request {
  tenant?: TenantContext;
}

@Injectable()
export class TenantMiddleware implements NestMiddleware {
  use(req: TenantRequest, res: Response, next: NextFunction): void {
    const slugHeader = req.headers[HTTP_HEADERS.TENANT_SLUG] as string;
    const orgIdHeader = req.headers[HTTP_HEADERS.ORGANIZATION_ID] as string;

    // Optional subdomain parsing
    const host = req.headers.host || '';
    const parts = host.split('.');
    let subdomain: string | undefined;
    if (parts.length > 2 && !['localhost', '127'].includes(parts[0])) {
      subdomain = parts[0];
    }

    if (slugHeader || orgIdHeader || subdomain) {
      req.tenant = {
        organizationId: orgIdHeader || '00000000-0000-0000-0000-000000000000',
        tenantSlug: slugHeader || subdomain || 'default',
        subdomain,
      };
    }

    next();
  }
}
