import { CanActivate, ExecutionContext, Inject, Injectable } from '@nestjs/common';
import { AuthService } from '../auth.service';
import { AuthErrors } from '../errors/auth.errors';
import { HTTP_HEADERS } from '@dcmp/api-contracts';
import type {
  TenantRequest,
  VerifiedAuthContext,
} from '../../../common/middleware/tenant.middleware';

/**
 * Protected-route guard: Authorization: DPoP <AT> + DPoP proof + PG session check.
 */
@Injectable()
export class DpopBoundAuthGuard implements CanActivate {
  constructor(@Inject(AuthService) private readonly auth: AuthService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<TenantRequest>();
    const authorization = header(req, HTTP_HEADERS.AUTHORIZATION);
    const dpop = header(req, HTTP_HEADERS.DPOP);

    if (!authorization?.startsWith('DPoP ')) {
      throw AuthErrors.unauthenticated('Authorization must use DPoP scheme');
    }
    const accessToken = authorization.slice(5).trim();
    if (!accessToken) throw AuthErrors.unauthenticated();

    const verified = await this.auth.authorizeProtectedResource({
      accessToken,
      dpopHeader: dpop,
      method: req.method,
      originalUrl: req.originalUrl || req.url,
      protocol: req.protocol,
      hostHeader: header(req, 'host') || 'localhost',
      forwardedHost: header(req, 'x-forwarded-host'),
      forwardedProto: header(req, 'x-forwarded-proto'),
      publicOrigin: process.env.DCMP_PUBLIC_ORIGIN,
    });

    const ctx: VerifiedAuthContext = {
      organizationId: verified.orgId,
      userId: verified.sub,
      sessionId: verified.sid,
      source: 'access_token',
    };
    req.verifiedAuth = ctx;
    return true;
  }
}

function header(
  req: { headers: Record<string, string | string[] | undefined> },
  name: string,
): string | undefined {
  const v = req.headers[name] ?? req.headers[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : v;
}
