import {
  Body,
  Controller,
  Get,
  Headers,
  HttpCode,
  Inject,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { ApiHeader, ApiOperation, ApiTags } from '@nestjs/swagger';
import { HTTP_HEADERS } from '@dcmp/api-contracts';
import { Response } from 'express';
import { AuthService, RequestBinding } from './auth.service';
import { LoginDto, LogoutDto, RefreshDto, RevokeSessionDto } from './dto/auth.dto';
import { AuthErrors } from './errors/auth.errors';
import { DpopBoundAuthGuard } from './guards/dpop-bound-auth.guard';
import type { TenantRequest } from '../../common/middleware/tenant.middleware';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(@Inject(AuthService) private readonly auth: AuthService) {}

  private binding(req: {
    method: string;
    originalUrl: string;
    protocol: string;
    headers: Record<string, string | string[] | undefined>;
  }): RequestBinding {
    const h = (name: string): string | undefined => {
      const v = req.headers[name];
      return Array.isArray(v) ? v[0] : v;
    };
    return {
      method: req.method,
      originalUrl: req.originalUrl,
      protocol: req.protocol,
      hostHeader: h('host') || 'localhost',
      forwardedHost: h('x-forwarded-host'),
      forwardedProto: h('x-forwarded-proto'),
      dpopHeader: h(HTTP_HEADERS.DPOP),
      publicOrigin: process.env.DCMP_PUBLIC_ORIGIN,
    };
  }

  private setNonce(res: Response, nonce: string): void {
    res.setHeader(HTTP_HEADERS.DPOP_NONCE, nonce);
  }

  @Get('.well-known/jwks.json')
  @ApiOperation({ summary: 'Access-token verification JWKS (public keys only)' })
  async jwks() {
    return this.auth.getJwks();
  }

  @Post('login')
  @HttpCode(200)
  @ApiOperation({ summary: 'Establish session with DPoP-bound refresh + access tokens' })
  @ApiHeader({ name: HTTP_HEADERS.DPOP, required: true })
  async login(
    @Body() body: LoginDto,
    @Req() req: { method: string; originalUrl: string; protocol: string; headers: Record<string, string | string[] | undefined> },
    @Res({ passthrough: true }) res: Response,
  ) {
    try {
      const result = await this.auth.login(body, this.binding(req));
      this.setNonce(res, result.dpopNonce);
      return result.data;
    } catch (e) {
      this.rethrowWithNonce(e, res);
    }
  }

  @Post('refresh')
  @HttpCode(200)
  @ApiOperation({ summary: 'Rotate refresh token under DPoP + PG idempotency' })
  @ApiHeader({ name: HTTP_HEADERS.DPOP, required: true })
  async refresh(
    @Body() body: RefreshDto,
    @Headers(HTTP_HEADERS.ORGANIZATION_ID) orgHeader: string | undefined,
    @Req() req: { method: string; originalUrl: string; protocol: string; headers: Record<string, string | string[] | undefined> },
    @Res({ passthrough: true }) res: Response,
  ) {
    try {
      const result = await this.auth.refresh(body.refreshToken, this.binding(req), orgHeader);
      this.setNonce(res, result.dpopNonce);
      return { tokens: result.tokens };
    } catch (e) {
      this.rethrowWithNonce(e, res);
    }
  }

  @Post('logout')
  @HttpCode(200)
  @ApiOperation({ summary: 'Revoke session and invalidate idempotency recovery' })
  async logout(
    @Body() body: LogoutDto,
    @Req() req: { method: string; originalUrl: string; protocol: string; headers: Record<string, string | string[] | undefined> },
  ) {
    await this.auth.logout(body.refreshToken, this.binding(req));
    return { revoked: true };
  }

  @Get('me')
  @UseGuards(DpopBoundAuthGuard)
  @ApiOperation({ summary: 'Current subject — requires DPoP-bound access token + live session' })
  @ApiHeader({ name: HTTP_HEADERS.AUTHORIZATION, required: true, description: 'DPoP <access_token>' })
  @ApiHeader({ name: HTTP_HEADERS.DPOP, required: true })
  async me(@Req() req: TenantRequest) {
    if (!req.verifiedAuth) throw AuthErrors.unauthenticated();
    return {
      sub: req.verifiedAuth.userId,
      orgId: req.verifiedAuth.organizationId,
      sid: req.verifiedAuth.sessionId,
    };
  }

  @Post('sessions/revoke')
  @HttpCode(200)
  @UseGuards(DpopBoundAuthGuard)
  @ApiOperation({
    summary: 'Revoke a session (requires DPoP-bound access token for that org+session)',
  })
  async revoke(@Body() body: RevokeSessionDto, @Req() req: TenantRequest) {
    const auth = req.verifiedAuth;
    if (!auth) throw AuthErrors.unauthenticated();
    if (auth.organizationId !== body.organizationId || auth.sessionId !== body.sessionId) {
      throw AuthErrors.tenantMismatch();
    }
    await this.auth.revokeSession(body.organizationId, body.sessionId);
    return { revoked: true };
  }

  @Post('sessions/status')
  @HttpCode(200)
  async status(@Body() body: RefreshDto) {
    return this.auth.sessionStatus(body.refreshToken);
  }

  private rethrowWithNonce(e: unknown, res: Response): never {
    if (e && typeof e === 'object' && 'getResponse' in e) {
      const body = (e as { getResponse: () => unknown }).getResponse();
      if (body && typeof body === 'object' && 'dpopNonce' in (body as object)) {
        this.setNonce(res, String((body as { dpopNonce: string }).dpopNonce));
      }
    }
    throw e;
  }
}
