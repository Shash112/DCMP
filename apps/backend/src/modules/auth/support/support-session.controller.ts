import { Body, Controller, HttpCode, Inject, Post } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { IsOptional, IsString, IsUUID, IsInt, Min, Max } from 'class-validator';
import { SupportSessionService } from './support-session.service';

class CreateSupportRequestDto {
  @IsUUID()
  organizationId!: string;

  @IsUUID()
  adminId!: string;

  @IsOptional()
  @IsUUID()
  ticketId?: string;
}

class ApproveSupportRequestDto {
  @IsUUID()
  requestId!: string;

  @IsUUID()
  organizationId!: string;

  @IsUUID()
  approvedByUserId!: string;

  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(60)
  ttlMinutes?: number;
}

class IssueChallengeDto {
  @IsUUID()
  organizationId!: string;

  @IsUUID()
  grantId!: string;

  @IsUUID()
  adminId!: string;
}

class MintAssertionDto {
  @IsUUID()
  adminId!: string;

  @IsUUID()
  organizationId!: string;

  @IsUUID()
  grantId!: string;

  @IsUUID()
  requestId!: string;
}

class OpenSupportSessionDto {
  @IsString()
  assertion!: string;

  @IsUUID()
  organizationId!: string;

  @IsUUID()
  grantId!: string;

  @IsUUID()
  challengeId!: string;
}

class RevokeGrantDto {
  @IsUUID()
  grantId!: string;

  @IsUUID()
  organizationId!: string;
}

/**
 * Platform support-session gateway (TEST-ONLY signing keys).
 * Routes under /api/v1/auth/support/*
 */
@ApiTags('Support Session')
@Controller('auth/support')
export class SupportSessionController {
  constructor(@Inject(SupportSessionService) private readonly support: SupportSessionService) {}

  @Post('requests')
  @HttpCode(200)
  @ApiOperation({ summary: 'Create support access request (platform operator)' })
  createRequest(@Body() body: CreateSupportRequestDto) {
    return this.support.createAccessRequest(body);
  }

  @Post('approve')
  @HttpCode(200)
  @ApiOperation({ summary: 'Customer approval → time-limited grant' })
  approve(@Body() body: ApproveSupportRequestDto) {
    return this.support.approveRequest(body);
  }

  @Post('challenges')
  @HttpCode(200)
  @ApiOperation({ summary: 'Issue single-use support session challenge' })
  challenge(@Body() body: IssueChallengeDto) {
    return this.support.issueChallenge(body);
  }

  @Post('assertions')
  @HttpCode(200)
  @ApiOperation({ summary: 'Mint HS256 SSA (TEST-ONLY key material)' })
  mint(@Body() body: MintAssertionDto) {
    return this.support.mintAssertion(body);
  }

  @Post('sessions/open')
  @HttpCode(200)
  @ApiOperation({ summary: 'Verify assertion via open_support_session' })
  open(@Body() body: OpenSupportSessionDto) {
    return this.support.openSession(body);
  }

  @Post('grants/revoke')
  @HttpCode(200)
  @ApiOperation({ summary: 'Revoke support grant' })
  async revoke(@Body() body: RevokeGrantDto) {
    await this.support.revokeGrant(body.grantId, body.organizationId);
    return { revoked: true };
  }
}
