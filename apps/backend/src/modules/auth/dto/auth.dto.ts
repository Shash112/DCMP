import { IsEmail, IsOptional, IsString, IsUUID, MinLength } from 'class-validator';

export class LoginDto {
  @IsEmail()
  email!: string;

  @IsString()
  @MinLength(8)
  password!: string;

  @IsOptional()
  @IsString()
  tenantSlug?: string;

  /** Optional client org hint — never used as authorization */
  @IsOptional()
  @IsUUID()
  organizationId?: string;
}

export class RefreshDto {
  @IsString()
  @MinLength(1)
  refreshToken!: string;
}

export class LogoutDto {
  @IsOptional()
  @IsString()
  refreshToken?: string;
}

export class RevokeSessionDto {
  @IsUUID()
  sessionId!: string;

  @IsUUID()
  organizationId!: string;
}
