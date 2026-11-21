/**
 * DCMP Identity & Authentication Models
 * Aligned with DCMP_Security_and_Tenant_Isolation_Design_v1.0.docx
 */

export interface AuthUser {
  id: string;
  organizationId?: string | null;
  email: string;
  firstName: string;
  lastName: string;
  isActive: boolean;
  isPlatformAdmin: boolean;
  roles: string[];
  permissions: string[];
}

export interface JwtPayload {
  sub: string;
  email: string;
  orgId?: string | null;
  roles: string[];
  isPlatformAdmin?: boolean;
  type: 'access' | 'refresh';
  iat?: number;
  exp?: number;
  jti?: string;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  tokenType: 'Bearer';
}

export interface LoginResponseData {
  user: AuthUser;
  tokens: AuthTokens;
}
