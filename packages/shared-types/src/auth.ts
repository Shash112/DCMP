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
  iss?: string;
  aud?: string | string[];
  sid?: string;
  iat?: number;
  exp?: number;
  nbf?: number;
  jti?: string;
  /** RFC 9449 confirmation — JWK thumbprint */
  cnf?: { jkt: string };
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  /** RFC 9449 — sender-constrained access tokens use DPoP (not Bearer) */
  tokenType: 'DPoP';
}

export interface LoginResponseData {
  user: AuthUser;
  tokens: AuthTokens;
}
