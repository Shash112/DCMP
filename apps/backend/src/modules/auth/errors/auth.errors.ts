import { HttpException, HttpStatus } from '@nestjs/common';
import { ERROR_CODES } from '@dcmp/api-contracts';

export class AuthHttpException extends HttpException {
  constructor(
    code: string,
    message: string,
    status: HttpStatus = HttpStatus.UNAUTHORIZED,
    extras?: Record<string, unknown>,
  ) {
    super({ code, message, ...extras }, status);
  }
}

export const AuthErrors = {
  dpopFailed: (message = 'DPoP proof validation failed') =>
    new AuthHttpException(ERROR_CODES.DPOP_PROOF_FAILED, message),
  dpopClaims: (message = 'Invalid DPoP claims') =>
    new AuthHttpException(ERROR_CODES.INVALID_DPOP_CLAIMS, message),
  dpopExpired: () =>
    new AuthHttpException(ERROR_CODES.DPOP_PROOF_EXPIRED, 'DPoP proof is outside the accepted time window'),
  dpopReplay: () =>
    new AuthHttpException(ERROR_CODES.DPOP_PROOF_REPLAY_DETECTED, 'DPoP proof jti has already been used'),
  useNonce: (nonce: string) =>
    new AuthHttpException(ERROR_CODES.USE_DPOP_NONCE, 'A fresh DPoP nonce is required', HttpStatus.UNAUTHORIZED, {
      dpopNonce: nonce,
    }),
  replayStoreUnavailable: () =>
    new AuthHttpException(
      ERROR_CODES.DPOP_REPLAY_STORE_UNAVAILABLE,
      'DPoP replay protection store unavailable; refusing new proof admission',
      HttpStatus.SERVICE_UNAVAILABLE,
    ),
  cryptoUnavailable: (message = 'Cryptographic key service unavailable; refusing to sign') =>
    new AuthHttpException(
      ERROR_CODES.DPOP_REPLAY_STORE_UNAVAILABLE,
      message,
      HttpStatus.SERVICE_UNAVAILABLE,
    ),
  tokenReuse: () =>
    new AuthHttpException(ERROR_CODES.TOKEN_REUSE_DETECTED, 'Refresh token reuse detected; session revoked'),
  sessionRevoked: () =>
    new AuthHttpException(ERROR_CODES.SESSION_REVOKED, 'Session is revoked or inactive'),
  unauthenticated: (message = 'Authentication required') =>
    new AuthHttpException(ERROR_CODES.UNAUTHENTICATED, message),
  tenantMismatch: () =>
    new AuthHttpException(ERROR_CODES.TENANT_MISMATCH, 'Cross-tenant session use denied', HttpStatus.FORBIDDEN),
  loginOrganizationRequired: () =>
    new AuthHttpException(
      ERROR_CODES.LOGIN_ORGANIZATION_REQUIRED,
      'Organization context is required to complete sign-in',
      HttpStatus.BAD_REQUEST,
    ),
  accessTokenInvalid: (message = 'Access token validation failed') =>
    new AuthHttpException(ERROR_CODES.ACCESS_TOKEN_INVALID, message, HttpStatus.UNAUTHORIZED),
  supportDenied: (message = 'Support session denied') =>
    new AuthHttpException(ERROR_CODES.UNAUTHENTICATED, message, HttpStatus.UNAUTHORIZED),
};
