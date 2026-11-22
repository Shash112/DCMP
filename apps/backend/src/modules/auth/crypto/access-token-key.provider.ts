import type { JWK, JWTPayload, KeyLike } from 'jose';

export const ACCESS_TOKEN_SIGNING_KEY_PROVIDER = Symbol('ACCESS_TOKEN_SIGNING_KEY_PROVIDER');

export interface AccessSigningKey {
  kid: string;
  /** Present for local providers; absent when KMS holds the private key */
  privateKey?: KeyLike | Uint8Array;
  publicJwk: JWK;
  /** When false, key may verify but must not sign new tokens */
  activeForSigning: boolean;
  /** When false, key is retired — verification must fail */
  acceptForVerify: boolean;
  /** When true, caller must use provider.signCompactJwt */
  kmsSign?: boolean;
}

/**
 * Access-token signing keys (ES256). Separate from refresh AES-GCM material.
 * Production KMS implementations must never export or log private keys.
 */
export interface AccessTokenSigningKeyProvider {
  getActiveSigningKey(): Promise<AccessSigningKey>;
  getVerificationKey(kid: string): Promise<AccessSigningKey | null>;
  /** Public JWKs currently acceptable for verification */
  listVerificationJwks(): Promise<JWK[]>;
  /**
   * Optional KMS (or other HSM) compact JWT signer.
   * Local providers may omit — AuthService falls back to SignJWT + privateKey.
   */
  signCompactJwt?(payload: JWTPayload, headerExtra?: Record<string, unknown>): Promise<string>;
}

/** Stub for AWS KMS / Secrets Manager — not configured in this environment. */
export class UnconfiguredProductionAccessTokenKeyProvider implements AccessTokenSigningKeyProvider {
  async getActiveSigningKey(): Promise<AccessSigningKey> {
    throw new Error(
      'Production access-token signing provider is not configured (KMS/Secrets Manager NOT RUN)',
    );
  }
  async getVerificationKey(): Promise<AccessSigningKey | null> {
    throw new Error('Production access-token signing provider is not configured');
  }
  async listVerificationJwks(): Promise<JWK[]> {
    throw new Error('Production access-token signing provider is not configured');
  }
}
