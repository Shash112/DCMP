import { Injectable } from '@nestjs/common';
import { exportJWK, generateKeyPair, importJWK, type JWK } from 'jose';
import { AccessSigningKey, AccessTokenSigningKeyProvider } from './access-token-key.provider';
import { assertCryptoTestHooksAllowed } from './crypto-test-hooks';

interface StoredKey {
  kid: string;
  privateJwk: JWK;
  publicJwk: JWK;
  activeForSigning: boolean;
  acceptForVerify: boolean;
  privateKey?: Awaited<ReturnType<typeof importJWK>>;
}

/**
 * Local/test ES256 access-token keys. Forbidden in production unless
 * AUTH_ALLOW_LOCAL_KEYS=true (still not for real deployments).
 */
@Injectable()
export class LocalAccessTokenKeyProvider implements AccessTokenSigningKeyProvider {
  private keys = new Map<string, StoredKey>();
  private activeKid: string;
  private ready: Promise<void>;

  constructor() {
    const nodeEnv = process.env.NODE_ENV || 'development';
    const allow = process.env.AUTH_ALLOW_LOCAL_KEYS === 'true';
    if (nodeEnv === 'production' && !allow) {
      throw new Error(
        'LocalAccessTokenKeyProvider cannot be used in production without AUTH_ALLOW_LOCAL_KEYS',
      );
    }
    this.activeKid = '';
    this.ready = this.bootstrap();
  }

  private async bootstrap(): Promise<void> {
    const v0 = await this.mintKey('access-es256:v0', false);
    const v1 = await this.mintKey('access-es256:v1', true);
    this.keys.set(v0.kid, v0);
    this.keys.set(v1.kid, v1);
    this.activeKid = v1.kid;
  }

  private async mintKey(kid: string, activeForSigning: boolean): Promise<StoredKey> {
    const pair = await generateKeyPair('ES256', { extractable: true });
    const privateJwk = await exportJWK(pair.privateKey);
    const publicJwk = await exportJWK(pair.publicKey);
    publicJwk.kid = kid;
    publicJwk.alg = 'ES256';
    publicJwk.use = 'sig';
    delete (publicJwk as { d?: string }).d;
    const privateKey = await importJWK(privateJwk, 'ES256');
    return {
      kid,
      privateJwk,
      publicJwk,
      activeForSigning,
      acceptForVerify: true,
      privateKey,
    };
  }

  private async ensureReady(): Promise<void> {
    await this.ready;
  }

  async getActiveSigningKey(): Promise<AccessSigningKey> {
    await this.ensureReady();
    const row = this.keys.get(this.activeKid);
    if (!row || !row.activeForSigning || !row.acceptForVerify) {
      throw new Error('No active access-token signing key');
    }
    return {
      kid: row.kid,
      privateKey: row.privateKey!,
      publicJwk: { ...row.publicJwk },
      activeForSigning: true,
      acceptForVerify: true,
    };
  }

  async getVerificationKey(kid: string): Promise<AccessSigningKey | null> {
    await this.ensureReady();
    const row = this.keys.get(kid);
    if (!row || !row.acceptForVerify) return null;
    return {
      kid: row.kid,
      privateKey: row.privateKey!,
      publicJwk: { ...row.publicJwk },
      activeForSigning: row.activeForSigning,
      acceptForVerify: true,
    };
  }

  async listVerificationJwks(): Promise<JWK[]> {
    await this.ensureReady();
    return [...this.keys.values()]
      .filter((k) => k.acceptForVerify)
      .map((k) => ({ ...k.publicJwk }));
  }

  /** Test-only. Allowed only when NODE_ENV=test. Not on production interface. */
  async rotateForTest(): Promise<string> {
    assertCryptoTestHooksAllowed();
    await this.ensureReady();
    for (const k of this.keys.values()) {
      k.activeForSigning = false;
    }
    const kid = `access-es256:v${Date.now().toString(36)}`;
    const next = await this.mintKey(kid, true);
    this.keys.set(kid, next);
    this.activeKid = kid;
    return kid;
  }

  /** Test-only. Allowed only when NODE_ENV=test. */
  async retireForTest(kid: string): Promise<void> {
    assertCryptoTestHooksAllowed();
    await this.ensureReady();
    const row = this.keys.get(kid);
    if (!row) return;
    row.acceptForVerify = false;
    row.activeForSigning = false;
    if (this.activeKid === kid) {
      throw new Error('Cannot retire the only active signing key without rotating first');
    }
  }
}
