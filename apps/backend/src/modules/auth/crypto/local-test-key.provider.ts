import { createHash, randomBytes } from 'crypto';
import { Injectable } from '@nestjs/common';
import { assertCryptoTestHooksAllowed } from './crypto-test-hooks';
import { EncryptionKeyMaterial, RefreshCipherKeyProvider } from './key-provider.interface';

/**
 * Local/test key provider. Refuses to activate when NODE_ENV=production
 * unless AUTH_ALLOW_LOCAL_KEYS=true is explicitly set (still not for real prod).
 *
 * Reads process.env directly so Nest DI works under tsx (no emitDecoratorMetadata).
 */
@Injectable()
export class LocalTestKeyProvider implements RefreshCipherKeyProvider {
  private readonly keys = new Map<string, Buffer>();
  private activeId: string;

  constructor() {
    const nodeEnv = process.env.NODE_ENV || 'development';
    const allow = process.env.AUTH_ALLOW_LOCAL_KEYS === 'true';
    if (nodeEnv === 'production' && !allow) {
      throw new Error(
        'LocalTestKeyProvider cannot be used in production without AUTH_ALLOW_LOCAL_KEYS (forbidden for real deployments)',
      );
    }
    const seed =
      process.env.DCMP_TEST_REFRESH_CIPHER_SEED ||
      'dcmp-local-test-refresh-cipher-seed-not-for-prod';
    this.activeId = 'local-test:v1';
    this.keys.set(this.activeId, createHash('sha256').update(seed).digest());
    this.keys.set('local-test:v0', createHash('sha256').update(`${seed}:v0`).digest());
  }

  async getActiveKey(): Promise<EncryptionKeyMaterial> {
    return { keyId: this.activeId, key: this.keys.get(this.activeId)! };
  }

  async getKeyById(keyId: string): Promise<EncryptionKeyMaterial | null> {
    const key = this.keys.get(keyId);
    return key ? { keyId, key } : null;
  }

  /** Test-only. Allowed only when NODE_ENV=test. */
  rotateForTest(): string {
    assertCryptoTestHooksAllowed();
    const id = `local-test:v${randomBytes(2).toString('hex')}`;
    this.keys.set(id, randomBytes(32));
    this.activeId = id;
    return id;
  }
}
