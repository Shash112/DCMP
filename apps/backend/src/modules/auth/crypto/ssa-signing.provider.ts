import { createHmac, randomUUID } from 'crypto';
import { Injectable, Logger } from '@nestjs/common';
import { GenerateMacCommand, KMSClient, VerifyMacCommand } from '@aws-sdk/client-kms';
import { assertCryptoTestHooksAllowed } from './crypto-test-hooks';
import { createKmsClient } from './kms-client.factory';
import { DcmpKmsConfig, loadKmsConfig } from './kms-config';

export const SSA_SIGNING_PROVIDER = Symbol('SSA_SIGNING_PROVIDER');

export interface SsaMintInput {
  adminId: string;
  organizationId: string;
  grantId: string;
  requestId: string;
  ttlSeconds?: number;
}

export interface SsaMinted {
  assertion: string;
  kid: string;
  expiresAt: number;
  keyMaterial: 'TEST-ONLY' | 'KMS-HMAC';
}

/**
 * HS256 SSA signing — local TEST-ONLY secret or AWS KMS HMAC_256 (GenerateMac).
 * KMS HMAC key material is never exported.
 */
export interface SsaSigningProvider {
  readonly mode: 'LOCAL_TEST' | 'KMS_HMAC';
  mint(input: SsaMintInput): Promise<SsaMinted>;
  verify(assertion: string): Promise<boolean>;
  activeKid(): string;
}

function b64url(data: Buffer | string): string {
  const buf = typeof data === 'string' ? Buffer.from(data) : data;
  return buf.toString('base64url');
}

@Injectable()
export class LocalSsaSigningProvider implements SsaSigningProvider {
  readonly mode = 'LOCAL_TEST' as const;
  private readonly kid: string;
  private readonly secret: Buffer;

  constructor() {
    const nodeEnv = process.env.NODE_ENV || 'development';
    const allow = process.env.AUTH_ALLOW_LOCAL_KEYS === 'true';
    if (nodeEnv === 'production' && !allow) {
      throw new Error('LocalSsaSigningProvider forbidden in production');
    }
    this.kid = process.env.DCMP_SSA_TEST_KID || 'val-key-gateway-1';
    this.secret = Buffer.from(
      process.env.DCMP_SSA_TEST_SECRET || 'validation-secret-key-32bytes!!',
    );
  }

  activeKid(): string {
    return this.kid;
  }

  async mint(input: SsaMintInput): Promise<SsaMinted> {
    const now = Math.floor(Date.now() / 1000);
    const exp = now + (input.ttlSeconds ?? 300);
    const header = { alg: 'HS256', typ: 'JWT', kid: this.kid };
    const claims = {
      iss: 'dcmp-platform-gateway',
      aud: 'dcmp-database-engine',
      sub: input.adminId,
      org_id: input.organizationId,
      grant_id: input.grantId,
      req_id: input.requestId,
      jti: randomUUID(),
      iat: now,
      exp,
    };
    const h = b64url(JSON.stringify(header));
    const p = b64url(JSON.stringify(claims));
    const sig = createHmac('sha256', this.secret).update(`${h}.${p}`).digest('base64url');
    return {
      assertion: `${h}.${p}.${sig}`,
      kid: this.kid,
      expiresAt: exp,
      keyMaterial: 'TEST-ONLY',
    };
  }

  async verify(assertion: string): Promise<boolean> {
    const parts = assertion.split('.');
    if (parts.length !== 3) return false;
    const expected = createHmac('sha256', this.secret)
      .update(`${parts[0]}.${parts[1]}`)
      .digest('base64url');
    return expected === parts[2];
  }
}

@Injectable()
export class KmsSsaSigningProvider implements SsaSigningProvider {
  readonly mode = 'KMS_HMAC' as const;
  private readonly logger = new Logger(KmsSsaSigningProvider.name);
  private readonly cfg: DcmpKmsConfig;
  private readonly client: KMSClient;
  private kid: string;

  constructor() {
    this.cfg = loadKmsConfig();
    this.client = createKmsClient(this.cfg);
    const bare = this.cfg.ssaHmacKeyId.includes('/')
      ? this.cfg.ssaHmacKeyId.split('/').pop()!
      : this.cfg.ssaHmacKeyId;
    this.kid = `kms-hmac256:${bare}`;
  }

  activeKid(): string {
    return this.kid;
  }

  /**
   * Test-only: switch active GenerateMac key (live rotation drills).
   * Allowed only when NODE_ENV=test (no override flag).
   */
  setActiveHmacKeyIdForTest(keyId: string): void {
    assertCryptoTestHooksAllowed();
    if (!keyId) throw new Error('setActiveHmacKeyIdForTest requires keyId');
    this.cfg.ssaHmacKeyId = keyId;
    const bare = keyId.includes('/') ? keyId.split('/').pop()! : keyId;
    this.kid = `kms-hmac256:${bare}`;
  }

  async mint(input: SsaMintInput): Promise<SsaMinted> {
    const now = Math.floor(Date.now() / 1000);
    const exp = now + (input.ttlSeconds ?? 300);
    const header = { alg: 'HS256', typ: 'JWT', kid: this.kid };
    const claims = {
      iss: 'dcmp-platform-gateway',
      aud: 'dcmp-database-engine',
      sub: input.adminId,
      org_id: input.organizationId,
      grant_id: input.grantId,
      req_id: input.requestId,
      jti: randomUUID(),
      iat: now,
      exp,
    };
    const h = b64url(JSON.stringify(header));
    const p = b64url(JSON.stringify(claims));
    const message = Buffer.from(`${h}.${p}`, 'utf8');
    try {
      const out = await this.client.send(
        new GenerateMacCommand({
          KeyId: this.cfg.ssaHmacKeyId,
          MacAlgorithm: 'HMAC_SHA_256',
          Message: message,
        }),
      );
      if (!out.Mac) throw new Error('GenerateMac empty');
      const sig = Buffer.from(out.Mac).toString('base64url');
      return {
        assertion: `${h}.${p}.${sig}`,
        kid: this.kid,
        expiresAt: exp,
        keyMaterial: 'KMS-HMAC',
      };
    } catch (e) {
      const name = (e as { name?: string }).name || 'Error';
      this.logger.warn(`KMS GenerateMac failed: ${name}`);
      throw new Error(`KMS_UNAVAILABLE:${name}`);
    }
  }

  async verify(assertion: string): Promise<boolean> {
    const parts = assertion.split('.');
    if (parts.length !== 3) return false;
    const message = Buffer.from(`${parts[0]}.${parts[1]}`, 'utf8');
    let mac: Buffer;
    try {
      mac = Buffer.from(parts[2], 'base64url');
    } catch {
      return false;
    }
    const keyIds = [this.cfg.ssaHmacKeyId, ...this.cfg.ssaHmacVerifyKeyIds];
    for (const keyId of keyIds) {
      try {
        const out = await this.client.send(
          new VerifyMacCommand({
            KeyId: keyId,
            MacAlgorithm: 'HMAC_SHA_256',
            Message: message,
            Mac: mac,
          }),
        );
        if (out.MacValid) return true;
      } catch (e) {
        const name = (e as { name?: string }).name || '';
        if (name === 'KMSInvalidMacException') continue;
        this.logger.warn(`KMS VerifyMac error: ${name}`);
        throw new Error(`KMS_UNAVAILABLE:${name}`);
      }
    }
    return false;
  }
}
