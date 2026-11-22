import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import {
  GetPublicKeyCommand,
  KMSClient,
  SignCommand,
} from '@aws-sdk/client-kms';
import { createPublicKey } from 'crypto';
import { exportJWK, importJWK, type JWK, type JWTPayload, type KeyLike } from 'jose';
import {
  AccessSigningKey,
  AccessTokenSigningKeyProvider,
} from './access-token-key.provider';
import { assertCryptoTestHooksAllowed } from './crypto-test-hooks';
import { derToJoseEs256 } from './ecdsa-der-jose';
import { createKmsClient } from './kms-client.factory';
import { DcmpKmsConfig, loadKmsConfig } from './kms-config';

function b64urlJson(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj), 'utf8').toString('base64url');
}

/**
 * AWS KMS ECC_NIST_P256 access-token signing (ES256).
 * Private key never leaves KMS. Signatures converted DER → JOSE R||S.
 */
@Injectable()
export class KmsAccessTokenKeyProvider implements AccessTokenSigningKeyProvider, OnModuleInit {
  private readonly logger = new Logger(KmsAccessTokenKeyProvider.name);
  private readonly cfg: DcmpKmsConfig;
  private readonly client: KMSClient;
  private readonly publicByKid = new Map<string, { jwk: JWK; keyId: string; accept: boolean }>();
  private activeKid = '';
  private ready: Promise<void>;

  constructor() {
    this.cfg = loadKmsConfig();
    this.client = createKmsClient(this.cfg);
    this.ready = this.bootstrap();
  }

  async onModuleInit(): Promise<void> {
    await this.ready;
  }

  private kidFor(keyId: string): string {
    // Stable opaque kid — last segment of UUID/ARN
    const bare = keyId.includes('/') ? keyId.split('/').pop()! : keyId;
    return `kms-es256:${bare}`;
  }

  private async loadPublic(keyId: string, accept: boolean): Promise<void> {
    try {
      const out = await this.client.send(
        new GetPublicKeyCommand({ KeyId: keyId }),
      );
      if (!out.PublicKey) throw new Error('GetPublicKey returned empty');
      const spki = Buffer.from(out.PublicKey);
      const pub = createPublicKey({ key: spki, format: 'der', type: 'spki' });
      const jwk = await exportJWK(pub);
      const kid = this.kidFor(keyId);
      jwk.kid = kid;
      jwk.alg = 'ES256';
      jwk.use = 'sig';
      this.publicByKid.set(kid, { jwk, keyId, accept });
    } catch (e) {
      const name = (e as { name?: string }).name || '';
      this.logger.error(`KMS GetPublicKey failed (${name}) — fail-closed`);
      throw e;
    }
  }

  private async bootstrap(): Promise<void> {
    await this.loadPublic(this.cfg.accessTokenKeyId, true);
    this.activeKid = this.kidFor(this.cfg.accessTokenKeyId);
    for (const id of this.cfg.accessTokenVerifyKeyIds) {
      if (id === this.cfg.accessTokenKeyId) continue;
      await this.loadPublic(id, true);
    }
    this.logger.log(
      `KMS access-token provider ready (activeKid=${this.activeKid}, verifyKeys=${this.publicByKid.size})`,
    );
  }

  private async ensureReady(): Promise<void> {
    await this.ready;
  }

  async getActiveSigningKey(): Promise<AccessSigningKey> {
    await this.ensureReady();
    const row = this.publicByKid.get(this.activeKid);
    if (!row || !row.accept) throw new Error('No active KMS access-token signing key');
    // privateKey intentionally absent — callers must use signCompactJwt
    return {
      kid: this.activeKid,
      privateKey: undefined as unknown as KeyLike,
      publicJwk: { ...row.jwk },
      activeForSigning: true,
      acceptForVerify: true,
      kmsSign: true,
    };
  }

  async getVerificationKey(kid: string): Promise<AccessSigningKey | null> {
    await this.ensureReady();
    const row = this.publicByKid.get(kid);
    if (!row || !row.accept) return null;
    const publicKey = await importJWK(row.jwk, 'ES256');
    return {
      kid,
      privateKey: publicKey,
      publicJwk: { ...row.jwk },
      activeForSigning: kid === this.activeKid,
      acceptForVerify: true,
    };
  }

  async listVerificationJwks(): Promise<JWK[]> {
    await this.ensureReady();
    return [...this.publicByKid.values()]
      .filter((r) => r.accept)
      .map((r) => ({ ...r.jwk }));
  }

  /**
   * Sign compact JWT via KMS Sign (ECDSA_SHA_256) + DER→JOSE conversion.
   */
  async signCompactJwt(payload: JWTPayload, headerExtra?: Record<string, unknown>): Promise<string> {
    await this.ensureReady();
    const row = this.publicByKid.get(this.activeKid);
    if (!row) throw new Error('No active KMS signing key');
    const header = { alg: 'ES256', typ: 'at+jwt', kid: this.activeKid, ...headerExtra };
    const h = b64urlJson(header);
    const p = b64urlJson(payload);
    const signingInput = `${h}.${p}`;
    try {
      const out = await this.client.send(
        new SignCommand({
          KeyId: row.keyId,
          Message: Buffer.from(signingInput, 'utf8'),
          MessageType: 'RAW',
          SigningAlgorithm: 'ECDSA_SHA_256',
        }),
      );
      if (!out.Signature) throw new Error('KMS Sign returned empty signature');
      const joseSig = derToJoseEs256(Buffer.from(out.Signature));
      return `${signingInput}.${joseSig.toString('base64url')}`;
    } catch (e) {
      const name = (e as { name?: string }).name || 'Error';
      this.logger.warn(`KMS Sign failed: ${name}`);
      throw new Error(`KMS_UNAVAILABLE:${name}`);
    }
  }

  /**
   * Test-only rotation drill. Allowed only when NODE_ENV=test (no override flag).
   * Not part of AccessTokenSigningKeyProvider production interface.
   */
  async rotateForTest(newKeyId: string): Promise<string> {
    assertCryptoTestHooksAllowed();
    if (!newKeyId) throw new Error('rotateForTest requires newKeyId');
    await this.ensureReady();
    await this.loadPublic(newKeyId, true);
    this.activeKid = this.kidFor(newKeyId);
    return this.activeKid;
  }

  /** Test-only. Allowed only when NODE_ENV=test. */
  async retireForTest(kid: string): Promise<void> {
    assertCryptoTestHooksAllowed();
    await this.ensureReady();
    const row = this.publicByKid.get(kid);
    if (!row) return;
    if (kid === this.activeKid) {
      throw new Error('Cannot retire active signing kid without rotating first');
    }
    row.accept = false;
  }
}
