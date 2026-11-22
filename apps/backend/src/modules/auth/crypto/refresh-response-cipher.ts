import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import { Injectable, Optional } from '@nestjs/common';
import { RefreshCipherKeyProvider } from './key-provider.interface';
import { KmsRefreshEnvelopeProvider } from './kms-refresh-envelope.provider';

export interface RefreshAadFields {
  organizationId: string;
  sessionId: string;
  requestFingerprint: string;
  presentedTokenHash: string;
  issuedTokenId: string;
  dpopJkt: string;
  encryptionKeyId: string;
  expiresAt: string; // RFC3339 UTC with Z
}

export interface EncryptedRefreshBlob {
  ciphertext: Buffer;
  iv: Buffer;
  authTag: Buffer;
  encryptionKeyId: string;
  expiresAt: string;
  /** Present for KMS envelope mode — never a plaintext DEK */
  encryptedDataKey?: Buffer;
  kmsKeyId?: string;
}

export function buildRefreshAad(fields: RefreshAadFields): Buffer {
  const lines = [
    'dcmp-refresh-aad-v1',
    `organization_id=${fields.organizationId}`,
    `session_id=${fields.sessionId}`,
    `request_fingerprint=${fields.requestFingerprint}`,
    `presented_token_hash=${fields.presentedTokenHash}`,
    `issued_token_id=${fields.issuedTokenId}`,
    `dpop_jkt=${fields.dpopJkt}`,
    `encryption_key_id=${fields.encryptionKeyId}`,
    `expires_at=${fields.expiresAt}`,
    '',
  ];
  return Buffer.from(lines.join('\n'), 'utf8');
}

@Injectable()
export class RefreshResponseCipher {
  constructor(
    private readonly keys: RefreshCipherKeyProvider,
    @Optional() private readonly envelope?: KmsRefreshEnvelopeProvider,
  ) {}

  async encrypt(
    plaintextObject: Record<string, unknown>,
    aadFields: Omit<RefreshAadFields, 'encryptionKeyId' | 'expiresAt'> & {
      expiresAt: Date;
    },
  ): Promise<EncryptedRefreshBlob> {
    if (this.envelope) {
      const env = await this.envelope.encryptEnvelope(plaintextObject, aadFields);
      return {
        ciphertext: env.ciphertext,
        iv: env.iv,
        authTag: env.authTag,
        encryptionKeyId: env.encryptionKeyId,
        expiresAt: env.expiresAt,
        encryptedDataKey: env.encryptedDataKey,
        kmsKeyId: env.kmsKeyId,
      };
    }

    const active = await this.keys.getActiveKey();
    const expZ = new Date(aadFields.expiresAt).toISOString().replace(/(\.\d{3})Z$/, '$1Z');
    const aad = buildRefreshAad({
      ...aadFields,
      encryptionKeyId: active.keyId,
      expiresAt: expZ,
    });
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', active.key, iv);
    cipher.setAAD(aad);
    const pt = Buffer.from(JSON.stringify(plaintextObject), 'utf8');
    const ciphertext = Buffer.concat([cipher.update(pt), cipher.final()]);
    const authTag = cipher.getAuthTag();
    if (iv.length !== 12 || authTag.length !== 16) {
      throw new Error('AES-GCM IV/tag length invariant violated');
    }
    return {
      ciphertext,
      iv,
      authTag,
      encryptionKeyId: active.keyId,
      expiresAt: expZ,
    };
  }

  async decrypt(
    blob: EncryptedRefreshBlob,
    aadFields: Omit<RefreshAadFields, 'encryptionKeyId' | 'expiresAt'> & {
      expiresAt: string;
    },
  ): Promise<Record<string, unknown>> {
    if (this.envelope) {
      if (!blob.encryptedDataKey) {
        throw new Error('KMS envelope decrypt requires encryptedDataKey');
      }
      return this.envelope.decryptEnvelope(
        {
          ...blob,
          encryptedDataKey: blob.encryptedDataKey,
          kmsKeyId: blob.kmsKeyId || '',
        },
        aadFields,
      );
    }

    if (new Date(aadFields.expiresAt).getTime() <= Date.now()) {
      throw new Error('Expired encryption record');
    }
    const material = await this.keys.getKeyById(blob.encryptionKeyId);
    if (!material) {
      throw new Error('Encryption key not available');
    }
    const aad = buildRefreshAad({
      ...aadFields,
      encryptionKeyId: blob.encryptionKeyId,
      expiresAt: aadFields.expiresAt,
    });
    const decipher = createDecipheriv('aes-256-gcm', material.key, blob.iv);
    decipher.setAAD(aad);
    decipher.setAuthTag(blob.authTag);
    const pt = Buffer.concat([decipher.update(blob.ciphertext), decipher.final()]);
    return JSON.parse(pt.toString('utf8')) as Record<string, unknown>;
  }
}
