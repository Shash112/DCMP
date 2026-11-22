import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import { Injectable, Logger } from '@nestjs/common';
import { DecryptCommand, GenerateDataKeyCommand, KMSClient } from '@aws-sdk/client-kms';
import { EncryptionKeyMaterial, RefreshCipherKeyProvider } from './key-provider.interface';
import { assertCryptoTestHooksAllowed } from './crypto-test-hooks';
import { createKmsClient } from './kms-client.factory';
import { DcmpKmsConfig, loadKmsConfig } from './kms-config';
import { assertWrappingKeyAllowed } from './kms-wrapping-key-allowlist';
import { EncryptedRefreshBlob, RefreshAadFields, buildRefreshAad } from './refresh-response-cipher';

/**
 * Encrypted blob extended with KMS-wrapped data key (never store plaintext DEK).
 */
export interface EnvelopeEncryptedRefreshBlob extends EncryptedRefreshBlob {
  /** CiphertextBlob from GenerateDataKey — Decrypt to recover AES-256 DEK */
  encryptedDataKey: Buffer;
  /** KMS CMK key id / ARN used to wrap the DEK */
  kmsKeyId: string;
}

/**
 * KMS envelope encryption for refresh-idempotency payloads.
 * GenerateDataKey(AES_256) → local AES-256-GCM with AAD → store CT/IV/tag + encrypted DEK.
 *
 * Implements RefreshCipherKeyProvider only for interface compatibility; prefer
 * encryptEnvelope/decryptEnvelope so plaintext DEKs are never retained.
 */
@Injectable()
export class KmsRefreshEnvelopeProvider implements RefreshCipherKeyProvider {
  private readonly logger = new Logger(KmsRefreshEnvelopeProvider.name);
  private readonly cfg: DcmpKmsConfig;
  private readonly client: KMSClient;

  constructor() {
    this.cfg = loadKmsConfig();
    this.client = createKmsClient(this.cfg);
  }

  /**
   * Test-only: switch active GenerateDataKey CMK (live rotation drills).
   * Allowed only when NODE_ENV=test (no override flag).
   */
  setActiveMasterKeyIdForTest(keyId: string): void {
    assertCryptoTestHooksAllowed();
    if (!keyId) throw new Error('setActiveMasterKeyIdForTest requires keyId');
    this.cfg.refreshMasterKeyId = keyId;
  }

  activeMasterKeyIdForTest(): string {
    assertCryptoTestHooksAllowed();
    return this.cfg.refreshMasterKeyId;
  }

  /** Not used for long-lived DEKs — envelope path generates per-record keys. */
  async getActiveKey(): Promise<EncryptionKeyMaterial> {
    throw new Error(
      'KmsRefreshEnvelopeProvider does not expose long-lived plaintext DEKs; use encryptEnvelope',
    );
  }

  async getKeyById(_keyId: string): Promise<EncryptionKeyMaterial | null> {
    return null;
  }

  async encryptEnvelope(
    plaintextObject: Record<string, unknown>,
    aadFields: Omit<RefreshAadFields, 'encryptionKeyId' | 'expiresAt'> & {
      expiresAt: Date;
    },
  ): Promise<EnvelopeEncryptedRefreshBlob> {
    const expZ = new Date(aadFields.expiresAt).toISOString().replace(/(\.\d{3})Z$/, '$1Z');
    let plainDek: Buffer | undefined;
    let encryptedDataKey: Buffer;
    try {
      const dk = await this.client.send(
        new GenerateDataKeyCommand({
          KeyId: this.cfg.refreshMasterKeyId,
          KeySpec: 'AES_256',
          // Encryption context binds DEK wrap to purpose (not a substitute for GCM AAD)
          EncryptionContext: {
            purpose: 'dcmp-refresh-idempotency',
            organization_id: aadFields.organizationId,
            session_id: aadFields.sessionId,
          },
        }),
      );
      if (!dk.Plaintext || !dk.CiphertextBlob) throw new Error('GenerateDataKey empty');
      plainDek = Buffer.from(dk.Plaintext);
      encryptedDataKey = Buffer.from(dk.CiphertextBlob);
      // Zeroize awareness: Plaintext from SDK should not be logged
    } catch (e) {
      const name = (e as { name?: string }).name || 'Error';
      this.logger.warn(`KMS GenerateDataKey failed: ${name}`);
      throw new Error(`KMS_UNAVAILABLE:${name}`);
    }

    const keyIdLabel = `kms-envelope:${this.cfg.refreshMasterKeyId.includes('/') ? this.cfg.refreshMasterKeyId.split('/').pop() : this.cfg.refreshMasterKeyId}`;
    const aad = buildRefreshAad({
      ...aadFields,
      encryptionKeyId: keyIdLabel,
      expiresAt: expZ,
    });
    try {
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', plainDek, iv);
      cipher.setAAD(aad);
      const pt = Buffer.from(JSON.stringify(plaintextObject), 'utf8');
      const ciphertext = Buffer.concat([cipher.update(pt), cipher.final()]);
      const authTag = cipher.getAuthTag();
      return {
        ciphertext,
        iv,
        authTag,
        encryptionKeyId: keyIdLabel,
        expiresAt: expZ,
        encryptedDataKey,
        kmsKeyId: this.cfg.refreshMasterKeyId,
      };
    } finally {
      if (plainDek) plainDek.fill(0);
    }
  }

  async decryptEnvelope(
    blob: EnvelopeEncryptedRefreshBlob,
    aadFields: Omit<RefreshAadFields, 'encryptionKeyId' | 'expiresAt'> & {
      expiresAt: string;
    },
  ): Promise<Record<string, unknown>> {
    if (new Date(aadFields.expiresAt).getTime() <= Date.now()) {
      throw new Error('Expired encryption record');
    }
    let plainDek: Buffer | undefined;
    try {
      const out = await this.client.send(
        new DecryptCommand({
          CiphertextBlob: blob.encryptedDataKey,
          // KeyId optional — CiphertextBlob embeds CMK metadata; omit avoids stale ARN issues
          EncryptionContext: {
            purpose: 'dcmp-refresh-idempotency',
            organization_id: aadFields.organizationId,
            session_id: aadFields.sessionId,
          },
        }),
      );
      if (!out.Plaintext) throw new Error('Decrypt empty');
      // CiphertextBlob embeds the wrapping CMK; KeyId is returned on Decrypt.
      // Allowlist = active master + optional DCMP_KMS_REFRESH_MASTER_VERIFY_KEY_IDS.
      // Empty KeyId fails closed; matching is exact ARN or exact UUID only.
      try {
        assertWrappingKeyAllowed(out.KeyId, [
          this.cfg.refreshMasterKeyId,
          ...this.cfg.refreshMasterVerifyKeyIds,
        ]);
      } catch (allowErr) {
        if (out.Plaintext instanceof Uint8Array) out.Plaintext.fill(0);
        throw allowErr;
      }
      plainDek = Buffer.from(out.Plaintext);
    } catch (e) {
      const name = (e as { name?: string }).name || 'Error';
      if (String((e as Error).message || '').startsWith('KMS_UNAVAILABLE:')) throw e;
      this.logger.warn(`KMS Decrypt failed: ${name}`);
      throw new Error(`KMS_UNAVAILABLE:${name}`);
    }

    const aad = buildRefreshAad({
      ...aadFields,
      encryptionKeyId: blob.encryptionKeyId,
      expiresAt: aadFields.expiresAt,
    });
    try {
      const decipher = createDecipheriv('aes-256-gcm', plainDek, blob.iv);
      decipher.setAAD(aad);
      decipher.setAuthTag(blob.authTag);
      const pt = Buffer.concat([decipher.update(blob.ciphertext), decipher.final()]);
      return JSON.parse(pt.toString('utf8')) as Record<string, unknown>;
    } finally {
      if (plainDek) plainDek.fill(0);
    }
  }
}
