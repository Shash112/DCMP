export const REFRESH_CIPHER_KEY_PROVIDER = Symbol('REFRESH_CIPHER_KEY_PROVIDER');

export interface EncryptionKeyMaterial {
  keyId: string;
  /** 32-byte AES-256 key */
  key: Buffer;
}

/**
 * Production implementations must load keys from Vault/KMS/Secrets Manager.
 * LocalTestKeyProvider is for tests and non-production NODE_ENV only.
 */
export interface RefreshCipherKeyProvider {
  getActiveKey(): Promise<EncryptionKeyMaterial>;
  getKeyById(keyId: string): Promise<EncryptionKeyMaterial | null>;
}
