export const AUTH_STORE = Symbol('AUTH_STORE');

export interface StoredUser {
  id: string;
  organizationId: string;
  email: string;
  passwordHash: string;
  displayName: string;
  isActive: boolean;
  roles: string[];
}

export interface StoredSession {
  id: string;
  organizationId: string;
  userId: string;
  dpopJkt: string;
  isActive: boolean;
  revokedAt?: Date;
  expiresAt: Date;
}

export interface StoredToken {
  id: string;
  organizationId: string;
  sessionId: string;
  tokenHash: string;
  sequenceNumber: number;
  expiresAt: Date;
  consumedAt?: Date;
  revokedAt?: Date;
  replacedByTokenId?: string;
}

export interface IdempotencyRecord {
  organizationId: string;
  sessionId: string;
  requestFingerprint: string;
  presentedTokenHash: string;
  issuedTokenId: string;
  responseCiphertext: Buffer;
  responseIv: Buffer;
  responseAuthTag: Buffer;
  encryptionKeyId: string;
  /** KMS-wrapped DEK (envelope mode); absent for local long-lived keys */
  encryptedDataKey?: Buffer;
  dpopJkt: string;
  expiresAt: Date;
  invalidatedAt?: Date;
}

export type LoginLookupResult =
  | { status: 'found'; user: StoredUser }
  | { status: 'none' }
  | { status: 'ambiguous' };

export interface AuthStore {
  /** Organization-aware login lookup — never silently picks among multi-org emails. */
  findUserForLogin(email: string, organizationId?: string): Promise<LoginLookupResult>;
  /** @deprecated prefer findUserForLogin */
  findUserByEmail(email: string, organizationId?: string): Promise<StoredUser | null>;
  findUserById(organizationId: string, userId: string): Promise<StoredUser | null>;
  /** Test/bootstrap seed — inserts org+user. Not a production IdP API. */
  upsertUser(user: StoredUser): Promise<void>;
  createSession(session: StoredSession, initialToken: StoredToken): Promise<void>;
  getSession(organizationId: string, sessionId: string): Promise<StoredSession | null>;
  getTokenByHash(tokenHash: string): Promise<StoredToken | null>;
  rotateRefresh(input: {
    organizationId: string;
    sessionId: string;
    presentedTokenHash: string;
    newToken: StoredToken;
    idempotency: IdempotencyRecord;
  }): Promise<'ROTATED' | 'RECOVERED' | 'TOKEN_REUSE'>;
  findIdempotency(
    organizationId: string,
    sessionId: string,
    fingerprint: string,
  ): Promise<IdempotencyRecord | null>;
  revokeSession(organizationId: string, sessionId: string): Promise<void>;
  invalidateIdempotency(organizationId: string, sessionId: string): Promise<void>;
}
