import { Injectable } from '@nestjs/common';
import {
  AuthStore,
  IdempotencyRecord,
  StoredSession,
  StoredToken,
  StoredUser,
} from './auth-store.port';

/**
 * In-memory authoritative store for HTTP integration tests.
 * Mirrors Phase 2.1.12 conditional rotation + fingerprint uniqueness semantics.
 */
@Injectable()
export class MemoryAuthStore implements AuthStore {
  users: StoredUser[] = [];
  sessions = new Map<string, StoredSession>();
  tokensByHash = new Map<string, StoredToken>();
  tokensById = new Map<string, StoredToken>();
  idempotency = new Map<string, IdempotencyRecord>();
  private locks = new Map<string, Promise<void>>();

  private key(org: string, sid: string): string {
    return `${org}:${sid}`;
  }

  private idemKey(org: string, sid: string, fp: string): string {
    return `${org}:${sid}:${fp}`;
  }

  private async withLock<T>(sessionKey: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.locks.get(sessionKey) || Promise.resolve();
    let release!: () => void;
    const gate = new Promise<void>((r) => {
      release = r;
    });
    this.locks.set(
      sessionKey,
      prev.then(() => gate),
    );
    await prev;
    try {
      return await fn();
    } finally {
      release();
    }
  }

  seedUser(user: StoredUser): void {
    this.users = this.users.filter((u) => u.id !== user.id);
    this.users.push(user);
  }

  async upsertUser(user: StoredUser): Promise<void> {
    this.seedUser(user);
  }

  async findUserForLogin(email: string, organizationId?: string) {
    const lower = email.toLowerCase();
    const matches = this.users.filter(
      (u) =>
        u.email.toLowerCase() === lower &&
        u.isActive &&
        (!organizationId || u.organizationId === organizationId),
    );
    if (!organizationId && matches.length > 1) return { status: 'ambiguous' as const };
    if (matches.length === 0) return { status: 'none' as const };
    return { status: 'found' as const, user: matches[0] };
  }

  async findUserByEmail(email: string, organizationId?: string): Promise<StoredUser | null> {
    const result = await this.findUserForLogin(email, organizationId);
    return result.status === 'found' ? result.user : null;
  }

  async findUserById(organizationId: string, userId: string): Promise<StoredUser | null> {
    return (
      this.users.find((u) => u.id === userId && u.organizationId === organizationId) || null
    );
  }

  async createSession(session: StoredSession, initialToken: StoredToken): Promise<void> {
    this.sessions.set(this.key(session.organizationId, session.id), session);
    this.tokensByHash.set(initialToken.tokenHash, initialToken);
    this.tokensById.set(initialToken.id, initialToken);
  }

  async getSession(organizationId: string, sessionId: string): Promise<StoredSession | null> {
    return this.sessions.get(this.key(organizationId, sessionId)) || null;
  }

  async getTokenByHash(tokenHash: string): Promise<StoredToken | null> {
    return this.tokensByHash.get(tokenHash) || null;
  }

  async findIdempotency(
    organizationId: string,
    sessionId: string,
    fingerprint: string,
  ): Promise<IdempotencyRecord | null> {
    const row = this.idempotency.get(this.idemKey(organizationId, sessionId, fingerprint));
    if (!row) return null;
    if (row.invalidatedAt) return null;
    if (row.expiresAt.getTime() <= Date.now()) return null;
    return row;
  }

  async rotateRefresh(input: {
    organizationId: string;
    sessionId: string;
    presentedTokenHash: string;
    newToken: StoredToken;
    idempotency: IdempotencyRecord;
  }): Promise<'ROTATED' | 'RECOVERED' | 'TOKEN_REUSE'> {
    const sk = this.key(input.organizationId, input.sessionId);
    return this.withLock(sk, async () => {
      const existing = await this.findIdempotency(
        input.organizationId,
        input.sessionId,
        input.idempotency.requestFingerprint,
      );
      if (existing) return 'RECOVERED';

      const session = this.sessions.get(sk);
      if (!session || !session.isActive) return 'TOKEN_REUSE';

      const old = this.tokensByHash.get(input.presentedTokenHash);
      if (!old || old.sessionId !== input.sessionId || old.organizationId !== input.organizationId) {
        return 'TOKEN_REUSE';
      }
      if (old.consumedAt || old.revokedAt) {
        // Identical fingerprint recovery already handled; divergent → reuse
        return 'TOKEN_REUSE';
      }

      old.consumedAt = new Date();
      old.replacedByTokenId = input.newToken.id;
      this.tokensByHash.set(input.newToken.tokenHash, input.newToken);
      this.tokensById.set(input.newToken.id, input.newToken);
      this.idempotency.set(
        this.idemKey(
          input.organizationId,
          input.sessionId,
          input.idempotency.requestFingerprint,
        ),
        input.idempotency,
      );
      return 'ROTATED';
    });
  }

  async revokeSession(organizationId: string, sessionId: string): Promise<void> {
    const sk = this.key(organizationId, sessionId);
    const session = this.sessions.get(sk);
    if (session) {
      session.isActive = false;
      session.revokedAt = new Date();
    }
    await this.invalidateIdempotency(organizationId, sessionId);
  }

  async invalidateIdempotency(organizationId: string, sessionId: string): Promise<void> {
    for (const [k, v] of this.idempotency.entries()) {
      if (v.organizationId === organizationId && v.sessionId === sessionId && !v.invalidatedAt) {
        v.invalidatedAt = new Date();
        this.idempotency.set(k, v);
      }
    }
  }
}
