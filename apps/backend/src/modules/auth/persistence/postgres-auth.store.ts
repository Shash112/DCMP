import { Inject, Injectable } from '@nestjs/common';
import { PoolClient } from 'pg';
import {
  AuthStore,
  IdempotencyRecord,
  StoredSession,
  StoredToken,
  StoredUser,
} from './auth-store.port';
import { ValidationPgPool } from './pg.pool';

function asDate(value: unknown): Date {
  if (value instanceof Date) return value;
  return new Date(String(value));
}

function asBuffer(value: unknown): Buffer {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (typeof value === 'string') {
    const hex = value.startsWith('\\x') ? value.slice(2) : value;
    return Buffer.from(hex, 'hex');
  }
  throw new Error('expected BYTEA value');
}

function mapUser(row: Record<string, unknown>): StoredUser {
  return {
    id: String(row.id),
    organizationId: String(row.organization_id),
    email: String(row.email),
    passwordHash: String(row.password_hash || ''),
    displayName: String(row.display_name),
    isActive: row.deleted_at == null,
    roles: Array.isArray(row.roles) ? (row.roles as string[]) : ['inspector'],
  };
}

function mapToken(row: Record<string, unknown>): StoredToken {
  return {
    id: String(row.id),
    organizationId: String(row.organization_id),
    sessionId: String(row.session_id),
    tokenHash: String(row.token_hash).trim(),
    sequenceNumber: Number(row.sequence_number),
    expiresAt: asDate(row.expires_at),
    consumedAt: row.consumed_at ? asDate(row.consumed_at) : undefined,
    revokedAt: row.revoked_at ? asDate(row.revoked_at) : undefined,
    replacedByTokenId: row.replaced_by_token_id ? String(row.replaced_by_token_id) : undefined,
  };
}

function mapSession(row: Record<string, unknown>): StoredSession {
  return {
    id: String(row.id),
    organizationId: String(row.organization_id),
    userId: String(row.user_id),
    dpopJkt: String(row.dpop_jkt),
    isActive: Boolean(row.is_active),
    revokedAt: row.revoked_at ? asDate(row.revoked_at) : undefined,
    expiresAt: asDate(row.expires_at),
  };
}

function mapIdem(row: Record<string, unknown>): IdempotencyRecord {
  return {
    organizationId: String(row.organization_id),
    sessionId: String(row.session_id),
    requestFingerprint: String(row.request_fingerprint).trim(),
    presentedTokenHash: String(row.presented_token_hash).trim(),
    issuedTokenId: String(row.issued_token_id),
    responseCiphertext: asBuffer(row.response_ciphertext),
    responseIv: asBuffer(row.response_iv),
    responseAuthTag: asBuffer(row.response_auth_tag),
    encryptionKeyId: String(row.encryption_key_id).trim(),
    encryptedDataKey: row.encrypted_data_key ? asBuffer(row.encrypted_data_key) : undefined,
    dpopJkt: String(row.dpop_jkt).trim(),
    expiresAt: asDate(row.expires_at),
    invalidatedAt: row.invalidated_at ? asDate(row.invalidated_at) : undefined,
  };
}

/**
 * PostgreSQL-backed AuthStore for disposable dcmp_validation.
 * Mutations run as dcmp_app under FORCE RLS with transaction-local tenant GUC.
 */
@Injectable()
export class PostgresAuthStore implements AuthStore {
  constructor(@Inject(ValidationPgPool) private readonly pg: ValidationPgPool) {}

  async findUserForLogin(email: string, organizationId?: string) {
    return this.pg.withAppClient(async (client) => {
      const { rows } = await client.query(
        `SELECT * FROM dcmp_security.lookup_user_for_login($1, $2)`,
        [email, organizationId ?? null],
      );
      const row = rows[0] as Record<string, unknown> | undefined;
      if (!row) return { status: 'none' as const };
      const matchCount = Number(row.match_count ?? 0);
      if (!row.id && matchCount > 1) return { status: 'ambiguous' as const };
      if (!row.id) return { status: 'none' as const };
      return { status: 'found' as const, user: mapUser(row) };
    });
  }

  async findUserByEmail(email: string, organizationId?: string): Promise<StoredUser | null> {
    const result = await this.findUserForLogin(email, organizationId);
    return result.status === 'found' ? result.user : null;
  }

  async findUserById(organizationId: string, userId: string): Promise<StoredUser | null> {
    return this.pg.withAppClient(async (client) => {
      const { rows } = await client.query(`SELECT * FROM dcmp_security.lookup_user_by_id($1, $2)`, [
        organizationId,
        userId,
      ]);
      return rows[0] ? mapUser(rows[0]) : null;
    });
  }

  async upsertUser(user: StoredUser): Promise<void> {
    // Seed path: bootstrap as current session user (superuser trust) then app ops.
    // Uses pool directly with RESET so we can insert org/user before RLS context exists.
    const client = await this.pg.pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        `INSERT INTO public.organizations (id, org_code, display_name, status, data_region)
         VALUES ($1, $2, $3, 'ACTIVE', 'us-east-1')
         ON CONFLICT (id) DO UPDATE SET status = 'ACTIVE', suspended_at = NULL`,
        [
          user.organizationId,
          `ORG-${user.organizationId.replace(/-/g, '').slice(0, 12)}`,
          `Org ${user.organizationId.slice(0, 8)}`,
        ],
      );
      await client.query(
        `INSERT INTO public.users (id, organization_id, email, display_name, password_hash, roles, deleted_at)
         VALUES ($1, $2, $3, $4, $5, $6, NULL)
         ON CONFLICT (id) DO UPDATE
           SET email = EXCLUDED.email,
               display_name = EXCLUDED.display_name,
               password_hash = EXCLUDED.password_hash,
               roles = EXCLUDED.roles,
               deleted_at = NULL`,
        [user.id, user.organizationId, user.email, user.displayName, user.passwordHash, user.roles],
      );
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
  }

  async createSession(session: StoredSession, initialToken: StoredToken): Promise<void> {
    await this.pg.withTenantTx(session.organizationId, async (client) => {
      await client.query(
        `INSERT INTO public.user_sessions
           (id, organization_id, user_id, dpop_jkt, is_active, expires_at)
         VALUES ($1, $2, $3, $4, true, $5)`,
        [session.id, session.organizationId, session.userId, session.dpopJkt, session.expiresAt],
      );
      await client.query(
        `INSERT INTO public.user_session_tokens
           (id, organization_id, session_id, token_hash, sequence_number, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          initialToken.id,
          initialToken.organizationId,
          initialToken.sessionId,
          initialToken.tokenHash,
          initialToken.sequenceNumber,
          initialToken.expiresAt,
        ],
      );
    });
  }

  async getSession(organizationId: string, sessionId: string): Promise<StoredSession | null> {
    return this.pg.withTenantTx(organizationId, async (client) => {
      const { rows } = await client.query(
        `SELECT * FROM public.user_sessions WHERE organization_id = $1 AND id = $2`,
        [organizationId, sessionId],
      );
      return rows[0] ? mapSession(rows[0]) : null;
    });
  }

  async getTokenByHash(tokenHash: string): Promise<StoredToken | null> {
    return this.pg.withAppClient(async (client) => {
      const { rows } = await client.query(`SELECT * FROM dcmp_security.lookup_token_by_hash($1)`, [
        tokenHash,
      ]);
      return rows[0] ? mapToken(rows[0]) : null;
    });
  }

  async findIdempotency(
    organizationId: string,
    sessionId: string,
    fingerprint: string,
  ): Promise<IdempotencyRecord | null> {
    return this.pg.withTenantTx(organizationId, async (client) => {
      return this.findIdempotencyOnClient(client, organizationId, sessionId, fingerprint);
    });
  }

  private async findIdempotencyOnClient(
    client: PoolClient,
    organizationId: string,
    sessionId: string,
    fingerprint: string,
  ): Promise<IdempotencyRecord | null> {
    const { rows } = await client.query(
      `SELECT * FROM public.refresh_idempotency_records
       WHERE organization_id = $1 AND session_id = $2 AND request_fingerprint = $3
         AND invalidated_at IS NULL AND expires_at > clock_timestamp()
       FOR SHARE`,
      [organizationId, sessionId, fingerprint],
    );
    return rows[0] ? mapIdem(rows[0]) : null;
  }

  async rotateRefresh(input: {
    organizationId: string;
    sessionId: string;
    presentedTokenHash: string;
    newToken: StoredToken;
    idempotency: IdempotencyRecord;
  }): Promise<'ROTATED' | 'RECOVERED' | 'TOKEN_REUSE'> {
    return this.pg.withTenantTx(input.organizationId, async (client) => {
      const existing = await this.findIdempotencyOnClient(
        client,
        input.organizationId,
        input.sessionId,
        input.idempotency.requestFingerprint,
      );
      if (existing) return 'RECOVERED';

      const sess = await client.query(
        `SELECT is_active FROM public.user_sessions
         WHERE organization_id = $1 AND id = $2 FOR SHARE`,
        [input.organizationId, input.sessionId],
      );
      if (!sess.rows[0]?.is_active) return 'TOKEN_REUSE';

      // Defer FK until both old.replaced_by and new token exist
      await client.query(`SET CONSTRAINTS fk_token_replaced_by DEFERRED`);

      const consumed = await client.query(
        `UPDATE public.user_session_tokens
         SET consumed_at = clock_timestamp(),
             replaced_by_token_id = $1
         WHERE organization_id = $2
           AND session_id = $3
           AND token_hash = $4
           AND consumed_at IS NULL
           AND revoked_at IS NULL
         RETURNING id, sequence_number`,
        [input.newToken.id, input.organizationId, input.sessionId, input.presentedTokenHash],
      );

      if (consumed.rowCount === 0) {
        const race = await this.findIdempotencyOnClient(
          client,
          input.organizationId,
          input.sessionId,
          input.idempotency.requestFingerprint,
        );
        if (race) return 'RECOVERED';

        await client.query(
          `UPDATE public.user_sessions
           SET is_active = false, revoked_at = clock_timestamp()
           WHERE organization_id = $1 AND id = $2 AND is_active = true`,
          [input.organizationId, input.sessionId],
        );
        await client.query(`SELECT public.invalidate_refresh_idempotency($1, $2)`, [
          input.organizationId,
          input.sessionId,
        ]);
        return 'TOKEN_REUSE';
      }

      await client.query(
        `INSERT INTO public.user_session_tokens
           (id, organization_id, session_id, token_hash, sequence_number, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          input.newToken.id,
          input.newToken.organizationId,
          input.newToken.sessionId,
          input.newToken.tokenHash,
          input.newToken.sequenceNumber,
          input.newToken.expiresAt,
        ],
      );

      const idem = input.idempotency;
      const ins = await client.query(
        `INSERT INTO public.refresh_idempotency_records (
           organization_id, session_id, request_fingerprint, presented_token_hash,
           issued_token_id, response_ciphertext, response_iv, response_auth_tag,
           encryption_key_id, dpop_jkt, expires_at, encrypted_data_key
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
         ON CONFLICT (organization_id, session_id, request_fingerprint) DO NOTHING
         RETURNING issued_token_id`,
        [
          idem.organizationId,
          idem.sessionId,
          idem.requestFingerprint,
          idem.presentedTokenHash,
          idem.issuedTokenId,
          idem.responseCiphertext,
          idem.responseIv,
          idem.responseAuthTag,
          idem.encryptionKeyId,
          idem.dpopJkt,
          idem.expiresAt,
          idem.encryptedDataKey ?? null,
        ],
      );

      if (ins.rowCount === 0) return 'RECOVERED';
      return 'ROTATED';
    });
  }

  async revokeSession(organizationId: string, sessionId: string): Promise<void> {
    await this.pg.withTenantTx(organizationId, async (client) => {
      await client.query(
        `UPDATE public.user_sessions
         SET is_active = false, revoked_at = clock_timestamp()
         WHERE organization_id = $1 AND id = $2`,
        [organizationId, sessionId],
      );
      await client.query(`SELECT public.invalidate_refresh_idempotency($1, $2)`, [
        organizationId,
        sessionId,
      ]);
    });
  }

  async invalidateIdempotency(organizationId: string, sessionId: string): Promise<void> {
    await this.pg.withTenantTx(organizationId, async (client) => {
      await client.query(`SELECT public.invalidate_refresh_idempotency($1, $2)`, [
        organizationId,
        sessionId,
      ]);
    });
  }
}
