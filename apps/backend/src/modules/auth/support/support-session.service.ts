import { Inject, Injectable, Logger } from '@nestjs/common';
import { randomBytes, randomUUID } from 'crypto';
import { ValidationPgPool } from '../persistence/pg.pool';
import { AuthErrors, AuthHttpException } from '../errors/auth.errors';
import { SSA_SIGNING_PROVIDER, SsaSigningProvider } from '../crypto/ssa-signing.provider';

/** @deprecated use LocalSsaSigningProvider — retained for SQL seed helpers */
export const SSA_TEST_KID = process.env.DCMP_SSA_TEST_KID || 'val-key-gateway-1';
export const SSA_TEST_SECRET = Buffer.from(
  process.env.DCMP_SSA_TEST_SECRET || 'validation-secret-key-32bytes!!',
);

export interface SupportAccessRequestResult {
  requestId: string;
  organizationId: string;
  status: string;
}

export interface SupportGrantResult {
  grantId: string;
  requestId: string;
  organizationId: string;
  expiresAt: string;
}

export interface SupportChallengeResult {
  challengeId: string;
  grantId: string;
  organizationId: string;
  expiresAt: string;
}

export interface MintedAssertion {
  assertion: string;
  kid: string;
  expiresAt: number;
  keyMaterial: 'TEST-ONLY' | 'KMS-HMAC';
}

export interface OpenSessionResult {
  opened: boolean;
  organizationId: string;
  grantId: string;
  verifySignature: boolean;
}

/**
 * Application-layer SSA gateway (Phase 2.1.20).
 * Mints HS256 assertions for dcmp_security.open_support_session.
 * Does not create a general platform-admin bypass.
 */
@Injectable()
export class SupportSessionService {
  private readonly logger = new Logger(SupportSessionService.name);

  constructor(
    @Inject(ValidationPgPool) private readonly pg: ValidationPgPool,
    @Inject(SSA_SIGNING_PROVIDER) private readonly ssaSigner: SsaSigningProvider,
  ) {}

  async ensureTestKey(): Promise<void> {
    if (this.ssaSigner.mode !== 'LOCAL_TEST') {
      // KMS HMAC keys are non-exportable — do not seed plaintext into PostgreSQL
      return;
    }
    const client = await this.pg.pool.connect();
    try {
      await client.query(
        `
        INSERT INTO dcmp_security.internal_keys (key_id, key_secret, status, valid_from)
        VALUES ($1, $2, 'ACTIVE', now() - interval '1 minute')
        ON CONFLICT (key_id) DO UPDATE
          SET key_secret = EXCLUDED.key_secret,
              status = 'ACTIVE',
              valid_until = NULL,
              valid_from = EXCLUDED.valid_from
        `,
        [SSA_TEST_KID, SSA_TEST_SECRET],
      );
    } catch (e) {
      try {
        await client.query(
          `
          INSERT INTO dcmp_security.internal_keys (key_id, key_secret, status, valid_from)
          VALUES ($1, $2, 'ACTIVE', now() - interval '1 minute')
          ON CONFLICT (key_id) DO UPDATE
            SET key_secret = EXCLUDED.key_secret, status = 'ACTIVE', valid_until = NULL
          `,
          [SSA_TEST_KID, SSA_TEST_SECRET],
        );
      } catch (e2) {
        this.logger.error(`Failed to seed TEST-ONLY SSA key: ${(e2 as Error).message}`);
        throw e2;
      }
    } finally {
      client.release();
    }
  }

  async createAccessRequest(input: {
    organizationId: string;
    adminId: string;
    ticketId?: string;
  }): Promise<SupportAccessRequestResult> {
    const client = await this.pg.pool.connect();
    const requestId = randomUUID();
    try {
      // Prefer Stage-1 shape (platform_admin_id); also set admin_id when present
      const cols = await client.query(
        `SELECT column_name FROM information_schema.columns
         WHERE table_schema='public' AND table_name='support_access_requests'`,
      );
      const names = new Set(cols.rows.map((r: { column_name: string }) => r.column_name));
      if (names.has('platform_admin_id') && !names.has('ticket_id')) {
        await client.query(
          `INSERT INTO public.support_access_requests (id, organization_id, platform_admin_id, status)
           VALUES ($1,$2,$3,'PENDING')`,
          [requestId, input.organizationId, input.adminId],
        );
      } else if (names.has('ticket_id')) {
        let ticketId = input.ticketId;
        if (!ticketId) {
          ticketId = randomUUID();
          await client.query(
            `INSERT INTO public.support_tickets (id, organization_id, opened_by, ticket_number, subject, status)
             SELECT $1, $2, u.id, $3, 'Support access', 'OPEN'
             FROM public.users u WHERE u.organization_id=$2 LIMIT 1
             ON CONFLICT (id) DO NOTHING`,
            [ticketId, input.organizationId, `T-${ticketId.slice(0, 8)}`],
          );
        }
        await client.query(
          `INSERT INTO public.support_access_requests
             (id, organization_id, ticket_id, admin_id, platform_admin_id, status)
           VALUES ($1,$2,$3,$4,$4,'PENDING')`,
          [requestId, input.organizationId, ticketId, input.adminId],
        );
      } else {
        throw new Error('unsupported support_access_requests schema');
      }
      return { requestId, organizationId: input.organizationId, status: 'PENDING' };
    } finally {
      client.release();
    }
  }

  async approveRequest(input: {
    requestId: string;
    organizationId: string;
    approvedByUserId: string;
    ttlMinutes?: number;
  }): Promise<SupportGrantResult> {
    const client = await this.pg.pool.connect();
    const grantId = randomUUID();
    const ttl = input.ttlMinutes ?? 10;
    try {
      await client.query(
        `UPDATE public.support_access_requests SET status='APPROVED' WHERE id=$1 AND organization_id=$2`,
        [input.requestId, input.organizationId],
      );
      const cols = await client.query(
        `SELECT column_name FROM information_schema.columns
         WHERE table_schema='public' AND table_name='support_access_grants'`,
      );
      const names = new Set(cols.rows.map((r: { column_name: string }) => r.column_name));
      if (names.has('request_id') && !names.has('support_access_request_id')) {
        await client.query(
          `INSERT INTO public.support_access_grants
             (id, request_id, organization_id, status, expires_at)
           VALUES ($1,$2,$3,'ACTIVE', now() + ($4::text || ' minutes')::interval)`,
          [grantId, input.requestId, input.organizationId, String(ttl)],
        );
      } else {
        await client.query(
          `INSERT INTO public.support_access_grants
             (id, organization_id, support_access_request_id, request_id, approved_by_user_id, expires_at)
           VALUES ($1,$2,$3,$3,$4, now() + ($5::text || ' minutes')::interval)`,
          [grantId, input.organizationId, input.requestId, input.approvedByUserId, String(ttl)],
        );
      }
      const exp = await client.query(`SELECT expires_at FROM public.support_access_grants WHERE id=$1`, [
        grantId,
      ]);
      return {
        grantId,
        requestId: input.requestId,
        organizationId: input.organizationId,
        expiresAt: new Date(exp.rows[0].expires_at).toISOString(),
      };
    } finally {
      client.release();
    }
  }

  async issueChallenge(input: {
    organizationId: string;
    grantId: string;
    adminId: string;
    ttlMinutes?: number;
  }): Promise<SupportChallengeResult> {
    await this.ensureTestKey();
    const client = await this.pg.pool.connect();
    const challengeId = randomUUID();
    const ttl = input.ttlMinutes ?? 5;
    try {
      const cols = await client.query(
        `SELECT column_name FROM information_schema.columns
         WHERE table_schema='dcmp_security' AND table_name='support_session_challenges'`,
      );
      const names = new Set(cols.rows.map((r: { column_name: string }) => r.column_name));
      // Full-schema challenges include surrogate `id` + nonce; Stage-1 PK is challenge_id only.
      if (names.has('id') && names.has('nonce')) {
        await client.query(
          `INSERT INTO dcmp_security.support_session_challenges
             (id, challenge_id, admin_id, platform_admin_id, organization_id, grant_id, nonce, expires_at)
           VALUES ($1,$1,$2,$2,$3,$4,$5, now() + ($6::text || ' minutes')::interval)`,
          [
            challengeId,
            input.adminId,
            input.organizationId,
            input.grantId,
            randomBytes(8).toString('hex'),
            String(ttl),
          ],
        );
      } else {
        await client.query(
          `INSERT INTO dcmp_security.support_session_challenges
             (challenge_id, platform_admin_id, organization_id, grant_id, expires_at)
           VALUES ($1,$2,$3,$4, now() + ($5::text || ' minutes')::interval)`,
          [challengeId, input.adminId, input.organizationId, input.grantId, String(ttl)],
        );
      }
      const exp = await client.query(
        `SELECT expires_at FROM dcmp_security.support_session_challenges
         WHERE challenge_id=$1 LIMIT 1`,
        [challengeId],
      );
      return {
        challengeId,
        grantId: input.grantId,
        organizationId: input.organizationId,
        expiresAt: new Date(exp.rows[0].expires_at).toISOString(),
      };
    } finally {
      client.release();
    }
  }

  async mintAssertion(input: {
    adminId: string;
    organizationId: string;
    grantId: string;
    requestId: string;
    ttlSeconds?: number;
  }): Promise<MintedAssertion> {
    return this.ssaSigner.mint(input);
  }

  async openSession(input: {
    assertion: string;
    organizationId: string;
    grantId: string;
    challengeId: string;
  }): Promise<OpenSessionResult> {
    const client = await this.pg.pool.connect();
    try {
      await client.query('BEGIN');
      // Match Phase 2.1.19 SQL harness authorization model
      await client.query('SET SESSION AUTHORIZATION dcmp_platform_admin');

      let ok = false;
      if (this.ssaSigner.mode === 'KMS_HMAC') {
        // Non-exportable KMS HMAC: VerifyMac at gateway, then attested SQL open
        const okMac = await this.ssaSigner.verify(input.assertion);
        if (!okMac) throw AuthErrors.supportDenied('SSA KMS VerifyMac failed');
        await client.query(`SELECT set_config('app.ssa_kms_attested', 'true', true)`);
        await client.query(
          `SELECT dcmp_security.open_support_session_attested($1::text,$2::uuid,$3::uuid,$4::uuid)`,
          [input.assertion, input.organizationId, input.grantId, input.challengeId],
        );
        // Attested open already enforced grant/challenge; confirm as privileged role
        // (dcmp_platform_admin lacks direct SELECT under FORCE RLS).
        await client.query('RESET SESSION AUTHORIZATION');
        const g = await client.query(
          `SELECT EXISTS (
             SELECT 1 FROM public.support_access_grants
             WHERE id=$1::uuid AND organization_id=$2::uuid
               AND revoked_at IS NULL AND expires_at > statement_timestamp()
           ) AS ok`,
          [input.grantId, input.organizationId],
        );
        ok = Boolean(g.rows[0]?.ok);
      } else {
        await client.query(
          `SELECT dcmp_security.open_support_session($1::text,$2::uuid,$3::uuid,$4::uuid)`,
          [input.assertion, input.organizationId, input.grantId, input.challengeId],
        );
        const verify = await client.query(`SELECT dcmp_security.verify_support_signature() AS ok`);
        ok = Boolean(verify.rows[0]?.ok);
      }
      if (!ok) {
        throw new Error('SSA session verification returned false');
      }
      await client.query('COMMIT');
      // Audit after successful open (best-effort; Stage-1 shapes vary)
      try {
        await client.query('RESET SESSION AUTHORIZATION');
        await client.query(
          `INSERT INTO public.security_events (organization_id, category, severity, event_source, details)
           VALUES ($1,'SUPPORT_ACCESS','MEDIUM','GATEWAY',$2::jsonb)`,
          [
            input.organizationId,
            JSON.stringify({
              action: 'open_support_session',
              grantId: input.grantId,
              challengeId: input.challengeId,
            }),
          ],
        );
      } catch {
        /* ignore audit shape mismatch */
      }
      return {
        opened: true,
        organizationId: input.organizationId,
        grantId: input.grantId,
        verifySignature: true,
      };
    } catch (e) {
      try {
        await client.query('ROLLBACK');
      } catch {
        /* ignore */
      }
      if (e instanceof AuthHttpException) throw e;
      throw AuthErrors.supportDenied(`SSA open failed: ${(e as Error).message.split('\n')[0]}`);
    } finally {
      try {
        await client.query('RESET SESSION AUTHORIZATION');
      } catch {
        /* ignore */
      }
      client.release();
    }
  }

  async revokeGrant(grantId: string, organizationId: string): Promise<void> {
    const client = await this.pg.pool.connect();
    try {
      await client.query(
        `UPDATE public.support_access_grants
         SET revoked_at=now(), status='REVOKED'
         WHERE id=$1 AND organization_id=$2`,
        [grantId, organizationId],
      );
    } finally {
      client.release();
    }
  }
}
