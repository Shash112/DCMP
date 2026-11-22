import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'crypto';
import { Inject, Injectable, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { decodeProtectedHeader, importJWK, SignJWT, jwtVerify, type JWK } from 'jose';
import { ERROR_CODES } from '@dcmp/api-contracts';
import { AuthTokens, AuthUser, LoginResponseData } from '@dcmp/shared-types';
import { AuthAuditService } from './audit/auth-audit.service';
import {
  ACCESS_TOKEN_SIGNING_KEY_PROVIDER,
  AccessTokenSigningKeyProvider,
} from './crypto/access-token-key.provider';
import { RefreshResponseCipher } from './crypto/refresh-response-cipher';
import { fingerprintRetryKey, buildRetryKeyCanonical } from './crypto/retry-key';
import { validateDpopProof, ValidatedDpopProof } from './dpop/dpop.validator';
import { AuthErrors, AuthHttpException } from './errors/auth.errors';
import {
  AUTH_STORE,
  AuthStore,
  IdempotencyRecord,
  StoredToken,
  StoredUser,
} from './persistence/auth-store.port';
import { AUTH_REDIS, AuthRedisPort } from './redis/redis.port';

export interface RequestBinding {
  method: string;
  originalUrl: string;
  protocol: string;
  hostHeader: string;
  publicOrigin?: string;
  forwardedHost?: string;
  forwardedProto?: string;
  dpopHeader?: string;
}

@Injectable()
export class AuthService {
  private readonly refreshPepper: string;
  private readonly accessIssuer: string;
  private readonly accessAudience: string;

  constructor(
    @Inject(AUTH_STORE) private readonly store: AuthStore,
    @Inject(AUTH_REDIS) private readonly redis: AuthRedisPort,
    private readonly cipher: RefreshResponseCipher,
    private readonly audit: AuthAuditService,
    @Inject(ACCESS_TOKEN_SIGNING_KEY_PROVIDER)
    private readonly accessKeys: AccessTokenSigningKeyProvider,
    @Optional() private readonly config?: ConfigService,
  ) {
    this.refreshPepper =
      this.config?.get<string>('jwt.refreshSecret') ||
      process.env.JWT_REFRESH_SECRET ||
      'dev';
    this.accessIssuer =
      process.env.DCMP_ACCESS_TOKEN_ISSUER ||
      this.config?.get<string>('auth.accessTokenIssuer') ||
      'https://auth.dcmp.local';
    this.accessAudience =
      process.env.DCMP_ACCESS_TOKEN_AUDIENCE ||
      this.config?.get<string>('auth.accessTokenAudience') ||
      'dcmp-api';
  }

  /** Test/bootstrap helper — works for Memory and Postgres AuthStore */
  async seedTestUser(input: {
    organizationId: string;
    email: string;
    password: string;
    displayName?: string;
    userId?: string;
  }): Promise<StoredUser> {
    const user: StoredUser = {
      id: input.userId || crypto.randomUUID(),
      organizationId: input.organizationId,
      email: input.email,
      passwordHash: this.hashPassword(input.password),
      displayName: input.displayName || 'Test User',
      isActive: true,
      roles: ['inspector'],
    };
    await this.store.upsertUser(user);
    return user;
  }

  async login(dto: { email: string; password: string; organizationId?: string }, binding: RequestBinding): Promise<{
    data: LoginResponseData;
    dpopNonce: string;
  }> {
    const proof = await this.validateProof(binding);
    const lookup = await this.store.findUserForLogin(dto.email, dto.organizationId);
    if (lookup.status === 'ambiguous') {
      throw AuthErrors.loginOrganizationRequired();
    }
    const user = lookup.status === 'found' ? lookup.user : null;
    if (!user || !user.isActive || !this.verifyPassword(dto.password, user.passwordHash)) {
      this.audit.record({
        category: 'AUTH_FAILURE',
        severity: 'MEDIUM',
        detail: 'login_invalid_credentials',
      });
      throw AuthErrors.unauthenticated('Invalid credentials');
    }

    // Client-supplied organizationId cannot escalate into another tenant
    if (dto.organizationId && dto.organizationId !== user.organizationId) {
      throw AuthErrors.tenantMismatch();
    }

    await this.enforceNonceAndJti(proof, user.id, { allowMissingNonce: true });

    const sessionId = crypto.randomUUID();
    const tokenId = crypto.randomUUID();
    const rawRefresh = this.mintRefreshOpaque();
    const tokenHash = this.hashRefresh(rawRefresh);
    const expiresAt = new Date(Date.now() + 7 * 24 * 3600 * 1000);

    await this.store.createSession(
      {
        id: sessionId,
        organizationId: user.organizationId,
        userId: user.id,
        dpopJkt: proof.jkt,
        isActive: true,
        expiresAt,
      },
      {
        id: tokenId,
        organizationId: user.organizationId,
        sessionId,
        tokenHash,
        sequenceNumber: 1,
        expiresAt,
      },
    );

    const accessToken = await this.signAccess(user, sessionId, proof.jkt);
    const nextNonce = await this.rotateNonce(sessionId);

    this.audit.record({
      category: 'AUTH_SUCCESS',
      severity: 'LOW',
      organizationId: user.organizationId,
      sessionId,
      actorId: user.id,
      detail: 'login_success',
    });

    return {
      dpopNonce: nextNonce,
      data: {
        user: this.toAuthUser(user),
        tokens: {
          accessToken,
          refreshToken: rawRefresh,
          expiresIn: 900,
          tokenType: 'DPoP',
        },
      },
    };
  }

  async refresh(
    refreshToken: string,
    binding: RequestBinding,
    clientOrgHeader?: string,
  ): Promise<{ tokens: AuthTokens; dpopNonce: string }> {
    // 1–3: DPoP cryptographic validation first (invalid proof never recovers)
    let proof: ValidatedDpopProof;
    try {
      proof = await this.validateProof(binding);
    } catch (e) {
      this.audit.record({ category: 'DPOP_FAILURE', severity: 'HIGH', detail: 'refresh_dpop_failed' });
      throw e;
    }

    const presentedHash = this.hashRefresh(refreshToken);
    const presented = await this.store.getTokenByHash(presentedHash);
    if (!presented) {
      throw AuthErrors.unauthenticated('Unknown refresh token');
    }

    const session = await this.store.getSession(presented.organizationId, presented.sessionId);
    if (!session) {
      throw AuthErrors.unauthenticated('Session not found');
    }

    // Tenant isolation: ignore/deny client org spoof
    if (clientOrgHeader && clientOrgHeader !== session.organizationId) {
      throw AuthErrors.tenantMismatch();
    }

    if (proof.jkt !== session.dpopJkt) {
      this.audit.record({
        category: 'DPOP_FAILURE',
        severity: 'HIGH',
        organizationId: session.organizationId,
        sessionId: session.id,
        detail: 'jkt_mismatch',
      });
      throw AuthErrors.dpopFailed('DPoP key thumbprint does not match bound session key');
    }

    if (!session.isActive) {
      throw AuthErrors.sessionRevoked();
    }

    const nonceForFingerprint = proof.nonce || '';
    const canonical = buildRetryKeyCanonical({
      sessionId: session.id,
      tokenHash: presentedHash,
      proofJti: proof.jti,
      proofNonce: nonceForFingerprint,
      sigHash: proof.sigHash,
      htm: proof.htm,
      htu: proof.htu,
    });
    const fingerprint = fingerprintRetryKey(canonical);

    // 5: Idempotency lookup BEFORE consuming jti (Phase 2.1.9/12 retry-aware order)
    const existing = await this.store.findIdempotency(
      session.organizationId,
      session.id,
      fingerprint,
    );
    if (existing) {
      return this.decryptRecoveredTokens(existing, proof, presentedHash, session.id);
    }

    // Optional Redis cache (non-authoritative) — still require active session (already checked)
    try {
      if (this.redis.isAvailable()) {
        const cached = await this.redis.get(`auth:retry:${fingerprint}`);
        if (cached) {
          // DB already confirmed active; do not trust cache alone for revocation
          const parsed = JSON.parse(cached) as AuthTokens & { expiresIn: number };
          const nextNonce = await this.peekOrRotateNonce(session.id);
          return { dpopNonce: nextNonce, tokens: parsed };
        }
      }
    } catch {
      // Redis miss/outage: continue with PG path
    }

    // 6: Nonce + JTI replay for non-recovery path.
    // Concurrent identical proofs may lose the JTI race after a peer already committed
    // durable idempotency — re-check PostgreSQL before treating as replay.
    try {
      await this.enforceNonceAndJti(proof, session.id, { allowMissingNonce: false });
    } catch (e) {
      if (e instanceof AuthHttpException && e.getStatus() === 401) {
        const body = e.getResponse();
        const code =
          typeof body === 'object' && body && 'code' in body
            ? String((body as { code: string }).code)
            : '';
        if (code === ERROR_CODES.DPOP_PROOF_REPLAY_DETECTED) {
          const raced = await this.waitForIdempotency(
            session.organizationId,
            session.id,
            fingerprint,
          );
          if (raced) {
            return this.decryptRecoveredTokens(raced, proof, presentedHash, session.id);
          }
        }
      }
      throw e;
    }

    if (presented.consumedAt || presented.revokedAt) {
      await this.store.revokeSession(session.organizationId, session.id);
      this.audit.record({
        category: 'TOKEN_REUSE',
        severity: 'CRITICAL',
        organizationId: session.organizationId,
        sessionId: session.id,
        detail: 'hard_reuse',
      });
      throw AuthErrors.tokenReuse();
    }

    // 7–10: Rotate + encrypt + persist idempotency
    const newTokenId = crypto.randomUUID();
    const newRefresh = this.mintRefreshOpaque();
    const newHash = this.hashRefresh(newRefresh);
    const user = await this.store.findUserById(session.organizationId, session.userId);
    if (!user || !user.isActive) throw AuthErrors.unauthenticated();

    const accessToken = await this.signAccess(user, session.id, session.dpopJkt);
    const tokenPayload = {
      accessToken,
      refreshToken: newRefresh,
      expiresIn: 900,
      tokenType: 'DPoP' as const,
    };

    const expiresAt = new Date(Date.now() + 60_000);
    let encrypted;
    try {
      encrypted = await this.cipher.encrypt(tokenPayload, {
        organizationId: session.organizationId,
        sessionId: session.id,
        requestFingerprint: fingerprint,
        presentedTokenHash: presentedHash,
        issuedTokenId: newTokenId,
        dpopJkt: proof.jkt,
        expiresAt,
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : '';
      if (msg.startsWith('KMS_UNAVAILABLE')) {
        // Encrypt runs before rotateRefresh — no idempotency row / no token consume.
        throw AuthErrors.cryptoUnavailable('Refresh envelope KMS unavailable');
      }
      throw e;
    }

    const newToken: StoredToken = {
      id: newTokenId,
      organizationId: session.organizationId,
      sessionId: session.id,
      tokenHash: newHash,
      sequenceNumber: presented.sequenceNumber + 1,
      expiresAt: new Date(Date.now() + 7 * 24 * 3600 * 1000),
    };

    const outcome = await this.store.rotateRefresh({
      organizationId: session.organizationId,
      sessionId: session.id,
      presentedTokenHash: presentedHash,
      newToken,
      idempotency: {
        organizationId: session.organizationId,
        sessionId: session.id,
        requestFingerprint: fingerprint,
        presentedTokenHash: presentedHash,
        issuedTokenId: newTokenId,
        responseCiphertext: encrypted.ciphertext,
        responseIv: encrypted.iv,
        responseAuthTag: encrypted.authTag,
        encryptionKeyId: encrypted.encryptionKeyId,
        encryptedDataKey: encrypted.encryptedDataKey,
        dpopJkt: proof.jkt,
        expiresAt,
      },
    });

    if (outcome === 'TOKEN_REUSE') {
      await this.store.revokeSession(session.organizationId, session.id);
      this.audit.record({
        category: 'TOKEN_REUSE',
        severity: 'CRITICAL',
        organizationId: session.organizationId,
        sessionId: session.id,
        detail: 'concurrent_or_divergent_reuse',
      });
      throw AuthErrors.tokenReuse();
    }

    if (outcome === 'RECOVERED') {
      const row = await this.store.findIdempotency(
        session.organizationId,
        session.id,
        fingerprint,
      );
      if (!row) throw AuthErrors.unauthenticated('Idempotency recovery failed');
      return this.decryptRecoveredTokens(row, proof, presentedHash, session.id);
    }

    // 11: Best-effort Redis cache
    try {
      if (this.redis.isAvailable()) {
        await this.redis.set(`auth:retry:${fingerprint}`, JSON.stringify(tokenPayload), 30);
      }
    } catch {
      // non-authoritative
    }

    const nextNonce = await this.rotateNonce(session.id);
    this.audit.record({
      category: 'AUTH_SUCCESS',
      severity: 'LOW',
      organizationId: session.organizationId,
      sessionId: session.id,
      actorId: session.userId,
      detail: 'refresh_rotated',
    });

    return { dpopNonce: nextNonce, tokens: tokenPayload };
  }

  async logout(refreshToken: string | undefined, binding: RequestBinding): Promise<void> {
    const proof = await this.validateProof(binding);
    if (!refreshToken) throw AuthErrors.unauthenticated('refreshToken required');
    const hash = this.hashRefresh(refreshToken);
    const token = await this.store.getTokenByHash(hash);
    if (!token) return;
    const session = await this.store.getSession(token.organizationId, token.sessionId);
    if (!session) return;
    if (proof.jkt !== session.dpopJkt) throw AuthErrors.dpopFailed();
    await this.store.revokeSession(session.organizationId, session.id);
    try {
      if (this.redis.isAvailable()) {
        await this.redis.del(`auth:dpop_nonce:${session.id}`);
      }
    } catch {
      /* ignore */
    }
    this.audit.record({
      category: 'LOGOUT',
      severity: 'LOW',
      organizationId: session.organizationId,
      sessionId: session.id,
      actorId: session.userId,
      detail: 'logout',
    });
  }

  async sessionStatus(refreshToken: string): Promise<{ active: boolean; sessionId?: string; organizationId?: string }> {
    const hash = this.hashRefresh(refreshToken);
    const token = await this.store.getTokenByHash(hash);
    if (!token) return { active: false };
    const session = await this.store.getSession(token.organizationId, token.sessionId);
    return {
      active: Boolean(session?.isActive),
      sessionId: session?.id,
      organizationId: session?.organizationId,
    };
  }

  async revokeSession(organizationId: string, sessionId: string): Promise<void> {
    await this.store.revokeSession(organizationId, sessionId);
    this.audit.record({
      category: 'SESSION_REVOCATION',
      severity: 'HIGH',
      organizationId,
      sessionId,
      detail: 'admin_or_system_revoke',
    });
  }

  private async decryptRecoveredTokens(
    row: IdempotencyRecord,
    proof: ValidatedDpopProof,
    presentedHash: string,
    sessionId: string,
  ): Promise<{ tokens: AuthTokens; dpopNonce: string }> {
    if (row.dpopJkt !== proof.jkt) {
      throw AuthErrors.dpopFailed('Idempotency recovery jkt mismatch');
    }
    const payload = await this.cipher.decrypt(
      {
        ciphertext: row.responseCiphertext,
        iv: row.responseIv,
        authTag: row.responseAuthTag,
        encryptionKeyId: row.encryptionKeyId,
        encryptedDataKey: row.encryptedDataKey,
        expiresAt: row.expiresAt.toISOString(),
      },
      {
        organizationId: row.organizationId,
        sessionId: row.sessionId,
        requestFingerprint: row.requestFingerprint,
        presentedTokenHash: presentedHash,
        issuedTokenId: row.issuedTokenId,
        dpopJkt: proof.jkt,
        expiresAt: row.expiresAt.toISOString(),
      },
    );
    const nextNonce = await this.peekOrRotateNonce(sessionId);
    return {
      dpopNonce: nextNonce,
      tokens: {
        accessToken: String(payload.accessToken),
        refreshToken: String(payload.refreshToken),
        expiresIn: Number(payload.expiresIn || 900),
        tokenType: 'DPoP',
      },
    };
  }

  /** Brief poll for peer commit when concurrent identical proofs race the JTI gate. */
  private async waitForIdempotency(
    organizationId: string,
    sessionId: string,
    fingerprint: string,
  ): Promise<IdempotencyRecord | null> {
    for (let i = 0; i < 8; i++) {
      const row = await this.store.findIdempotency(organizationId, sessionId, fingerprint);
      if (row) return row;
      await new Promise((r) => setTimeout(r, 25));
    }
    return null;
  }

  private async validateProof(binding: RequestBinding): Promise<ValidatedDpopProof> {
    return validateDpopProof({
      dpopHeader: binding.dpopHeader,
      method: binding.method,
      originalUrl: binding.originalUrl,
      protocol: binding.protocol,
      hostHeader: binding.hostHeader,
      publicOrigin:
        binding.publicOrigin ||
        this.config?.get<string>('auth.publicOrigin') ||
        process.env.DCMP_PUBLIC_ORIGIN,
      forwardedHost: binding.forwardedHost,
      forwardedProto: binding.forwardedProto,
    });
  }

  /**
   * Fail-closed JTI admission when Redis is down for NEW proofs.
   * Identical-proof recovery must happen before this is called.
   */
  private async enforceNonceAndJti(
    proof: ValidatedDpopProof,
    sessionOrUserKey: string,
    opts: { allowMissingNonce: boolean },
  ): Promise<void> {
    if (!this.redis.isAvailable()) {
      throw AuthErrors.replayStoreUnavailable();
    }

    try {
      if (!opts.allowMissingNonce) {
        const active = await this.redis.get(`auth:dpop_nonce:${sessionOrUserKey}`);
        if (!proof.nonce || !active || proof.nonce !== active) {
          const next = await this.rotateNonce(sessionOrUserKey);
          throw AuthErrors.useNonce(next);
        }
      } else if (proof.nonce) {
        const active = await this.redis.get(`auth:dpop_nonce:${sessionOrUserKey}`);
        if (active && proof.nonce !== active) {
          const next = await this.rotateNonce(sessionOrUserKey);
          throw AuthErrors.useNonce(next);
        }
      }

      const ok = await this.redis.setNx(`auth:dpop_jti:${proof.jti}`, '1', 120);
      if (!ok) throw AuthErrors.dpopReplay();
    } catch (e) {
      if (e instanceof Error && e.message === 'REDIS_UNAVAILABLE') {
        throw AuthErrors.replayStoreUnavailable();
      }
      throw e;
    }
  }

  private async rotateNonce(sessionId: string): Promise<string> {
    const nonce = randomBytes(16).toString('base64url');
    if (!this.redis.isAvailable()) {
      // Login after outage: still need a nonce value for client; store best-effort
      return nonce;
    }
    await this.redis.set(`auth:dpop_nonce:${sessionId}`, nonce, 300);
    return nonce;
  }

  private async peekOrRotateNonce(sessionId: string): Promise<string> {
    try {
      if (this.redis.isAvailable()) {
        const existing = await this.redis.get(`auth:dpop_nonce:${sessionId}`);
        if (existing) return existing;
      }
    } catch {
      /* fall through */
    }
    return this.rotateNonce(sessionId);
  }

  private async signAccess(
    user: { id: string; email: string; organizationId: string; roles: string[] },
    sessionId: string,
    dpopJkt: string,
  ): Promise<string> {
    const key = await this.accessKeys.getActiveSigningKey();
    const now = Math.floor(Date.now() / 1000);
    const ttlSec = Math.min(
      15 * 60,
      parseExpiresSeconds(
        this.config?.get<string>('jwt.accessExpiresIn') ||
          process.env.JWT_ACCESS_EXPIRES_IN ||
          '15m',
      ),
    );
    const payload = {
      email: user.email,
      orgId: user.organizationId,
      roles: user.roles,
      sid: sessionId,
      type: 'access' as const,
      cnf: { jkt: dpopJkt },
      iss: this.accessIssuer,
      aud: this.accessAudience,
      sub: user.id,
      jti: crypto.randomUUID(),
      iat: now,
      nbf: now,
      exp: now + ttlSec,
    };

    // KMS path: private key never leaves KMS; Sign + DER→JOSE
    if (key.kmsSign || typeof this.accessKeys.signCompactJwt === 'function') {
      if (!this.accessKeys.signCompactJwt) {
        throw new Error('KMS access-token provider missing signCompactJwt');
      }
      try {
        return await this.accessKeys.signCompactJwt(payload);
      } catch (e) {
        const msg = e instanceof Error ? e.message : '';
        if (msg.startsWith('KMS_UNAVAILABLE')) {
          throw AuthErrors.cryptoUnavailable('Access-token KMS signing unavailable');
        }
        throw e;
      }
    }

    if (!key.privateKey) {
      throw new Error('Access-token signing key has no privateKey and no KMS signer');
    }
    return new SignJWT({
      email: user.email,
      orgId: user.organizationId,
      roles: user.roles,
      sid: sessionId,
      type: 'access',
      cnf: { jkt: dpopJkt },
    })
      .setProtectedHeader({ alg: 'ES256', kid: key.kid, typ: 'at+jwt' })
      .setIssuer(this.accessIssuer)
      .setAudience(this.accessAudience)
      .setSubject(user.id)
      .setJti(payload.jti)
      .setIssuedAt(now)
      .setNotBefore(now)
      .setExpirationTime(now + ttlSec)
      .sign(key.privateKey);
  }

  /**
   * Cryptographic access-token verification (ES256 + iss/aud/cnf).
   * Does not perform session introspection — use authorizeProtectedResource.
   */
  async verifyAccessTokenClaims(token: string): Promise<{
    sub: string;
    orgId: string;
    sid: string;
    jkt: string;
    jti: string;
    email?: string;
    roles: string[];
  }> {
    let header: { alg?: string; kid?: string };
    try {
      header = decodeProtectedHeader(token);
    } catch {
      throw AuthErrors.accessTokenInvalid('Malformed access token');
    }
    if (header.alg !== 'ES256') {
      throw AuthErrors.accessTokenInvalid('Access token alg must be ES256');
    }
    if (!header.kid) throw AuthErrors.accessTokenInvalid('Missing kid');
    const key = await this.accessKeys.getVerificationKey(header.kid);
    if (!key) throw AuthErrors.accessTokenInvalid('Unknown or retired kid');

    let payload;
    try {
      const publicKey = await importJWK(key.publicJwk, 'ES256');
      const verified = await jwtVerify(token, publicKey, {
        algorithms: ['ES256'],
        issuer: this.accessIssuer,
        audience: this.accessAudience,
        clockTolerance: 5,
      });
      payload = verified.payload;
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'verify failed';
      if (/exp|expired/i.test(msg)) throw AuthErrors.accessTokenInvalid('Access token expired');
      throw AuthErrors.accessTokenInvalid('Access token signature or claims invalid');
    }

    if (payload.type !== 'access') throw AuthErrors.accessTokenInvalid('Invalid token type');
    const cnf = payload.cnf as { jkt?: string } | undefined;
    if (!cnf?.jkt) throw AuthErrors.accessTokenInvalid('Missing cnf.jkt');
    return {
      sub: String(payload.sub),
      orgId: String(payload.orgId),
      sid: String(payload.sid),
      jkt: cnf.jkt,
      jti: String(payload.jti || ''),
      email: payload.email ? String(payload.email) : undefined,
      roles: Array.isArray(payload.roles) ? (payload.roles as string[]) : [],
    };
  }

  /** @deprecated use authorizeProtectedResource — retained name for transitional callers */
  async verifyAccess(token: string): Promise<{ sub: string; orgId: string; sid: string }> {
    const claims = await this.verifyAccessTokenClaims(token);
    return { sub: claims.sub, orgId: claims.orgId, sid: claims.sid };
  }

  /**
   * Full protected-resource authorization: AT + DPoP (+ath) + PG session.
   */
  async authorizeProtectedResource(input: {
    accessToken: string;
    dpopHeader?: string;
    method: string;
    originalUrl: string;
    protocol: string;
    hostHeader: string;
    publicOrigin?: string;
    forwardedHost?: string;
    forwardedProto?: string;
  }): Promise<{ sub: string; orgId: string; sid: string; jkt: string }> {
    const claims = await this.verifyAccessTokenClaims(input.accessToken);

    const proof = await validateDpopProof({
      dpopHeader: input.dpopHeader,
      method: input.method,
      originalUrl: input.originalUrl,
      protocol: input.protocol,
      hostHeader: input.hostHeader,
      publicOrigin: input.publicOrigin || process.env.DCMP_PUBLIC_ORIGIN,
      forwardedHost: input.forwardedHost,
      forwardedProto: input.forwardedProto,
      accessToken: input.accessToken,
      expectedJkt: claims.jkt,
    });

    if (proof.jkt !== claims.jkt) {
      throw AuthErrors.dpopFailed('DPoP jkt does not match access token cnf.jkt');
    }

    await this.enforceNonceAndJti(proof, claims.sid, { allowMissingNonce: true });

    const session = await this.store.getSession(claims.orgId, claims.sid);
    if (!session) throw AuthErrors.sessionRevoked();
    if (!session.isActive || session.revokedAt) throw AuthErrors.sessionRevoked();
    if (session.expiresAt.getTime() <= Date.now()) throw AuthErrors.sessionRevoked();
    if (session.userId !== claims.sub) throw AuthErrors.unauthenticated('Subject mismatch');
    if (session.organizationId !== claims.orgId) throw AuthErrors.tenantMismatch();
    if (session.dpopJkt !== claims.jkt) {
      throw AuthErrors.dpopFailed('Session DPoP binding mismatch');
    }

    return { sub: claims.sub, orgId: claims.orgId, sid: claims.sid, jkt: claims.jkt };
  }

  async getJwks(): Promise<{ keys: JWK[] }> {
    const keys = await this.accessKeys.listVerificationJwks();
    return { keys };
  }

  private mintRefreshOpaque(): string {
    return randomBytes(32).toString('base64url');
  }

  private hashRefresh(raw: string): string {
    return createHash('sha256').update(`${this.refreshPepper}:${raw}`, 'utf8').digest('hex');
  }

  private hashPassword(password: string): string {
    const salt = randomBytes(16).toString('hex');
    const hash = scryptSync(password, salt, 32).toString('hex');
    return `scrypt$${salt}$${hash}`;
  }

  private verifyPassword(password: string, stored: string): boolean {
    const [algo, salt, hash] = stored.split('$');
    if (algo !== 'scrypt' || !salt || !hash) return false;
    const next = scryptSync(password, salt, 32).toString('hex');
    try {
      return timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(next, 'hex'));
    } catch {
      return false;
    }
  }

  private toAuthUser(user: {
    id: string;
    organizationId: string;
    email: string;
    displayName: string;
    isActive: boolean;
    roles: string[];
  }): AuthUser {
    const [firstName, ...rest] = user.displayName.split(' ');
    return {
      id: user.id,
      organizationId: user.organizationId,
      email: user.email,
      firstName: firstName || user.displayName,
      lastName: rest.join(' ') || '',
      isActive: user.isActive,
      isPlatformAdmin: false,
      roles: user.roles,
      permissions: [],
    };
  }
}

function parseExpiresSeconds(spec: string): number {
  const m = /^(\d+)([smhd])?$/.exec(spec.trim());
  if (!m) return 900;
  const n = parseInt(m[1], 10);
  const unit = m[2] || 's';
  switch (unit) {
    case 's':
      return n;
    case 'm':
      return n * 60;
    case 'h':
      return n * 3600;
    case 'd':
      return n * 86400;
    default:
      return 900;
  }
}
