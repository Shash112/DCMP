import { createHash } from 'crypto';
import {
  calculateJwkThumbprint,
  CompactSign,
  exportJWK,
  generateKeyPair,
  importJWK,
  jwtVerify,
  type CryptoKey,
  type JWK,
  type JWTPayload,
} from 'jose';
import { AuthErrors } from '../errors/auth.errors';
import { buildExpectedHtu, methodsEqual, normalizeHtuFromAbsolute } from './dpop.uri';

const ALLOWED_ALGS = new Set(['ES256']);
const PRIVATE_JWK_FIELDS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

export interface DpopValidationInput {
  dpopHeader: string | undefined;
  method: string;
  originalUrl: string;
  protocol: string;
  hostHeader: string;
  publicOrigin?: string;
  forwardedHost?: string;
  forwardedProto?: string;
  /** Required when presenting an access token to a protected resource */
  accessToken?: string;
  /** Expected bound jkt from session (refresh/login binding check) */
  expectedJkt?: string;
  /** Max age of iat in seconds */
  maxAgeSeconds?: number;
  /** Allowed future clock skew for iat */
  futureSkewSeconds?: number;
  nowSeconds?: number;
}

export interface ValidatedDpopProof {
  jti: string;
  htm: string;
  htu: string;
  iat: number;
  nonce?: string;
  jkt: string;
  jwk: JWK;
  sigHash: string;
  ignoredForwardedHeaders: boolean;
}

function rejectPrivateMaterial(jwk: JWK): void {
  for (const field of PRIVATE_JWK_FIELDS) {
    if (
      Object.prototype.hasOwnProperty.call(jwk, field) &&
      (jwk as Record<string, unknown>)[field] != null
    ) {
      throw AuthErrors.dpopFailed('DPoP jwk must not contain private key material');
    }
  }
}

function athOf(accessToken: string): string {
  return createHash('sha256').update(accessToken, 'ascii').digest('base64url');
}

export async function validateDpopProof(input: DpopValidationInput): Promise<ValidatedDpopProof> {
  if (!input.dpopHeader || typeof input.dpopHeader !== 'string') {
    throw AuthErrors.dpopFailed('Missing DPoP header');
  }
  if (input.dpopHeader.includes(',')) {
    throw AuthErrors.dpopFailed('Multiple DPoP header values are not allowed');
  }

  const parts = input.dpopHeader.split('.');
  if (parts.length !== 3) {
    throw AuthErrors.dpopFailed('DPoP proof is not a compact JWT');
  }

  let header: Record<string, unknown>;
  try {
    header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')) as Record<
      string,
      unknown
    >;
  } catch {
    throw AuthErrors.dpopFailed('Malformed DPoP protected header');
  }

  if (header.typ !== 'dpop+jwt') {
    throw AuthErrors.dpopClaims('DPoP typ must be dpop+jwt');
  }
  const alg = String(header.alg || '');
  if (alg === 'none' || !ALLOWED_ALGS.has(alg)) {
    throw AuthErrors.dpopFailed(`Unsupported or forbidden DPoP alg: ${alg || '(missing)'}`);
  }
  if (!header.jwk || typeof header.jwk !== 'object') {
    throw AuthErrors.dpopFailed('DPoP header must include public jwk');
  }
  const jwk = header.jwk as JWK;
  rejectPrivateMaterial(jwk);
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256') {
    throw AuthErrors.dpopFailed('Only EC P-256 JWKs are accepted');
  }

  let payload: JWTPayload;
  try {
    const key = await importJWK(jwk, alg);
    const verified = await jwtVerify(input.dpopHeader, key, {
      typ: 'dpop+jwt',
      algorithms: ['ES256'],
      maxTokenAge: `${input.maxAgeSeconds ?? 120}s`,
      clockTolerance: input.futureSkewSeconds ?? 5,
      currentDate: input.nowSeconds != null ? new Date(input.nowSeconds * 1000) : undefined,
    });
    payload = verified.payload;
  } catch (err) {
    const msg = err instanceof Error ? err.message : 'signature verification failed';
    if (/exp|iat|age|timestamp|current too/i.test(msg)) {
      throw AuthErrors.dpopExpired();
    }
    throw AuthErrors.dpopFailed(`DPoP signature or time validation failed`);
  }

  const jti = payload.jti;
  const htm = payload.htm as string | undefined;
  const htu = payload.htu as string | undefined;
  const iat = payload.iat;
  if (!jti || typeof jti !== 'string') throw AuthErrors.dpopClaims('Missing jti');
  if (!htm || typeof htm !== 'string') throw AuthErrors.dpopClaims('Missing htm');
  if (!htu || typeof htu !== 'string') throw AuthErrors.dpopClaims('Missing htu');
  if (typeof iat !== 'number') throw AuthErrors.dpopClaims('Missing iat');

  if (!methodsEqual(htm, input.method)) {
    throw AuthErrors.dpopClaims('htm does not match HTTP method');
  }

  let normalizedProofHtu: string;
  try {
    normalizedProofHtu = normalizeHtuFromAbsolute(htu);
  } catch {
    throw AuthErrors.dpopClaims('htu is not a valid absolute URI without query/fragment');
  }

  const expected = buildExpectedHtu({
    method: input.method,
    originalUrl: input.originalUrl,
    protocol: input.protocol,
    hostHeader: input.hostHeader,
    publicOrigin: input.publicOrigin,
    forwardedHost: input.forwardedHost,
    forwardedProto: input.forwardedProto,
  });

  if (normalizedProofHtu !== expected.htu) {
    throw AuthErrors.dpopClaims('htu does not match request URI');
  }

  if (input.accessToken) {
    const ath = payload.ath as string | undefined;
    if (!ath || ath !== athOf(input.accessToken)) {
      throw AuthErrors.dpopClaims('ath access-token hash mismatch');
    }
  }

  const jkt = await calculateJwkThumbprint(jwk, 'sha256');
  if (input.expectedJkt && input.expectedJkt !== jkt) {
    throw AuthErrors.dpopFailed('DPoP key thumbprint does not match bound session key');
  }

  const sigHash = createHash('sha256').update(parts[2], 'utf8').digest('hex');

  return {
    jti,
    htm: htm.toUpperCase(),
    htu: normalizedProofHtu,
    iat,
    nonce: typeof payload.nonce === 'string' ? payload.nonce : undefined,
    jkt,
    jwk,
    sigHash,
    ignoredForwardedHeaders: expected.ignoredForwardedHeaders,
  };
}

/** Test helper: mint a valid ES256 DPoP proof */
export async function mintTestDpopProof(opts: {
  method: string;
  htu: string;
  nonce?: string;
  jti?: string;
  iat?: number;
  accessToken?: string;
  privateJwk?: JWK;
}): Promise<{ proof: string; jkt: string; privateJwk: JWK; publicJwk: JWK }> {
  let privateJwk: JWK;
  let publicJwk: JWK;
  let privateKey: CryptoKey | Uint8Array;

  if (opts.privateJwk) {
    privateJwk = opts.privateJwk;
    publicJwk = Object.fromEntries(
      Object.entries(opts.privateJwk).filter(([k]) => !PRIVATE_JWK_FIELDS.includes(k)),
    ) as JWK;
    publicJwk.alg = 'ES256';
    privateKey = await importJWK(privateJwk, 'ES256');
  } else {
    const pair = await generateKeyPair('ES256', { extractable: true });
    privateJwk = await exportJWK(pair.privateKey);
    publicJwk = await exportJWK(pair.publicKey);
    publicJwk.alg = 'ES256';
    delete (publicJwk as { d?: string }).d;
    privateKey = pair.privateKey;
  }

  const jkt = await calculateJwkThumbprint(publicJwk, 'sha256');

  const payload: Record<string, unknown> = {
    jti: opts.jti || cryptoRandomUuid(),
    htm: opts.method.toUpperCase(),
    htu: opts.htu,
    iat: opts.iat ?? Math.floor(Date.now() / 1000),
  };
  if (opts.nonce) payload.nonce = opts.nonce;
  if (opts.accessToken) payload.ath = athOf(opts.accessToken);

  const proof = await new CompactSign(Buffer.from(JSON.stringify(payload)))
    .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: publicJwk })
    .sign(privateKey);

  return { proof, jkt, privateJwk, publicJwk };
}

function cryptoRandomUuid(): string {
  return globalThis.crypto.randomUUID();
}

export { athOf };
