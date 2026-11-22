/**
 * Phase 2.1.25 — strict post-Decrypt wrapping CMK allowlist.
 * Matches exact ARN equality or exact UUID equality (including UUID extracted from ARN).
 * Rejects substring / loose suffix matching.
 */

const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Extract bare key UUID from a key id or key ARN; null if not a recognizable form. */
export function extractKmsKeyUuid(id: string): string | null {
  const s = id.trim();
  if (!s) return null;
  if (UUID_RE.test(s)) return s.toLowerCase();
  const m = s.match(/:key\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i);
  if (m) return m[1].toLowerCase();
  return null;
}

/**
 * True iff `returned` (Decrypt KeyId) is an exact match to one of `allowed`
 * (full string equality) or both resolve to the same key UUID.
 */
export function isAllowedWrappingKeyId(returned: string, allowed: string[]): boolean {
  if (!returned || !returned.trim()) return false;
  const returnedExact = returned.trim();
  const returnedUuid = extractKmsKeyUuid(returnedExact);
  for (const raw of allowed) {
    if (!raw || !String(raw).trim()) continue;
    const allowedExact = String(raw).trim();
    if (returnedExact === allowedExact) return true;
    const allowedUuid = extractKmsKeyUuid(allowedExact);
    if (returnedUuid && allowedUuid && returnedUuid === allowedUuid) return true;
  }
  return false;
}

export function assertWrappingKeyAllowed(returned: string | undefined | null, allowed: string[]): void {
  if (!returned || !String(returned).trim()) {
    throw new Error('KMS_UNAVAILABLE:UnexpectedWrappingKey');
  }
  if (!isAllowedWrappingKeyId(String(returned), allowed)) {
    throw new Error('KMS_UNAVAILABLE:UnexpectedWrappingKey');
  }
}
