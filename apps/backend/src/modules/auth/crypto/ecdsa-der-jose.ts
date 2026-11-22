/**
 * Convert AWS KMS ECDSA DER signatures (ANSI X9.62) ↔ JOSE ES256 R||S (64 bytes).
 * No key material is handled here — signature format only.
 */

const ES256_PARAM_BYTES = 32;

function readAsn1Int(buf: Buffer, offset: number): { value: Buffer; next: number } {
  if (buf[offset] !== 0x02) throw new Error('DER: expected INTEGER');
  const len = buf[offset + 1];
  if (len > 0x7f) throw new Error('DER: unexpected long-form length');
  const start = offset + 2;
  const end = start + len;
  let value = buf.subarray(start, end);
  // Strip leading zero padding used for positive sign bit
  while (value.length > 1 && value[0] === 0x00) value = value.subarray(1);
  if (value.length > ES256_PARAM_BYTES) throw new Error('DER: integer too large for P-256');
  const out = Buffer.alloc(ES256_PARAM_BYTES);
  value.copy(out, ES256_PARAM_BYTES - value.length);
  return { value: out, next: end };
}

/** KMS Sign ECDSA_SHA_256 DER → JOSE R||S (64 bytes) */
export function derToJoseEs256(der: Buffer): Buffer {
  if (der[0] !== 0x30) throw new Error('DER: expected SEQUENCE');
  let offset = 2;
  if (der[1] & 0x80) {
    const n = der[1] & 0x7f;
    offset = 2 + n;
  }
  const r = readAsn1Int(der, offset);
  const s = readAsn1Int(der, r.next);
  return Buffer.concat([r.value, s.value]);
}

/** JOSE R||S → DER for KMS Verify (if needed) */
export function joseToDerEs256(jose: Buffer): Buffer {
  if (jose.length !== ES256_PARAM_BYTES * 2) {
    throw new Error('JOSE ES256 signature must be 64 bytes');
  }
  const encodeInt = (part: Buffer): Buffer => {
    let v = part;
    while (v.length > 1 && v[0] === 0x00) v = v.subarray(1);
    if (v[0] & 0x80) v = Buffer.concat([Buffer.from([0x00]), v]);
    return Buffer.concat([Buffer.from([0x02, v.length]), v]);
  };
  const r = encodeInt(jose.subarray(0, ES256_PARAM_BYTES));
  const s = encodeInt(jose.subarray(ES256_PARAM_BYTES));
  const body = Buffer.concat([r, s]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}
