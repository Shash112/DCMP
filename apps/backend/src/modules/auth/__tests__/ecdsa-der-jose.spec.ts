import assert from 'node:assert/strict';
import { createSign, generateKeyPairSync, createVerify } from 'node:crypto';
import test from 'node:test';
import { derToJoseEs256, joseToDerEs256 } from '../crypto/ecdsa-der-jose';

test('DER ↔ JOSE ES256 round-trip preserves verify', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const msg = Buffer.from('header.payload', 'utf8');
  const der = createSign('SHA256').update(msg).sign(privateKey);
  const jose = derToJoseEs256(der);
  assert.equal(jose.length, 64);
  const der2 = joseToDerEs256(jose);
  const ok = createVerify('SHA256').update(msg).verify(publicKey, der2);
  assert.equal(ok, true);
});

test('derToJose rejects non-SEQUENCE', () => {
  assert.throws(() => derToJoseEs256(Buffer.from([0x02, 0x01, 0x00])));
});
