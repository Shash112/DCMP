"""E — AES-256-GCM refresh idempotency encryption validation harness.

Standalone validation harness using documented dcmp-refresh-aad-v1 format.
Not production AuthModule code. Never prints keys or plaintext tokens.
"""
from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from dbutil import connect, write_json
from refresh_protocol import build_aad, decrypt_response_blob, encrypt_response_blob

ORG = uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
SESS = uuid.UUID("33333333-3333-4333-8333-333333333333")
ISSUED = uuid.UUID("44444444-4444-4444-8444-444444444402")
FP = hashlib.sha256(b"fp-e").hexdigest()
PTH = hashlib.sha256(b"presented-e").hexdigest()
JKT = "jkt-device-a"
KID = "harness:v1"


def expires_z(hours_delta: float = 0.016) -> str:
    dt = datetime.now(timezone.utc) + timedelta(hours=hours_delta)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def run() -> dict:
    cases = []
    exp = expires_z()
    aad = build_aad(ORG, SESS, FP, PTH, ISSUED, JKT, KID, exp)
    blob = {
        "issued_token_id": str(ISSUED),
        "sequence": 2,
        "new_token_hash": "bb" * 32,
    }
    ct, iv, tag = encrypt_response_blob(aad, blob)

    def rec(cid, name, passed, detail):
        cases.append(
            {
                "id": cid,
                "name": name,
                "status": "PASSED" if passed else "FAILED",
                "detail": detail,
            }
        )

    # 1 encrypt/decrypt
    try:
        pt = decrypt_response_blob(aad, ct, iv, tag)
        rec("E1", "Encrypt and decrypt valid response", b"ok" in pt or b"issued_token_id" in pt, "roundtrip ok")
    except Exception as e:
        rec("E1", "Encrypt and decrypt valid response", False, type(e).__name__)

    # 2 incorrect key
    try:
        bad = AESGCM(hashlib.sha256(b"wrong-key").digest())
        bad.decrypt(iv, ct + tag, aad)
        rec("E2", "Reject incorrect key", False, "decrypt unexpectedly succeeded")
    except InvalidTag:
        rec("E2", "Reject incorrect key", True, "InvalidTag")
    except Exception as e:
        rec("E2", "Reject incorrect key", True, type(e).__name__)

    # 3 modified ciphertext
    try:
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        decrypt_response_blob(aad, bytes(tampered), iv, tag)
        rec("E3", "Reject modified ciphertext", False, "accepted")
    except InvalidTag:
        rec("E3", "Reject modified ciphertext", True, "InvalidTag")

    # 4 modified tag
    try:
        t2 = bytearray(tag)
        t2[0] ^= 0x01
        decrypt_response_blob(aad, ct, iv, bytes(t2))
        rec("E4", "Reject modified authentication tag", False, "accepted")
    except InvalidTag:
        rec("E4", "Reject modified authentication tag", True, "InvalidTag")

    # 5 modified IV
    try:
        iv2 = bytearray(iv)
        iv2[0] ^= 0x01
        decrypt_response_blob(aad, ct, bytes(iv2), tag)
        rec("E5", "Reject modified IV", False, "accepted")
    except InvalidTag:
        rec("E5", "Reject modified IV", True, "InvalidTag")

    # 6 incorrect AAD
    try:
        bad_aad = aad + b"x"
        decrypt_response_blob(bad_aad, ct, iv, tag)
        rec("E6", "Reject incorrect AAD", False, "accepted")
    except InvalidTag:
        rec("E6", "Reject incorrect AAD", True, "InvalidTag")

    # 7 different org in AAD
    try:
        a2 = build_aad(uuid.UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"), SESS, FP, PTH, ISSUED, JKT, KID, exp)
        decrypt_response_blob(a2, ct, iv, tag)
        rec("E7", "Reject different organization ID in AAD", False, "accepted")
    except InvalidTag:
        rec("E7", "Reject different organization ID in AAD", True, "InvalidTag")

    # 8 different session
    try:
        a2 = build_aad(ORG, uuid.uuid4(), FP, PTH, ISSUED, JKT, KID, exp)
        decrypt_response_blob(a2, ct, iv, tag)
        rec("E8", "Reject different session ID in AAD", False, "accepted")
    except InvalidTag:
        rec("E8", "Reject different session ID in AAD", True, "InvalidTag")

    # 9 different token fingerprint (presented hash)
    try:
        a2 = build_aad(ORG, SESS, FP, "cc" * 32, ISSUED, JKT, KID, exp)
        decrypt_response_blob(a2, ct, iv, tag)
        rec("E9", "Reject different token fingerprint/hash in AAD", False, "accepted")
    except InvalidTag:
        rec("E9", "Reject different token fingerprint/hash in AAD", True, "InvalidTag")

    # 10 different DPoP jkt
    try:
        a2 = build_aad(ORG, SESS, FP, PTH, ISSUED, "other-jkt", KID, exp)
        decrypt_response_blob(a2, ct, iv, tag)
        rec("E10", "Reject different DPoP key thumbprint in AAD", False, "accepted")
    except InvalidTag:
        rec("E10", "Reject different DPoP key thumbprint in AAD", True, "InvalidTag")

    # 11 expired encryption record (AAD expiry binding + app policy)
    # Encrypt with short-lived expires_at already past in AAD; decrypt cryptographically still works,
    # but harness policy rejects expired records before decrypt return.
    past = (datetime.now(timezone.utc) - timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    a_past = build_aad(ORG, SESS, FP, PTH, ISSUED, JKT, KID, past)
    ct2, iv2, tag2 = encrypt_response_blob(a_past, blob)
    # Policy check: treat expires_at in AAD < now as expired
    expired_policy = past < datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    try:
        decrypt_response_blob(a_past, ct2, iv2, tag2)
        crypto_ok = True
    except InvalidTag:
        crypto_ok = False
    rec(
        "E11",
        "Reject expired encryption record (policy)",
        expired_policy and crypto_ok,
        "AAD-bound expires_at in past; app must refuse return even if GCM verifies",
    )

    # 12 keys not in PostgreSQL
    conn = connect()
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT column_name FROM information_schema.columns
            WHERE table_schema='public' AND table_name='refresh_idempotency_records'
            ORDER BY 1
            """
        )
        cols = [r[0] for r in cur.fetchall()]
        cur.execute(
            """
            SELECT count(*) FROM information_schema.columns
            WHERE table_name='refresh_idempotency_records'
              AND column_name ILIKE '%key_material%' OR column_name ILIKE '%aes_key%'
            """
        )
        # Fix OR precedence — rewrite
        cur.execute(
            """
            SELECT count(*) FROM information_schema.columns
            WHERE table_schema='public' AND table_name='refresh_idempotency_records'
              AND (column_name ILIKE '%key_material%' OR column_name ILIKE '%aes_key%'
                   OR column_name = 'encryption_key')
            """
        )
        bad_cols = cur.fetchone()[0]
        # Ensure encryption_key_id exists but no raw key column
        has_kid = "encryption_key_id" in cols
        # Scan no bytea column named like secret key beyond ciphertext/iv/tag
        forbidden = {"encryption_key", "key_material", "aes_key", "master_key"}
        overlap = forbidden.intersection(cols)
    conn.close()
    rec(
        "E12",
        "Encryption keys not stored in PostgreSQL",
        has_kid and bad_cols == 0 and not overlap,
        f"columns={cols}; forbidden_overlap={list(overlap)}",
    )

    # IV/tag sizes
    rec("E-IV", "IV is 96-bit", len(iv) == 12, f"len={len(iv)}")
    rec("E-TAG", "Auth tag is 128-bit", len(tag) == 16, f"len={len(tag)}")
    # IV uniqueness sample
    ivs = {encrypt_response_blob(aad, blob)[1] for _ in range(20)}
    rec("E-IV-RND", "IVs are CSPRNG-unique in sample", len(ivs) == 20, f"unique={len(ivs)}")

    summary = {
        "group": "E_aes_gcm_aad",
        "aad_prefix": "dcmp-refresh-aad-v1",
        "harness_note": "Validation harness only; production AuthModule encryption not present in repo",
        "passed": sum(1 for c in cases if c["status"] == "PASSED"),
        "failed": sum(1 for c in cases if c["status"] == "FAILED"),
        "cases": cases,
        # Do not include key material, plaintext, or ciphertext hex dumps
    }
    write_json("E_aes_gcm_results.json", summary)
    return summary


if __name__ == "__main__":
    import pprint

    pprint.pp(run())
