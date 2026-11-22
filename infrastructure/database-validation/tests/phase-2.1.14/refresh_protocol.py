"""
PostgreSQL-authoritative refresh rotation + idempotency recovery harness.

Implements Phase 2.1.12 §2.7 transaction sequence against disposable dcmp_validation.
This is a validation harness, not production AuthModule code.
Never logs plaintext tokens or encryption keys.
"""
from __future__ import annotations

import hashlib
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

import psycopg
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from dbutil import ORG_A, USER_A, fingerprint_for_proof, sha256_hex, token_hash_from_label, utc_z

# Ephemeral harness key — never written to evidence or DB as plaintext key material.
# Only encryption_key_id reference is stored in PostgreSQL.
_HARNESS_KEY = hashlib.sha256(b"dcmp-phase-2.1.14-harness-aes-key-material").digest()
_KID = "harness:v1"


def build_aad(
    org_id: uuid.UUID,
    session_id: uuid.UUID,
    fingerprint: str,
    presented_token_hash: str,
    issued_token_id: uuid.UUID,
    dpop_jkt: str,
    encryption_key_id: str,
    expires_at_z: str,
) -> bytes:
    lines = [
        "dcmp-refresh-aad-v1",
        f"organization_id={org_id}",
        f"session_id={session_id}",
        f"request_fingerprint={fingerprint}",
        f"presented_token_hash={presented_token_hash}",
        f"issued_token_id={issued_token_id}",
        f"dpop_jkt={dpop_jkt}",
        f"encryption_key_id={encryption_key_id}",
        f"expires_at={expires_at_z}",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def encrypt_response_blob(aad: bytes, response_obj: dict[str, Any]) -> tuple[bytes, bytes, bytes]:
    """Returns (ciphertext_without_tag, iv, tag). Plaintext is opaque JSON without real tokens."""
    # Use placeholders — never real credentials
    import json

    plaintext = json.dumps(
        {
            "status": "ok",
            "issued_token_id": response_obj["issued_token_id"],
            "sequence": response_obj["sequence"],
            "token_fingerprint": response_obj["new_token_hash"][:16] + "...",
        },
        separators=(",", ":"),
    ).encode("utf-8")
    iv = secrets.token_bytes(12)
    aes = AESGCM(_HARNESS_KEY)
    ct_with_tag = aes.encrypt(iv, plaintext, aad)
    ciphertext, tag = ct_with_tag[:-16], ct_with_tag[-16:]
    return ciphertext, iv, tag


def decrypt_response_blob(
    aad: bytes, ciphertext: bytes, iv: bytes, tag: bytes
) -> bytes:
    aes = AESGCM(_HARNESS_KEY)
    return aes.decrypt(iv, ciphertext + tag, aad)


@dataclass
class RefreshResult:
    http_status: int
    outcome: str  # ROTATED | RECOVERED | TOKEN_REUSE | REVOKED | EXPIRED | ERROR
    issued_token_id: Optional[str] = None
    rotations: int = 0
    detail: str = ""
    invariant_violated: bool = False


@dataclass
class SessionSeed:
    org_id: uuid.UUID
    user_id: uuid.UUID
    session_id: uuid.UUID
    token_id: uuid.UUID
    token_hash: str
    dpop_jkt: str
    proof_a: str
    proof_b: str
    fp_a: str
    fp_b: str


def reset_seed(conn: psycopg.Connection, label: str = "base") -> SessionSeed:
    """Superuser seed for a fresh active session + unconsumed token."""
    org = ORG_A
    user = USER_A
    sess = uuid.uuid4()
    tok = uuid.uuid4()
    th = token_hash_from_label(f"{label}:{sess}:{tok}")
    proof_a = f"proof-a-{label}"
    proof_b = f"proof-b-{label}"
    fp_a = fingerprint_for_proof(proof_a)
    fp_b = fingerprint_for_proof(proof_b)
    with conn.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute("SET session_replication_role = replica")
        # Leave orgs/users; wipe session-related for this harness pass selectively
        cur.execute(
            """
            DELETE FROM public.refresh_idempotency_records
            WHERE organization_id = %s
            """,
            (org,),
        )
        cur.execute(
            "DELETE FROM public.user_session_tokens WHERE organization_id = %s", (org,)
        )
        cur.execute("DELETE FROM public.user_sessions WHERE organization_id = %s", (org,))
        cur.execute(
            """
            INSERT INTO public.organizations (id, org_code, display_name, status, data_region)
            VALUES (%s, 'ORG-A', 'Tenant A', 'ACTIVE', 'us-east-1')
            ON CONFLICT (id) DO UPDATE SET status = 'ACTIVE', suspended_at = NULL
            """,
            (org,),
        )
        cur.execute(
            """
            INSERT INTO public.users (id, organization_id, email, display_name)
            VALUES (%s, %s, 'a@example.com', 'User A')
            ON CONFLICT (id) DO NOTHING
            """,
            (user, org),
        )
        cur.execute(
            """
            INSERT INTO public.user_sessions
              (id, organization_id, user_id, dpop_jkt, is_active, expires_at)
            VALUES (%s, %s, %s, 'jkt-device-a', true, now() + interval '1 day')
            """,
            (sess, org, user),
        )
        cur.execute(
            """
            INSERT INTO public.user_session_tokens
              (id, organization_id, session_id, token_hash, sequence_number, expires_at)
            VALUES (%s, %s, %s, %s, 1, now() + interval '1 day')
            """,
            (tok, org, sess, th),
        )
        cur.execute("SET session_replication_role = DEFAULT")
    return SessionSeed(org, user, sess, tok, th, "jkt-device-a", proof_a, proof_b, fp_a, fp_b)


def _as_app(cur: psycopg.Cursor, org_id: uuid.UUID) -> None:
    cur.execute("SET SESSION AUTHORIZATION dcmp_app")
    cur.execute(
        "SELECT set_config('app.current_organization_id', %s, true)",
        (str(org_id),),
    )


def _new_conn() -> psycopg.Connection:
    return psycopg.connect(
        host="127.0.0.1", port=55432, dbname="dcmp_validation", user="dcmp_val_super"
    )


def refresh_once(
    seed: SessionSeed,
    fingerprint: str,
    presented_token_hash: str,
    *,
    conn: Optional[psycopg.Connection] = None,
    hold_before_consume: Optional[threading.Event] = None,
    release_hold: Optional[threading.Event] = None,
    redis_sim: Optional["RedisSim"] = None,
    redis_fail_phase: Optional[str] = None,
    dpop_jkt: Optional[str] = None,
    pretouch_sleep: float = 0.0,
) -> RefreshResult:
    """
    Execute one refresh attempt on an independent PostgreSQL connection.
    Opens a dedicated connection when conn is omitted; always closes owned connections.
    redis_fail_phase: None | before_tx | during | after_commit | cache_write
    """
    jkt = dpop_jkt or seed.dpop_jkt
    if redis_sim is not None and redis_fail_phase == "before_tx":
        if not redis_sim.available:
            pass  # continue — PG authoritative
        else:
            redis_sim.force_down()

    owns_conn = conn is None
    if owns_conn:
        conn = _new_conn()
    assert conn is not None
    conn.autocommit = False
    rotations = 0
    result: Optional[RefreshResult] = None
    try:
        with conn.cursor() as cur:
            _as_app(cur, seed.org_id)

            if pretouch_sleep:
                time.sleep(pretouch_sleep)

            # Optional Redis lookup (non-authoritative)
            if redis_sim is not None and redis_sim.available and redis_fail_phase != "during":
                cached = redis_sim.get(fingerprint)
                if cached and cached.get("session_id") == str(seed.session_id):
                    # Still verify DB session
                    cur.execute(
                        """
                        SELECT is_active FROM public.user_sessions
                        WHERE organization_id = %s AND id = %s
                        FOR SHARE
                        """,
                        (seed.org_id, seed.session_id),
                    )
                    row = cur.fetchone()
                    if row and row[0]:
                        conn.commit()
                        return RefreshResult(200, "RECOVERED", cached.get("issued_token_id"), 0, "redis-cache-hit")

            # 1. Idempotency lookup
            cur.execute(
                """
                SELECT issued_token_id, response_ciphertext, response_iv, response_auth_tag,
                       encryption_key_id, dpop_jkt, expires_at, invalidated_at,
                       presented_token_hash, request_fingerprint
                FROM public.refresh_idempotency_records
                WHERE organization_id = %s AND session_id = %s
                  AND request_fingerprint = %s
                  AND invalidated_at IS NULL
                  AND expires_at > clock_timestamp()
                FOR SHARE
                """,
                (seed.org_id, seed.session_id, fingerprint),
            )
            idem = cur.fetchone()
            if idem:
                issued_id = idem[0]
                if idem[5] != jkt:
                    conn.commit()
                    return RefreshResult(401, "ERROR", detail="dpop_jkt mismatch on recovery")
                cur.execute(
                    """
                    SELECT is_active FROM public.user_sessions
                    WHERE organization_id = %s AND id = %s FOR SHARE
                    """,
                    (seed.org_id, seed.session_id),
                )
                srow = cur.fetchone()
                if not srow or not srow[0]:
                    conn.commit()
                    return RefreshResult(401, "REVOKED", detail="session inactive on recovery")
                # Decrypt check (app layer)
                expires_at_z = utc_z(idem[6])
                aad = build_aad(
                    seed.org_id,
                    seed.session_id,
                    fingerprint,
                    idem[8],
                    issued_id,
                    idem[5],
                    idem[4],
                    expires_at_z,
                )
                try:
                    decrypt_response_blob(aad, bytes(idem[1]), bytes(idem[2]), bytes(idem[3]))
                except Exception:
                    conn.commit()
                    return RefreshResult(401, "ERROR", detail="decrypt failed")
                conn.commit()
                if redis_sim is not None and redis_sim.available:
                    try:
                        redis_sim.set(
                            fingerprint,
                            {"issued_token_id": str(issued_id), "session_id": str(seed.session_id)},
                        )
                    except Exception:
                        redis_sim.note_write_failure(fingerprint)
                return RefreshResult(200, "RECOVERED", str(issued_id), 0, "pg-idempotency")

            # 2. Session lock
            cur.execute(
                """
                SELECT is_active, dpop_jkt FROM public.user_sessions
                WHERE organization_id = %s AND id = %s
                FOR SHARE
                """,
                (seed.org_id, seed.session_id),
            )
            srow = cur.fetchone()
            if not srow or not srow[0]:
                conn.commit()
                return RefreshResult(401, "REVOKED", detail="session inactive")
            if srow[1] != jkt:
                conn.commit()
                return RefreshResult(401, "ERROR", detail="session jkt mismatch")

            if hold_before_consume is not None:
                hold_before_consume.set()
            if release_hold is not None:
                release_hold.wait(timeout=10)

            if redis_sim is not None and redis_fail_phase == "during":
                redis_sim.force_down()

            new_tok = uuid.uuid4()
            new_hash = token_hash_from_label(f"rotated:{new_tok}")
            # 3. Conditional consume
            cur.execute(
                """
                UPDATE public.user_session_tokens
                SET consumed_at = clock_timestamp(),
                    replaced_by_token_id = %s
                WHERE organization_id = %s
                  AND session_id = %s
                  AND token_hash = %s
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL
                RETURNING id, sequence_number
                """,
                (new_tok, seed.org_id, seed.session_id, presented_token_hash),
            )
            consumed = cur.fetchone()
            if not consumed:
                # Hard reuse path unless concurrent identical proof already wrote idempotency
                cur.execute(
                    """
                    SELECT issued_token_id FROM public.refresh_idempotency_records
                    WHERE organization_id = %s AND session_id = %s
                      AND request_fingerprint = %s
                      AND invalidated_at IS NULL
                      AND expires_at > clock_timestamp()
                    """,
                    (seed.org_id, seed.session_id, fingerprint),
                )
                race = cur.fetchone()
                if race:
                    conn.commit()
                    return RefreshResult(200, "RECOVERED", str(race[0]), 0, "concurrent-identical-reread")

                # Divergent / replay → revoke family
                cur.execute(
                    """
                    UPDATE public.user_sessions
                    SET is_active = false, revoked_at = clock_timestamp()
                    WHERE organization_id = %s AND id = %s AND is_active = true
                    """,
                    (seed.org_id, seed.session_id),
                )
                cur.execute(
                    "SELECT public.invalidate_refresh_idempotency(%s, %s)",
                    (seed.org_id, seed.session_id),
                )
                conn.commit()
                return RefreshResult(401, "TOKEN_REUSE", detail="conditional update 0 rows")

            old_id, seq = consumed
            # 4. Insert new token
            cur.execute(
                """
                INSERT INTO public.user_session_tokens
                  (id, organization_id, session_id, token_hash, sequence_number, expires_at)
                VALUES (%s, %s, %s, %s, %s, now() + interval '1 day')
                """,
                (new_tok, seed.org_id, seed.session_id, new_hash, seq + 1),
            )
            rotations = 1

            expires = datetime.now(timezone.utc) + timedelta(seconds=60)
            expires_z = utc_z(expires)
            aad = build_aad(
                seed.org_id,
                seed.session_id,
                fingerprint,
                presented_token_hash,
                new_tok,
                jkt,
                _KID,
                expires_z,
            )
            ct, iv, tag = encrypt_response_blob(
                aad,
                {
                    "issued_token_id": str(new_tok),
                    "sequence": seq + 1,
                    "new_token_hash": new_hash,
                },
            )

            # 5. Insert idempotency (ON CONFLICT DO NOTHING)
            cur.execute(
                """
                INSERT INTO public.refresh_idempotency_records (
                  organization_id, session_id, request_fingerprint, presented_token_hash,
                  issued_token_id, response_ciphertext, response_iv, response_auth_tag,
                  encryption_key_id, dpop_jkt, expires_at
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (organization_id, session_id, request_fingerprint) DO NOTHING
                RETURNING issued_token_id
                """,
                (
                    seed.org_id,
                    seed.session_id,
                    fingerprint,
                    presented_token_hash,
                    new_tok,
                    ct,
                    iv,
                    tag,
                    _KID,
                    jkt,
                    expires,
                ),
            )
            ins = cur.fetchone()
            if not ins:
                cur.execute(
                    """
                    SELECT issued_token_id FROM public.refresh_idempotency_records
                    WHERE organization_id = %s AND session_id = %s
                      AND request_fingerprint = %s
                      AND invalidated_at IS NULL
                    """,
                    (seed.org_id, seed.session_id, fingerprint),
                )
                winner = cur.fetchone()
                conn.commit()
                return RefreshResult(
                    200,
                    "RECOVERED",
                    str(winner[0]) if winner else str(new_tok),
                    rotations,
                    "on-conflict-reread",
                )

            conn.commit()

            # 6. Best-effort Redis
            if redis_sim is not None:
                if redis_fail_phase in ("after_commit", "cache_write"):
                    redis_sim.force_down()
                    redis_sim.note_write_failure(fingerprint)
                elif redis_sim.available:
                    redis_sim.set(
                        fingerprint,
                        {"issued_token_id": str(new_tok), "session_id": str(seed.session_id)},
                    )

            return RefreshResult(200, "ROTATED", str(new_tok), rotations, "ok")
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        return RefreshResult(500, "ERROR", detail=str(e)[:200], invariant_violated=False)
    finally:
        try:
            conn.rollback()
        except Exception:
            pass
        if owns_conn:
            try:
                conn.close()
            except Exception:
                pass
        else:
            try:
                conn.autocommit = True
                with conn.cursor() as cur:
                    cur.execute("RESET SESSION AUTHORIZATION")
            except Exception:
                pass


@dataclass
class RedisSim:
    """In-process Redis failure simulator. Not a real Redis instance."""

    available: bool = True
    store: dict[str, Any] = field(default_factory=dict)
    write_failures: list[str] = field(default_factory=list)
    mode: str = "SIMULATED"

    def force_down(self) -> None:
        self.available = False

    def recover(self) -> None:
        self.available = True

    def clear(self) -> None:
        self.store.clear()

    def get(self, key: str) -> Optional[dict]:
        if not self.available:
            raise RuntimeError("redis unavailable")
        return self.store.get(key)

    def set(self, key: str, value: dict) -> None:
        if not self.available:
            raise RuntimeError("redis unavailable")
        self.store[key] = value

    def note_write_failure(self, key: str) -> None:
        self.write_failures.append(key)


def db_state(conn: psycopg.Connection, seed: SessionSeed) -> dict[str, Any]:
    with conn.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute(
            """
            SELECT is_active, revoked_at IS NOT NULL
            FROM public.user_sessions WHERE id = %s
            """,
            (seed.session_id,),
        )
        sess = cur.fetchone()
        cur.execute(
            """
            SELECT count(*) FILTER (WHERE consumed_at IS NULL),
                   count(*),
                   coalesce(max(sequence_number),0)
            FROM public.user_session_tokens WHERE session_id = %s
            """,
            (seed.session_id,),
        )
        tok = cur.fetchone()
        cur.execute(
            """
            SELECT count(*) FILTER (WHERE invalidated_at IS NULL AND expires_at > clock_timestamp()),
                   count(*)
            FROM public.refresh_idempotency_records WHERE session_id = %s
            """,
            (seed.session_id,),
        )
        idem = cur.fetchone()
    return {
        "session_active": bool(sess[0]) if sess else None,
        "session_revoked_flag": bool(sess[1]) if sess else None,
        "unconsumed_tokens": tok[0],
        "token_rows": tok[1],
        "max_sequence": tok[2],
        "active_idempotency_rows": idem[0],
        "idempotency_rows": idem[1],
    }


def dual_refresh(
    seed: SessionSeed,
    fp1: str,
    fp2: str,
    th: str,
    *,
    stagger: bool = False,
    hold: bool = False,
) -> tuple[RefreshResult, RefreshResult, dict]:
    """Two genuinely independent connections (each refresh_once opens its own)."""
    results: dict[str, RefreshResult] = {}
    barrier = threading.Barrier(2)
    hold_evt = threading.Event() if hold else None
    release_evt = threading.Event() if hold else None

    def worker(name: str, fp: str, is_holder: bool) -> None:
        try:
            if stagger and name == "B":
                time.sleep(0.05)
            barrier.wait(timeout=5)
            if hold and is_holder:
                results[name] = refresh_once(
                    seed, fp, th, hold_before_consume=hold_evt, release_hold=release_evt
                )
            elif hold and not is_holder:
                hold_evt.wait(timeout=5)
                t = threading.Thread(target=lambda: (time.sleep(0.05), release_evt.set()))
                t.start()
                results[name] = refresh_once(seed, fp, th)
                t.join()
            else:
                results[name] = refresh_once(seed, fp, th)
        except Exception as e:
            results[name] = RefreshResult(500, "ERROR", detail=f"worker:{e}"[:200])

    t1 = threading.Thread(target=worker, args=("A", fp1, True))
    t2 = threading.Thread(target=worker, args=("B", fp2, False))
    t1.start()
    t2.start()
    t1.join(timeout=30)
    t2.join(timeout=30)
    c_probe = _new_conn()
    state = db_state(c_probe, seed)
    c_probe.close()
    return results.get("A", RefreshResult(500, "ERROR", detail="missing A")), results.get(
        "B", RefreshResult(500, "ERROR", detail="missing B")
    ), state
