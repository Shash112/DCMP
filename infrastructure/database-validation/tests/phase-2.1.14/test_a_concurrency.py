"""A — Multi-connection refresh concurrency (DB-SEC-071/072 + scenarios 1–10)."""
from __future__ import annotations

import time
import uuid

import psycopg

from dbutil import connect, write_json
from refresh_protocol import (
    RedisSim,
    db_state,
    dual_refresh,
    refresh_once,
    reset_seed,
)


def _ok(cond: bool, msg: str) -> dict:
    return {"passed": bool(cond), "detail": msg}


def run() -> dict:
    results = []
    conn = connect()
    print("A: connected", flush=True)

    # 1. Two simultaneous identical proof
    seed = reset_seed(conn, "s1")
    print("A1: seed", flush=True)
    before = db_state(conn, seed)
    a, b, after = dual_refresh(seed, seed.fp_a, seed.fp_a, seed.token_hash)
    print("A1: done", a.outcome, b.outcome, flush=True)
    ok = (
        a.http_status == 200
        and b.http_status == 200
        and after["max_sequence"] == 2
        and after["active_idempotency_rows"] == 1
        and after["session_active"] is True
        and {a.outcome, b.outcome} <= {"ROTATED", "RECOVERED"}
    )
    inv = after["max_sequence"] > 2 or after["active_idempotency_rows"] > 1
    results.append(
        {
            "id": "A1/DB-SEC-071",
            "name": "simultaneous identical proof",
            "connections": 2,
            "expected": "both 200; exactly 1 rotation; 1 idempotency row",
            "actual": {"A": a.__dict__, "B": b.__dict__, "before": before, "after": after},
            **_ok(ok and not inv, "ok" if ok else "mismatch"),
            "invariant_violated": inv,
        }
    )

    # 2. Simultaneous divergent proofs
    seed = reset_seed(conn, "s2")
    a, b, after = dual_refresh(seed, seed.fp_a, seed.fp_b, seed.token_hash)
    statuses = sorted([a.http_status, b.http_status])
    ok = statuses == [200, 401] and after["session_active"] is False
    results.append(
        {
            "id": "A2/DB-SEC-072",
            "name": "simultaneous divergent proofs",
            "connections": 2,
            "expected": "one 200, one 401 TOKEN_REUSE; session revoked",
            "actual": {"A": a.__dict__, "B": b.__dict__, "after": after},
            **_ok(ok, "ok" if ok else f"statuses={statuses} active={after['session_active']}"),
            "invariant_violated": after["max_sequence"] > 2,
        }
    )

    # 3. B arrives while A still executing
    seed = reset_seed(conn, "s3")
    a, b, after = dual_refresh(seed, seed.fp_a, seed.fp_a, seed.token_hash, hold=True)
    ok = a.http_status == 200 and b.http_status == 200 and after["max_sequence"] == 2
    results.append(
        {
            "id": "A3",
            "name": "overlap while first tx executing",
            "connections": 2,
            "expected": "both 200; single rotation",
            "actual": {"A": a.__dict__, "B": b.__dict__, "after": after},
            **_ok(ok, "ok" if ok else "fail"),
            "invariant_violated": after["max_sequence"] > 2,
        }
    )

    # 4. Retry immediately after first commit
    seed = reset_seed(conn, "s4")
    r1 = refresh_once(seed, seed.fp_a, seed.token_hash)
    r2 = refresh_once(seed, seed.fp_a, seed.token_hash)
    after = db_state(conn, seed)
    ok = r1.outcome == "ROTATED" and r2.outcome == "RECOVERED" and after["max_sequence"] == 2
    results.append(
        {
            "id": "A4",
            "name": "retry immediately after commit",
            "connections": 2,
            "expected": "first ROTATED, second RECOVERED; no second rotation",
            "actual": {"first": r1.__dict__, "retry": r2.__dict__, "after": after},
            **_ok(ok, "ok" if ok else "fail"),
            "invariant_violated": False,
        }
    )

    # 5. Retry after Redis cache cleared
    seed = reset_seed(conn, "s5")
    redis = RedisSim()
    r1 = refresh_once(seed, seed.fp_a, seed.token_hash, redis_sim=redis)
    redis.clear()
    r2 = refresh_once(seed, seed.fp_a, seed.token_hash, redis_sim=redis)
    after = db_state(conn, seed)
    ok = r1.http_status == 200 and r2.outcome == "RECOVERED" and r2.detail == "pg-idempotency"
    results.append(
        {
            "id": "A5",
            "name": "retry after Redis cache cleared (SIMULATED Redis)",
            "connections": 2,
            "redis_mode": "SIMULATED",
            "expected": "recover from PostgreSQL idempotency",
            "actual": {"first": r1.__dict__, "retry": r2.__dict__, "after": after},
            **_ok(ok, "ok" if ok else "fail"),
            "invariant_violated": False,
        }
    )

    # 6. Retry after PG idempotency committed
    seed = reset_seed(conn, "s6")
    r1 = refresh_once(seed, seed.fp_a, seed.token_hash)
    r2 = refresh_once(seed, seed.fp_a, seed.token_hash)
    ok = r1.outcome == "ROTATED" and r2.outcome == "RECOVERED" and r1.issued_token_id == r2.issued_token_id
    results.append(
        {
            "id": "A6",
            "name": "retry after PG idempotency committed",
            "connections": 2,
            "expected": "same issued_token_id recovered",
            "actual": {"first": r1.__dict__, "retry": r2.__dict__},
            **_ok(ok, "ok" if ok else "fail"),
            "invariant_violated": False,
        }
    )

    # 7. Two requests rotating same session token (identical) — already covered; assert token family length
    seed = reset_seed(conn, "s7")
    a, b, after = dual_refresh(seed, seed.fp_a, seed.fp_a, seed.token_hash)
    ok = after["token_rows"] == 2 and after["unconsumed_tokens"] == 1
    results.append(
        {
            "id": "A7",
            "name": "two requests attempting same token rotation",
            "connections": 2,
            "expected": "2 token rows, 1 unconsumed",
            "actual": {"A": a.__dict__, "B": b.__dict__, "after": after},
            **_ok(ok and a.http_status == 200 and b.http_status == 200, "ok" if ok else "fail"),
            "invariant_violated": after["unconsumed_tokens"] > 1,
        }
    )

    # 8. Refresh commits, then logout, then recovery attempt (overlap variant covered by A3)
    print("A8", flush=True)
    seed = reset_seed(conn, "s8")
    r_refresh = refresh_once(seed, seed.fp_a, seed.token_hash)
    with conn.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute(
            """
            UPDATE public.user_sessions
            SET is_active = false, revoked_at = clock_timestamp()
            WHERE id = %s
            """,
            (seed.session_id,),
        )
        cur.execute("SET SESSION AUTHORIZATION dcmp_app")
        cur.execute(
            "SELECT set_config('app.current_organization_id', %s, true)",
            (str(seed.org_id),),
        )
        cur.execute(
            "SELECT public.invalidate_refresh_idempotency(%s, %s)",
            (seed.org_id, seed.session_id),
        )
        cur.execute("RESET SESSION AUTHORIZATION")
    r_retry = refresh_once(seed, seed.fp_a, seed.token_hash)
    after = db_state(conn, seed)
    ok = r_refresh.http_status == 200 and r_retry.http_status == 401 and after["session_active"] is False
    results.append(
        {
            "id": "A8",
            "name": "logout after refresh blocks recovery",
            "connections": 3,
            "expected": "refresh 200; subsequent recovery 401",
            "actual": {"refresh": r_refresh.__dict__, "retry": r_retry.__dict__, "after": after},
            **_ok(ok, "ok" if ok else "fail"),
            "invariant_violated": r_retry.http_status == 200,
        }
    )
    print("A8 done", flush=True)

    # 9. Session revocation before idempotency recovery
    seed = reset_seed(conn, "s9")
    r1 = refresh_once(seed, seed.fp_a, seed.token_hash)
    with conn.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute(
            "UPDATE public.user_sessions SET is_active=false, revoked_at=clock_timestamp() WHERE id=%s",
            (seed.session_id,),
        )
        cur.execute("SET SESSION AUTHORIZATION dcmp_app")
        cur.execute(
            "SELECT set_config('app.current_organization_id', %s, true)",
            (str(seed.org_id),),
        )
        cur.execute("SELECT public.invalidate_refresh_idempotency(%s,%s)", (seed.org_id, seed.session_id))
        cur.execute("RESET SESSION AUTHORIZATION")
    r2 = refresh_once(seed, seed.fp_a, seed.token_hash)
    ok = r1.http_status == 200 and r2.http_status == 401
    results.append(
        {
            "id": "A9",
            "name": "revocation before idempotency recovery",
            "connections": 2,
            "expected": "recovery denied after revoke",
            "actual": {"first": r1.__dict__, "retry": r2.__dict__},
            **_ok(ok, "ok" if ok else "fail"),
            "invariant_violated": r2.http_status == 200,
        }
    )

    # 10. Expired idempotency records
    seed = reset_seed(conn, "s10")
    r1 = refresh_once(seed, seed.fp_a, seed.token_hash)
    with conn.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        # Force expiry as superuser (bypass immutability? expires_at is immutable via trigger for app —
        # use replica role to age the row for test)
        cur.execute("SET session_replication_role = replica")
        cur.execute(
            """
            UPDATE public.refresh_idempotency_records
            SET expires_at = clock_timestamp() - interval '1 second'
            WHERE session_id = %s
            """,
            (seed.session_id,),
        )
        cur.execute("SET session_replication_role = DEFAULT")
    r2 = refresh_once(seed, seed.fp_a, seed.token_hash)
    # After expiry, presented token is already consumed → TOKEN_REUSE / 401
    ok = r1.http_status == 200 and r2.http_status == 401
    results.append(
        {
            "id": "A10",
            "name": "expired idempotency records",
            "connections": 2,
            "expected": "expired row not recoverable; hard reuse 401",
            "actual": {"first": r1.__dict__, "retry": r2.__dict__},
            **_ok(ok, "ok" if ok else "fail"),
            "invariant_violated": False,
        }
    )
    conn.close()

    passed = sum(1 for r in results if r["passed"])
    failed = sum(1 for r in results if not r["passed"])
    summary = {
        "group": "A_multi_connection_refresh",
        "passed": passed,
        "failed": failed,
        "total": len(results),
        "cases": results,
    }
    write_json("A_concurrency_results.json", summary)
    return summary


if __name__ == "__main__":
    import pprint

    pprint.pp(run())
