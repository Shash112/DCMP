"""B — Redis failure and recovery (SIMULATED Redis only; no real Redis instance)."""
from __future__ import annotations

from dbutil import connect, write_json
from refresh_protocol import RedisSim, db_state, refresh_once, reset_seed


def run() -> dict:
    conn = connect()
    cases = []

    def case(cid, name, fn):
        try:
            ok, detail, actual = fn()
            cases.append(
                {
                    "id": cid,
                    "name": name,
                    "redis_mode": "SIMULATED",
                    "passed": ok,
                    "detail": detail,
                    "actual": actual,
                }
            )
        except Exception as e:
            cases.append(
                {
                    "id": cid,
                    "name": name,
                    "redis_mode": "SIMULATED",
                    "passed": False,
                    "detail": str(e)[:300],
                    "actual": {},
                }
            )

    def b1():
        seed = reset_seed(conn, "b1")
        redis = RedisSim(available=False)
        r = refresh_once(
            seed, seed.fp_a, seed.token_hash, redis_sim=redis, redis_fail_phase="before_tx"
        )
        return r.http_status == 200 and r.outcome == "ROTATED", "PG path without Redis", r.__dict__

    case("B1", "Redis unavailable before PostgreSQL transaction", b1)

    def b2():
        seed = reset_seed(conn, "b2")
        redis = RedisSim(available=True)
        r = refresh_once(
            seed, seed.fp_a, seed.token_hash, redis_sim=redis, redis_fail_phase="during"
        )
        return r.http_status == 200, "rotation succeeds despite mid-tx Redis down", r.__dict__

    case("B2", "Redis unavailable during refresh processing", b2)

    def b3():
        seed = reset_seed(conn, "b3")
        redis = RedisSim()
        r1 = refresh_once(
            seed, seed.fp_a, seed.token_hash, redis_sim=redis, redis_fail_phase="after_commit"
        )
        redis.force_down()
        redis.recover()
        redis.clear()
        redis.force_down()
        r2 = refresh_once(seed, seed.fp_a, seed.token_hash, redis_sim=redis)
        ok = r1.http_status == 200 and r2.outcome == "RECOVERED"
        return ok, "retry via PG after Redis down post-commit", {"r1": r1.__dict__, "r2": r2.__dict__}

    case("B3/DB-SEC-054", "Redis unavailable after PostgreSQL commit", b3)

    def b4():
        seed = reset_seed(conn, "b4")
        redis = RedisSim()
        r1 = refresh_once(
            seed, seed.fp_a, seed.token_hash, redis_sim=redis, redis_fail_phase="cache_write"
        )
        redis.recover()
        redis.clear()
        r2 = refresh_once(seed, seed.fp_a, seed.token_hash, redis_sim=redis)
        ok = (
            r1.http_status == 200
            and r2.detail == "pg-idempotency"
            and len(redis.write_failures) >= 1
        )
        return (
            ok,
            "write failure noted; PG recovery",
            {"r1": r1.__dict__, "r2": r2.__dict__, "write_failures": len(redis.write_failures)},
        )

    case("B4", "Redis cache write failure after successful PG commit", b4)

    def b5():
        seed = reset_seed(conn, "b5")
        redis = RedisSim()
        r1 = refresh_once(seed, seed.fp_a, seed.token_hash, redis_sim=redis)
        redis.clear()
        r2 = refresh_once(seed, seed.fp_a, seed.token_hash, redis_sim=redis)
        return r2.outcome == "RECOVERED", "PG durable truth", {"r1": r1.__dict__, "r2": r2.__dict__}

    case("B5", "Redis cache cleared before retry", b5)

    def b6():
        seed = reset_seed(conn, "b6")
        redis = RedisSim(available=False)
        r1 = refresh_once(seed, seed.fp_a, seed.token_hash, redis_sim=redis)
        redis.recover()
        r2 = refresh_once(seed, seed.fp_a, seed.token_hash, redis_sim=redis)
        r3 = refresh_once(seed, seed.fp_a, seed.token_hash, redis_sim=redis)
        ok = r1.outcome == "ROTATED" and r2.outcome == "RECOVERED" and r3.http_status == 200
        return ok, "outage then recover; no extra rotation", {
            "r1": r1.__dict__,
            "r2": r2.__dict__,
            "r3": r3.__dict__,
            "state": db_state(conn, seed),
        }

    case("B6", "Redis recovery after outage", b6)

    def b7():
        seed = reset_seed(conn, "b7")
        r1 = refresh_once(seed, seed.fp_a, seed.token_hash)
        r2 = refresh_once(seed, seed.fp_a, seed.token_hash)
        ok = (
            r1.outcome == "ROTATED"
            and r2.outcome == "RECOVERED"
            and r1.issued_token_id == r2.issued_token_id
        )
        return ok, "no second rotation", {"r1": r1.__dict__, "r2": r2.__dict__}

    case("B7", "Retry using original token after database commit", b7)

    def b8():
        seed = reset_seed(conn, "b8")
        redis = RedisSim()
        r1 = refresh_once(seed, seed.fp_a, seed.token_hash, redis_sim=redis)
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
            cur.execute(
                "SELECT public.invalidate_refresh_idempotency(%s,%s)",
                (seed.org_id, seed.session_id),
            )
            cur.execute("RESET SESSION AUTHORIZATION")
        redis.clear()
        r2 = refresh_once(seed, seed.fp_a, seed.token_hash, redis_sim=redis)
        return r1.http_status == 200 and r2.http_status == 401, "no credential recovery after logout", {
            "r1": r1.__dict__,
            "r2": r2.__dict__,
        }

    case("B8", "Retry after session logout/revocation", b8)

    conn.close()
    summary = {
        "group": "B_redis_failure_recovery",
        "note": "No real Redis instance was available; all cases used RedisSim (SIMULATED).",
        "passed": sum(1 for c in cases if c["passed"]),
        "failed": sum(1 for c in cases if not c["passed"]),
        "total": len(cases),
        "cases": cases,
    }
    write_json("B_redis_sim_results.json", summary)
    return summary


if __name__ == "__main__":
    import pprint

    pprint.pp(run())
