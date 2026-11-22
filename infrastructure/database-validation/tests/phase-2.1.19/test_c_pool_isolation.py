"""Workstream C — real multi-connection pooled tenant-context isolation."""
from __future__ import annotations

import threading
import time
from typing import Any

from dbutil import ORG_A, ORG_B, USER_A, USER_B, HOST, PORT, DB, USER, write_json


def conninfo() -> str:
    return f"host={HOST} port={PORT} dbname={DB} user={USER}"


def backend_pid(conn) -> int:
    with conn.cursor() as cur:
        cur.execute("SELECT pg_backend_pid()")
        return int(cur.fetchone()[0])


def set_tenant(cur, org_id) -> None:
    if org_id is None:
        cur.execute("SELECT set_config('app.current_organization_id', '', true)")
    else:
        cur.execute(
            "SELECT set_config('app.current_organization_id', %s, true)",
            (str(org_id),),
        )


def ensure_users(pool) -> None:
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO public.organizations (id, org_code, display_name, status, data_region)
                VALUES (%s,'ORG-AAAA','Org A','ACTIVE','us-east-1'),
                       (%s,'ORG-BBBB','Org B','ACTIVE','us-east-1')
                ON CONFLICT (id) DO NOTHING
                """,
                (ORG_A, ORG_B),
            )
            cur.execute(
                """
                INSERT INTO public.users (id, organization_id, email, display_name, password_hash)
                VALUES (%s,%s,'a@example.com','User A','scrypt$x$y'),
                       (%s,%s,'b@example.com','User B','scrypt$x$y')
                ON CONFLICT (id) DO NOTHING
                """,
                (USER_A, ORG_A, USER_B, ORG_B),
            )
        conn.commit()


def run() -> dict[str, Any]:
    cases: list[dict[str, Any]] = []

    def rec(tid: str, name: str, passed: bool, detail: str, **extra):
        cases.append(
            {
                "test_id": tid,
                "name": name,
                "status": "PASSED" if passed else "FAILED",
                "detail": detail,
                "database": DB,
                "harness": "tests/phase-2.1.19/test_c_pool_isolation.py",
                **extra,
            }
        )

    try:
        from psycopg_pool import ConnectionPool
    except Exception as e:
        payload = {
            "workstream": "C",
            "summary": {"BLOCKED": 1},
            "cases": [
                {
                    "test_id": "DB-SEC-POOL-101",
                    "status": "BLOCKED",
                    "detail": f"psycopg_pool missing: {e}",
                }
            ],
        }
        write_json("C_pool_results.json", payload)
        return payload

    pool = ConnectionPool(conninfo=conninfo(), min_size=1, max_size=4, open=True)
    try:
        ensure_users(pool)

        with pool.connection() as conn:
            pid1 = backend_pid(conn)
            with conn.cursor() as cur:
                cur.execute("SET ROLE dcmp_app")
                set_tenant(cur, ORG_A)
                cur.execute(
                    "SELECT count(*)::int FROM public.users WHERE organization_id=%s",
                    (ORG_A,),
                )
                a_ok = cur.fetchone()[0] >= 1
                cur.execute(
                    "SELECT count(*)::int FROM public.users WHERE organization_id=%s",
                    (ORG_B,),
                )
                a_x = cur.fetchone()[0]
            conn.commit()
            rec(
                "DB-SEC-POOL-101",
                "tenant A reads own",
                a_ok and a_x == 0,
                f"pid={pid1} a_ok={a_ok} x={a_x}",
                pid=pid1,
            )

        with pool.connection() as conn:
            pid2 = backend_pid(conn)
            with conn.cursor() as cur:
                cur.execute("SET ROLE dcmp_app")
                cur.execute(
                    "SELECT nullif(current_setting('app.current_organization_id', true), '')"
                )
                guc = cur.fetchone()[0]
                cur.execute("SELECT count(*)::int FROM public.users")
                n = cur.fetchone()[0]
            conn.commit()
            rec(
                "DB-SEC-POOL-102",
                "pooled reuse has no residual tenant GUC",
                guc is None and n == 0,
                f"pid={pid2} guc={guc} rows={n} reused={pid1==pid2}",
                pid=pid2,
                reused_backend=(pid1 == pid2),
            )

        with pool.connection() as conn:
            pid3 = backend_pid(conn)
            with conn.cursor() as cur:
                cur.execute("SET ROLE dcmp_app")
                set_tenant(cur, ORG_B)
                cur.execute(
                    "SELECT count(*)::int FROM public.users WHERE organization_id=%s",
                    (ORG_A,),
                )
                leak = cur.fetchone()[0]
                cur.execute(
                    "SELECT count(*)::int FROM public.users WHERE organization_id=%s",
                    (ORG_B,),
                )
                own = cur.fetchone()[0]
            conn.commit()
            rec(
                "DB-SEC-POOL-103",
                "tenant B cannot see A after reuse",
                leak == 0 and own >= 1,
                f"pid={pid3} leak={leak} own={own}",
                pid=pid3,
            )

        with pool.connection() as conn:
            pid4 = backend_pid(conn)
            with conn.cursor() as cur:
                cur.execute("SET ROLE dcmp_app")
                set_tenant(cur, ORG_A)
                cur.execute("SELECT count(*)::int FROM public.users")
                mid = cur.fetchone()[0]
            conn.rollback()
            with conn.cursor() as cur:
                cur.execute("SET ROLE dcmp_app")
                cur.execute(
                    "SELECT nullif(current_setting('app.current_organization_id', true), '')"
                )
                guc = cur.fetchone()[0]
                cur.execute("SELECT count(*)::int FROM public.users")
                n = cur.fetchone()[0]
            conn.commit()
            rec(
                "DB-SEC-POOL-104",
                "rollback clears SET LOCAL tenant context",
                guc is None and n == 0 and mid >= 1,
                f"pid={pid4} mid={mid} after_guc={guc} after_n={n}",
                pid=pid4,
            )

        barrier = threading.Barrier(2)
        outcomes: dict[str, Any] = {}

        def worker(label: str, org, other):
            with pool.connection() as conn:
                pid = backend_pid(conn)
                with conn.cursor() as cur:
                    cur.execute("SET ROLE dcmp_app")
                    set_tenant(cur, org)
                    barrier.wait(timeout=10)
                    time.sleep(0.05)
                    cur.execute(
                        "SELECT count(*)::int FROM public.users WHERE organization_id=%s",
                        (other,),
                    )
                    leak = cur.fetchone()[0]
                    cur.execute(
                        "SELECT count(*)::int FROM public.users WHERE organization_id=%s",
                        (org,),
                    )
                    own = cur.fetchone()[0]
                conn.commit()
                outcomes[label] = {"pid": pid, "leak": leak, "own": own}

        t1 = threading.Thread(target=worker, args=("A", ORG_A, ORG_B))
        t2 = threading.Thread(target=worker, args=("B", ORG_B, ORG_A))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        ok = (
            outcomes.get("A", {}).get("leak") == 0
            and outcomes.get("B", {}).get("leak") == 0
            and outcomes.get("A", {}).get("own", 0) >= 1
            and outcomes.get("B", {}).get("own", 0) >= 1
        )
        rec("DB-SEC-POOL-105", "concurrent A/B no cross leak", ok, str(outcomes))

        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SET ROLE dcmp_app")
                set_tenant(cur, None)
                cur.execute("SELECT count(*)::int FROM public.users")
                n = cur.fetchone()[0]
            conn.commit()
            rec("DB-SEC-POOL-106", "missing tenant fail-closed", n == 0, f"rows={n}")

        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SET ROLE dcmp_app")
                set_tenant(cur, ORG_A)
                cur.execute(
                    "SELECT set_config('app.client_organization_id', %s, true)",
                    (str(ORG_B),),
                )
                cur.execute(
                    "SELECT count(*)::int FROM public.users WHERE organization_id=%s",
                    (ORG_B,),
                )
                n = cur.fetchone()[0]
            conn.commit()
            rec(
                "DB-SEC-POOL-107",
                "client org GUC ignored by RLS",
                n == 0,
                f"visible_b={n}",
                notes="RLS binds only app.current_organization_id set server-side",
            )

        pids = []
        for _ in range(8):
            with pool.connection() as conn:
                pids.append(backend_pid(conn))
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                conn.commit()
        rec(
            "DB-SEC-POOL-108",
            "connection reuse observed",
            len(set(pids)) < len(pids),
            f"pids={pids} unique={len(set(pids))}",
        )
    finally:
        pool.close()

    summary: dict[str, int] = {}
    for c in cases:
        summary[c["status"]] = summary.get(c["status"], 0) + 1
    payload = {"workstream": "C", "summary": summary, "cases": cases}
    write_json("C_pool_results.json", payload)
    return payload


if __name__ == "__main__":
    print(run()["summary"])
