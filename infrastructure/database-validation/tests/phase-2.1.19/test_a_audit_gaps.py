"""Workstream A verification — security_events protections on full schema."""
from __future__ import annotations

from typing import Any

from dbutil import ORG_A, connect, write_json


def run() -> dict[str, Any]:
    cases: list[dict[str, Any]] = []

    def rec(tid, name, passed, detail):
        cases.append(
            {
                "test_id": tid,
                "name": name,
                "status": "PASSED" if passed else "FAILED",
                "detail": detail,
                "database": "dcmp_full_schema_validation",
                "harness": "tests/phase-2.1.19/test_a_audit_gaps.py",
            }
        )

    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT column_name FROM information_schema.columns
                WHERE table_schema='public' AND table_name='security_events'
                  AND column_name IN ('event_source','recorded_by')
                """
            )
            cols = {r["column_name"] for r in cur.fetchall()}
            rec(
                "DB-SEC-082",
                "event_source column present",
                "event_source" in cols and "recorded_by" in cols,
                str(cols),
            )

            cur.execute(
                """
                SELECT 1 FROM pg_trigger
                WHERE tgname='trg_protect_security_events_truncate'
                """
            )
            rec("DB-SEC-070", "TRUNCATE trigger exists", cur.fetchone() is not None, "catalog")

            cur.execute(
                """
                SELECT 1 FROM pg_trigger
                WHERE tgname='trg_protect_security_events_dml'
                """
            )
            rec("DB-SEC-084-TRIG", "UPDATE/DELETE trigger exists", cur.fetchone() is not None, "catalog")

            # Valid insert as audit writer
            cur.execute("SET ROLE dcmp_audit_writer")
            try:
                cur.execute(
                    """
                    INSERT INTO public.security_events
                      (organization_id, category, severity, event_source, details)
                    VALUES (%s,'TEST','LOW','GATEWAY','{}'::jsonb)
                    """,
                    (ORG_A,),
                )
                rec("DB-SEC-067", "audit writer INSERT GATEWAY ok", True, "inserted")
            except Exception as e:
                rec("DB-SEC-067", "audit writer INSERT GATEWAY ok", False, str(e)[:200])
            conn.commit()

            cur.execute("SET ROLE dcmp_audit_writer")
            try:
                cur.execute(
                    """
                    INSERT INTO public.security_events
                      (organization_id, category, severity, event_source, details)
                    VALUES (%s,'TEST','LOW','ADMIN_PORTAL','{}'::jsonb)
                    """,
                    (ORG_A,),
                )
                rec("DB-SEC-069", "invalid event_source rejected", False, "accepted ADMIN_PORTAL")
                conn.rollback()
            except Exception as e:
                rec("DB-SEC-069", "invalid event_source rejected", True, str(e)[:200])
                conn.rollback()

            cur.execute("SET ROLE dcmp_audit_writer")
            try:
                cur.execute("SELECT count(*) FROM public.security_events")
                rec("DB-SEC-068", "audit writer SELECT denied", False, "select allowed")
            except Exception as e:
                rec("DB-SEC-068", "audit writer SELECT denied", True, str(e)[:200])
            conn.rollback()

            cur.execute("SET ROLE dcmp_audit_writer")
            try:
                cur.execute("UPDATE public.security_events SET severity='HIGH'")
                rec("DB-SEC-037", "UPDATE denied", cur.rowcount == 0 and False, f"rowcount={cur.rowcount}")
            except Exception as e:
                rec("DB-SEC-037", "UPDATE denied", True, str(e)[:200])
            conn.rollback()

            cur.execute("SET ROLE dcmp_app")
            try:
                cur.execute("TRUNCATE public.security_events")
                rec("DB-SEC-050", "TRUNCATE denied for dcmp_app", False, "truncate succeeded")
            except Exception as e:
                rec("DB-SEC-050", "TRUNCATE denied for dcmp_app", True, str(e)[:200])
            conn.rollback()

            # Truncate as table owner should still be blocked by trigger
            cur.execute("RESET ROLE")
            try:
                cur.execute("TRUNCATE public.security_events")
                rec("DB-SEC-070-EXEC", "TRUNCATE blocked even for owner", False, "truncate succeeded")
            except Exception as e:
                rec("DB-SEC-070-EXEC", "TRUNCATE blocked even for owner", True, str(e)[:200])
            conn.rollback()

            cur.execute("SET ROLE dcmp_platform_admin")
            try:
                cur.execute("TRUNCATE public.security_events")
                rec("DB-SEC-061", "platform_admin TRUNCATE denied", False, "allowed")
            except Exception as e:
                rec("DB-SEC-061", "platform_admin TRUNCATE denied", True, str(e)[:200])
            conn.rollback()
    finally:
        conn.close()

    summary: dict[str, int] = {}
    for c in cases:
        summary[c["status"]] = summary.get(c["status"], 0) + 1
    payload = {"workstream": "A", "summary": summary, "cases": cases}
    write_json("A_audit_gap_results.json", payload)
    return payload


if __name__ == "__main__":
    print(run()["summary"])
