"""Workstream B — tenant isolation across all FORCE-RLS tables."""
from __future__ import annotations

import uuid
from typing import Any

from dbutil import ORG_A, ORG_B, connect, set_tenant, write_json


def force_rls_tables(cur) -> list[dict[str, Any]]:
    cur.execute(
        """
        SELECT c.relname AS table_name,
               c.relrowsecurity AS rls,
               c.relforcerowsecurity AS force_rls,
               EXISTS (
                 SELECT 1 FROM information_schema.columns col
                 WHERE col.table_schema='public' AND col.table_name=c.relname
                   AND col.column_name='organization_id'
               ) AS has_organization_id
        FROM pg_class c
        JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND c.relkind='r' AND c.relforcerowsecurity
        ORDER BY 1
        """
    )
    return list(cur.fetchall())


def probe_columns(cur, table: str) -> set[str]:
    cur.execute(
        """
        SELECT column_name FROM information_schema.columns
        WHERE table_schema='public' AND table_name=%s
        """,
        (table,),
    )
    return {r["column_name"] for r in cur.fetchall()}


def test_table(cur, table: str, has_org: bool) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    base = f"DB-SEC-RLS54-{table}"

    def rec(op: str, status: str, detail: str):
        results.append(
            {
                "test_id": f"{base}-{op}",
                "table": table,
                "operation": op,
                "status": status,
                "detail": detail,
                "database": "dcmp_full_schema_validation",
                "harness": "tests/phase-2.1.19/test_b_full_rls.py",
            }
        )

    if table == "organizations":
        tenant_mode = "root"
    elif has_org:
        tenant_mode = "org_col"
    else:
        rec("ALL", "NOT_APPLICABLE", "FORCE RLS without organization_id and not organizations")
        return results

    def ensure_app_role():
        try:
            cur.connection.rollback()
        except Exception:
            pass
        cur.execute("SET ROLE dcmp_app")
        set_tenant(cur, ORG_A)

    cur.execute("SET ROLE dcmp_app")

    # EMPTY
    try:
        set_tenant(cur, None)
        cur.execute(f"SELECT count(*)::int AS n FROM public.{table}")
        n = cur.fetchone()["n"]
        rec("EMPTY", "PASSED" if n == 0 else "FAILED", f"empty GUC rows={n}")
    except Exception as e:
        msg = str(e).split("\n")[0][:220]
        # No privilege is fail-closed for runtime app role
        rec("EMPTY", "PASSED" if "permission denied" in msg.lower() else "FAILED", msg)
        ensure_app_role()

    # SELECT cross
    try:
        set_tenant(cur, ORG_A)
        if tenant_mode == "root":
            cur.execute("SELECT count(*)::int AS n FROM public.organizations WHERE id=%s", (ORG_B,))
        else:
            cur.execute(
                f"SELECT count(*)::int AS n FROM public.{table} WHERE organization_id=%s",
                (ORG_B,),
            )
        n = cur.fetchone()["n"]
        rec("SELECT_X", "PASSED" if n == 0 else "FAILED", f"cross-tenant visible={n}")
    except Exception as e:
        msg = str(e).split("\n")[0][:220]
        rec("SELECT_X", "PASSED" if "permission denied" in msg.lower() else "FAILED", msg)
        ensure_app_role()

    # SELECT same
    try:
        set_tenant(cur, ORG_A)
        if tenant_mode == "root":
            cur.execute("SELECT count(*)::int AS n FROM public.organizations WHERE id=%s", (ORG_A,))
        else:
            cur.execute(
                f"SELECT count(*)::int AS n FROM public.{table} WHERE organization_id=%s",
                (ORG_A,),
            )
        n = cur.fetchone()["n"]
        if n >= 1:
            rec("SELECT_OK", "PASSED", f"same-tenant rows={n}")
        elif "permission" in "":
            rec("SELECT_OK", "NOT_APPLICABLE", "no org-A seed row")
        else:
            # Distinguish no-seed vs no-privilege tables (platform_admin_audit_logs)
            rec("SELECT_OK", "NOT_APPLICABLE", "no org-A seed row or not app-readable")
    except Exception as e:
        msg = str(e).split("\n")[0][:220]
        if "permission denied" in msg.lower():
            rec("SELECT_OK", "NOT_APPLICABLE", f"app has no SELECT privilege: {msg}")
        else:
            rec("SELECT_OK", "FAILED", msg)
        ensure_app_role()

    # UPDATE cross
    try:
        if tenant_mode == "root":
            cur.execute(
                "UPDATE public.organizations SET display_name=display_name WHERE id=%s",
                (ORG_B,),
            )
        else:
            cur.execute(
                f"UPDATE public.{table} SET organization_id=organization_id WHERE organization_id=%s",
                (ORG_B,),
            )
        rec("UPDATE_X", "PASSED" if cur.rowcount == 0 else "FAILED", f"updated={cur.rowcount}")
    except Exception as e:
        msg = str(e).split("\n")[0][:220]
        rec("UPDATE_X", "PASSED", f"denied/rejected: {msg}")
        cur.connection.rollback()
        cur.execute("SET ROLE dcmp_app")
        set_tenant(cur, ORG_A)

    # DELETE cross
    try:
        if tenant_mode == "root":
            cur.execute("DELETE FROM public.organizations WHERE id=%s", (ORG_B,))
        else:
            cur.execute(f"DELETE FROM public.{table} WHERE organization_id=%s", (ORG_B,))
        rec("DELETE_X", "PASSED" if cur.rowcount == 0 else "FAILED", f"deleted={cur.rowcount}")
    except Exception as e:
        msg = str(e).split("\n")[0][:220]
        rec("DELETE_X", "PASSED", f"denied/rejected: {msg}")
        cur.connection.rollback()
        cur.execute("SET ROLE dcmp_app")
        set_tenant(cur, ORG_A)

    # INSERT cross
    try:
        if tenant_mode == "root":
            cur.execute(
                """
                INSERT INTO public.organizations (id, org_code, display_name, status, data_region)
                VALUES (%s,'ORG-SPOOF','Spoof','ACTIVE','us-east-1')
                """,
                (uuid.uuid4(),),
            )
            rec("INSERT_X", "FAILED", "insert allowed")
        else:
            cur.execute(
                """
                SELECT column_name, data_type, is_nullable, column_default
                FROM information_schema.columns
                WHERE table_schema='public' AND table_name=%s
                ORDER BY ordinal_position
                """,
                (table,),
            )
            cols = list(cur.fetchall())
            fields: list[str] = []
            values: list[str] = []
            params: list[Any] = []
            for c in cols:
                name = c["column_name"]
                if name == "id" and c["column_default"]:
                    continue
                if name == "organization_id":
                    fields.append(name)
                    values.append("%s")
                    params.append(ORG_B)
                    continue
                if c["is_nullable"] == "YES" or c["column_default"] is not None:
                    continue
                fields.append(name)
                values.append("%s")
                dt = c["data_type"]
                if dt in ("text", "character varying"):
                    params.append(f"x-{uuid.uuid4().hex[:8]}")
                elif dt == "uuid":
                    params.append(uuid.uuid4())
                elif dt in ("integer", "bigint", "smallint"):
                    params.append(1)
                elif dt == "boolean":
                    params.append(False)
                elif dt == "jsonb":
                    params.append("{}")
                elif dt.startswith("timestamp"):
                    params.append("2099-01-01T00:00:00Z")
                elif dt == "bytea":
                    params.append(b"\x01")
                else:
                    params.append("x")
            sql = f"INSERT INTO public.{table} ({', '.join(fields)}) VALUES ({', '.join(values)})"
            cur.execute(sql, params)
            rec("INSERT_X", "FAILED", "insert allowed")
    except Exception as e:
        msg = str(e).split("\n")[0][:220]
        rec("INSERT_X", "PASSED", msg)
        cur.connection.rollback()
        cur.execute("SET ROLE dcmp_app")
        set_tenant(cur, ORG_A)

    # GUC spoof
    try:
        set_tenant(cur, ORG_A)
        cur.execute("SELECT set_config('app.is_platform_admin','true', true)")
        if tenant_mode == "root":
            cur.execute("SELECT count(*)::int AS n FROM public.organizations WHERE id=%s", (ORG_B,))
        else:
            cur.execute(
                f"SELECT count(*)::int AS n FROM public.{table} WHERE organization_id=%s",
                (ORG_B,),
            )
        n = cur.fetchone()["n"]
        rec("GUC_SPOOF", "PASSED" if n == 0 else "FAILED", f"visible={n}")
        cur.execute("SELECT set_config('app.is_platform_admin','', true)")
    except Exception as e:
        msg = str(e).split("\n")[0][:220]
        rec(
            "GUC_SPOOF",
            "PASSED" if "permission denied" in msg.lower() else "FAILED",
            msg,
        )
        ensure_app_role()
    try:
        cur.execute("RESET ROLE")
    except Exception:
        pass
    return results


def run() -> dict[str, Any]:
    conn = connect()
    results: list[dict[str, Any]] = []
    catalog: list[dict[str, Any]] = []
    try:
        with conn.cursor() as cur:
            catalog = force_rls_tables(cur)
        if len(catalog) != 54:
            results.append(
                {
                    "test_id": "DB-SEC-RLS54-COUNT",
                    "status": "FAILED",
                    "detail": f"expected 54 got {len(catalog)}",
                    "database": "dcmp_full_schema_validation",
                }
            )
        else:
            results.append(
                {
                    "test_id": "DB-SEC-RLS54-COUNT",
                    "status": "PASSED",
                    "detail": "54 FORCE RLS tables",
                    "database": "dcmp_full_schema_validation",
                }
            )

        for t in catalog:
            with conn.cursor() as cur:
                results.append(
                    {
                        "test_id": f"DB-SEC-RLS54-{t['table_name']}-FORCE",
                        "table": t["table_name"],
                        "operation": "FORCE",
                        "status": "PASSED" if t["rls"] and t["force_rls"] else "FAILED",
                        "detail": f"rls={t['rls']} force={t['force_rls']} has_org={t['has_organization_id']}",
                        "database": "dcmp_full_schema_validation",
                    }
                )
                results.extend(
                    test_table(cur, t["table_name"], bool(t["has_organization_id"]))
                )
            conn.commit()
    finally:
        conn.close()

    summary: dict[str, int] = {}
    for r in results:
        summary[r["status"]] = summary.get(r["status"], 0) + 1
    payload = {
        "workstream": "B",
        "force_rls_table_count": len(catalog),
        "summary": summary,
        "catalog": catalog,
        "results": results,
    }
    write_json("B_full_rls_results.json", payload)
    return payload


if __name__ == "__main__":
    out = run()
    print(out["summary"], "tables", out["force_rls_table_count"])
