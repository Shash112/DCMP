"""Workstream D — support-session SSA path against dcmp_full_schema_validation."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from typing import Any

from dbutil import ORG_A, ORG_B, USER_A, connect, write_json

# TEST-ONLY material — not for production
KID = "val-key-fullschema-1"
SECRET = b"validation-secret-key-32bytes!!"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_jwt(claims: dict[str, Any], *, secret: bytes = SECRET, kid: str = KID) -> str:
    header = {"alg": "HS256", "typ": "JWT", "kid": kid}
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(claims, separators=(",", ":")).encode())
    sig = hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64url(sig)}"


def bootstrap(cur) -> dict[str, uuid.UUID]:
    admin = uuid.UUID("99999999-9999-4999-8999-999999999999")
    req = uuid.uuid4()
    grant = uuid.uuid4()
    challenge = uuid.uuid4()
    ticket = uuid.uuid4()

    cur.execute("RESET SESSION AUTHORIZATION")
    cur.execute("RESET ROLE")
    cur.execute(
        """
        INSERT INTO dcmp_security.internal_keys (key_id, key_secret, status, valid_from)
        VALUES (%s, %s, 'ACTIVE', now() - interval '1 minute')
        ON CONFLICT (key_id) DO UPDATE
          SET key_secret=EXCLUDED.key_secret, status='ACTIVE', valid_until=NULL, valid_from=EXCLUDED.valid_from
        """,
        (KID, SECRET),
    )
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
        VALUES (%s,%s,'a@example.com','User A','scrypt$x$y')
        ON CONFLICT (id) DO NOTHING
        """,
        (USER_A, ORG_A),
    )
    cur.execute(
        """
        INSERT INTO public.platform_admins (id, email, display_name)
        VALUES (%s,'admin@example.com','Admin')
        ON CONFLICT (id) DO NOTHING
        """,
        (admin,),
    )
    cur.execute(
        """
        INSERT INTO public.support_tickets (id, organization_id, opened_by, ticket_number, subject, status)
        VALUES (%s, %s, %s, %s, 'Help', 'OPEN')
        ON CONFLICT (id) DO NOTHING
        """,
        (ticket, ORG_A, USER_A, f"T-{ticket.hex[:8]}"),
    )
    # Clear prior SSA state for deterministic tests
    cur.execute("DELETE FROM dcmp_security.support_session_challenges")
    cur.execute("DELETE FROM dcmp_security.consumed_support_assertions")
    cur.execute("DELETE FROM public.support_access_logs")
    cur.execute("DELETE FROM public.support_access_grants")
    cur.execute("DELETE FROM public.support_access_requests")

    cur.execute(
        """
        INSERT INTO public.support_access_requests
          (id, organization_id, ticket_id, admin_id, platform_admin_id, status)
        VALUES (%s, %s, %s, %s, %s, 'APPROVED')
        """,
        (req, ORG_A, ticket, admin, admin),
    )
    cur.execute(
        """
        INSERT INTO public.support_access_grants
          (id, organization_id, support_access_request_id, request_id, approved_by_user_id, expires_at)
        VALUES (%s, %s, %s, %s, %s, now() + interval '10 minutes')
        """,
        (grant, ORG_A, req, req, USER_A),
    )
    cur.execute(
        """
        INSERT INTO dcmp_security.support_session_challenges
          (id, challenge_id, admin_id, platform_admin_id, organization_id, grant_id, nonce, expires_at)
        VALUES (%s, %s, %s, %s, %s, %s, 'n1', now() + interval '5 minutes')
        """,
        (challenge, challenge, admin, admin, ORG_A, grant),
    )
    return {"admin": admin, "req": req, "grant": grant, "challenge": challenge, "ticket": ticket}


def base_claims(ids: dict[str, uuid.UUID], **overrides) -> dict[str, Any]:
    now = int(time.time())
    c = {
        "iss": "dcmp-platform-gateway",
        "aud": "dcmp-database-engine",
        "sub": str(ids["admin"]),
        "org_id": str(ORG_A),
        "grant_id": str(ids["grant"]),
        "req_id": str(ids["req"]),
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + 300,
    }
    c.update(overrides)
    return c


def try_open(jwt: str, ids: dict, org=None, grant=None, challenge=None) -> tuple[bool, str]:
    org = org or ORG_A
    grant = grant or ids["grant"]
    challenge = challenge or ids["challenge"]
    c = connect(dict_rows=False)
    try:
        with c.cursor() as cur:
            cur.execute("SET SESSION AUTHORIZATION dcmp_platform_admin")
            cur.execute(
                "SELECT dcmp_security.open_support_session(%s, %s, %s, %s)",
                (jwt, org, grant, challenge),
            )
            cur.execute("SELECT dcmp_security.verify_support_signature()")
            ok = bool(cur.fetchone()[0])
            # Bound SELECT should see tenant A users
            cur.execute("SELECT count(*) FROM public.users WHERE organization_id=%s", (ORG_A,))
            own = cur.fetchone()[0]
            cur.execute("SELECT count(*) FROM public.users WHERE organization_id=%s", (ORG_B,))
            other = cur.fetchone()[0]
            c.commit()
            return ok and own >= 1 and other == 0, f"verify={ok} own={own} other={other}"
    except Exception as e:
        try:
            c.rollback()
        except Exception:
            pass
        return False, str(e).split("\n")[0][:240]
    finally:
        c.close()


def run() -> dict[str, Any]:
    cases: list[dict[str, Any]] = []

    def rec(tid, name, passed, detail, notes=None):
        cases.append(
            {
                "test_id": tid,
                "name": name,
                "status": "PASSED" if passed else "FAILED",
                "detail": detail,
                "notes": notes,
                "database": "dcmp_full_schema_validation",
                "harness": "tests/phase-2.1.19/test_d_support_ssa.py",
                "key_material": "TEST-ONLY",
            }
        )

    conn = connect()
    try:
        with conn.cursor() as cur:
            # constant_time_eq
            cur.execute(
                "SELECT dcmp_security.constant_time_eq(digest('a','sha256'), digest('a','sha256'))"
            )
            ok = cur.fetchone()["constant_time_eq"]
            cur.execute(
                "SELECT dcmp_security.constant_time_eq(digest('a','sha256'), digest('b','sha256'))"
            )
            bad = cur.fetchone()["constant_time_eq"]
            rec("DB-SEC-062", "constant_time_eq", ok and (not bad), f"eq={ok} ne={bad}")

            ids = bootstrap(cur)
        conn.commit()

        # Happy path
        ok, detail = try_open(make_jwt(base_claims(ids)), ids)
        rec("DB-SEC-SSA-001", "open+verify happy path", ok, detail)

        # Forged GUC without open
        with connect().cursor() as cur:
            cur.execute("SET SESSION AUTHORIZATION dcmp_platform_admin")
            cur.execute("SELECT set_config('app.support_signature', 'deadbeef', true)")
            cur.execute("SELECT set_config('app.current_organization_id', %s, true)", (str(ORG_A),))
            cur.execute("SELECT dcmp_security.verify_support_signature()")
            v = cur.fetchone()["verify_support_signature"]
            cur.execute("SELECT count(*)::int AS n FROM public.users")
            n = cur.fetchone()["n"]
            rec("DB-SEC-009", "forged support GUC fails", (not v) and n == 0, f"verify={v} rows={n}")

        # Bad iss/aud
        ok, detail = try_open(make_jwt(base_claims(ids, iss="evil")), ids)
        rec("DB-SEC-041", "invalid iss rejected", not ok, detail)

        # Org mismatch
        ok, detail = try_open(make_jwt(base_claims(ids, org_id=str(ORG_B))), ids, org=ORG_A)
        rec("DB-SEC-010", "org claim mismatch rejected", not ok, detail)

        # Expired grant
        with conn.cursor() as cur:
            ids2 = bootstrap(cur)
            cur.execute(
                "UPDATE public.support_access_grants SET expires_at=now()-interval '1 minute' WHERE id=%s",
                (ids2["grant"],),
            )
        conn.commit()
        ok, detail = try_open(make_jwt(base_claims(ids2)), ids2)
        rec("DB-SEC-013", "expired grant rejected", not ok, detail)

        # Replay JTI
        with conn.cursor() as cur:
            ids3 = bootstrap(cur)
        conn.commit()
        claims = base_claims(ids3)
        jwt = make_jwt(claims)
        ok1, d1 = try_open(jwt, ids3)
        # Need fresh challenge for second open attempt with same jti — bootstrap new challenge but same jti
        with conn.cursor() as cur:
            challenge2 = uuid.uuid4()
            cur.execute(
                """
                INSERT INTO dcmp_security.support_session_challenges
                  (id, challenge_id, admin_id, platform_admin_id, organization_id, grant_id, nonce, expires_at)
                VALUES (%s,%s,%s,%s,%s,%s,'n2', now()+interval '5 minutes')
                """,
                (
                    challenge2,
                    challenge2,
                    ids3["admin"],
                    ids3["admin"],
                    ORG_A,
                    ids3["grant"],
                ),
            )
            ids3["challenge"] = challenge2
        conn.commit()
        ok2, d2 = try_open(jwt, ids3)
        rec(
            "DB-SEC-034",
            "JTI replay rejected",
            ok1 and (not ok2),
            f"first={d1}; second={d2}",
        )

        # Platform admin without SSA cannot read users
        with connect().cursor() as cur:
            cur.execute("SET SESSION AUTHORIZATION dcmp_platform_admin")
            cur.execute("SELECT set_config('app.current_organization_id', %s, true)", (str(ORG_A),))
            cur.execute("SELECT count(*)::int AS n FROM public.users")
            n = cur.fetchone()["n"]
            rec(
                "DB-SEC-058",
                "platform admin without SSA fail-closed",
                n == 0,
                f"rows={n}",
                notes="SELECT policies require verify_support_signature()",
            )

        # Application gateway SSA minting remains app-layer
        rec(
            "DB-SEC-SSA-GATEWAY",
            "HTTP gateway SSA minting",
            False,
            "NOT_RUN",
        )
        # Fix status for gateway
        cases[-1]["status"] = "NOT_RUN"
        cases[-1]["detail"] = "Nest gateway SSA issuance not in scope for SQL pack"
    finally:
        conn.close()

    summary: dict[str, int] = {}
    for c in cases:
        summary[c["status"]] = summary.get(c["status"], 0) + 1
    payload = {
        "workstream": "D",
        "summary": summary,
        "cases": cases,
        "limitations": [
            "SQL SSA path validated; application gateway that mints SSA JWTs remains separate",
            "Test key material only",
        ],
    }
    write_json("D_support_ssa_results.json", payload)
    return payload


if __name__ == "__main__":
    print(run()["summary"])
