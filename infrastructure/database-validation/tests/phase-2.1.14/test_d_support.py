"""D — Support authorization / SSA validation against PostgreSQL functions."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from typing import Any

import psycopg

from dbutil import ORG_A, connect, write_json

KID = "val-key-1"
# Must match seed in run_db_sec_suite / harness bootstrap
SECRET = b"validation-secret-key-32bytes!!"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_jwt(claims: dict[str, Any], *, secret: bytes = SECRET, kid: str = KID, alg: str = "HS256", typ: str = "JWT") -> str:
    header = {"alg": alg, "typ": typ, "kid": kid}
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(claims, separators=(",", ":")).encode())
    sig = hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64url(sig)}"


def bootstrap_support(conn: psycopg.Connection) -> dict[str, uuid.UUID]:
    admin = uuid.UUID("99999999-9999-4999-8999-999999999999")
    req = uuid.uuid4()
    grant = uuid.uuid4()
    challenge = uuid.uuid4()
    with conn.cursor() as cur:
        cur.execute("RESET SESSION AUTHORIZATION")
        cur.execute(
            """
            INSERT INTO dcmp_security.internal_keys (key_id, key_secret, status, valid_from)
            VALUES (%s, %s, 'ACTIVE', now() - interval '1 minute')
            ON CONFLICT (key_id) DO UPDATE
              SET key_secret = EXCLUDED.key_secret, status = 'ACTIVE', valid_until = NULL
            """,
            (KID, SECRET),
        )
        cur.execute(
            """
            INSERT INTO public.organizations (id, org_code, display_name, status, data_region)
            VALUES (%s, 'ORG-A', 'Tenant A', 'ACTIVE', 'us-east-1')
            ON CONFLICT (id) DO NOTHING
            """,
            (ORG_A,),
        )
        cur.execute("DELETE FROM dcmp_security.support_session_challenges")
        cur.execute("DELETE FROM dcmp_security.consumed_support_assertions")
        cur.execute("DELETE FROM public.support_access_grants")
        cur.execute("DELETE FROM public.support_access_requests")
        cur.execute(
            """
            INSERT INTO public.support_access_requests
              (id, organization_id, platform_admin_id, status)
            VALUES (%s, %s, %s, 'APPROVED')
            """,
            (req, ORG_A, admin),
        )
        cur.execute(
            """
            INSERT INTO public.support_access_grants
              (id, request_id, organization_id, status, expires_at)
            VALUES (%s, %s, %s, 'ACTIVE', now() + interval '10 minutes')
            """,
            (grant, req, ORG_A),
        )
        cur.execute(
            """
            INSERT INTO dcmp_security.support_session_challenges
              (challenge_id, platform_admin_id, organization_id, grant_id, expires_at)
            VALUES (%s, %s, %s, %s, now() + interval '5 minutes')
            """,
            (challenge, admin, ORG_A, grant),
        )
    return {"admin": admin, "req": req, "grant": grant, "challenge": challenge}


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


def try_open(conn: psycopg.Connection, jwt: str, ids: dict, org=None, grant=None, challenge=None) -> tuple[bool, str]:
    org = org or ORG_A
    grant = grant or ids["grant"]
    challenge = challenge or ids["challenge"]
    # Use a dedicated connection so SET SESSION AUTHORIZATION cannot leak / lock the seed conn.
    c = psycopg.connect(
        host="127.0.0.1", port=55432, dbname="dcmp_validation", user="dcmp_val_super"
    )
    try:
        c.autocommit = False
        with c.cursor() as cur:
            cur.execute("SET SESSION AUTHORIZATION dcmp_platform_admin")
            cur.execute(
                "SELECT dcmp_security.open_support_session(%s, %s, %s, %s)",
                (jwt, org, grant, challenge),
            )
            cur.execute("SELECT dcmp_security.verify_support_signature()")
            ok = cur.fetchone()[0]
            c.commit()
            return bool(ok), "opened+verified" if ok else "verify false"
    except Exception as e:
        try:
            c.rollback()
        except Exception:
            pass
        return False, str(e).split("\n")[0][:240]
    finally:
        try:
            c.close()
        except Exception:
            pass


def run() -> dict:
    conn = connect()
    cases = []

    def record(cid, name, passed, detail, notes=None):
        cases.append(
            {
                "id": cid,
                "name": name,
                "status": "PASSED" if passed else "FAILED",
                "detail": detail,
                "notes": notes,
            }
        )

    # Valid
    ids = bootstrap_support(conn)
    jwt = make_jwt(base_claims(ids))
    ok, detail = try_open(conn, jwt, ids)
    record("D1", "Valid signed support authorization", ok, detail)

    # Invalid signature
    ids = bootstrap_support(conn)
    jwt = make_jwt(base_claims(ids), secret=b"wrong-secret-key-material-32b!!")
    ok, detail = try_open(conn, jwt, ids)
    record("D2", "Invalid signature", (not ok) and ("28009" in detail or "Signature" in detail or "28000" in detail), detail)

    # Modified organization ID (claim vs arg)
    ids = bootstrap_support(conn)
    claims = base_claims(ids)
    jwt = make_jwt(claims)
    other_org = uuid.UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO public.organizations (id, org_code, display_name, status, data_region)
            VALUES (%s, 'ORG-B', 'Tenant B', 'ACTIVE', 'us-east-1')
            ON CONFLICT (id) DO NOTHING
            """,
            (other_org,),
        )
    ok, detail = try_open(conn, jwt, ids, org=other_org)
    record("D3", "Modified organization ID (arg mismatch)", not ok, detail)

    # Modified grant ID
    ids = bootstrap_support(conn)
    jwt = make_jwt(base_claims(ids))
    fake_grant = uuid.uuid4()
    ok, detail = try_open(conn, jwt, ids, grant=fake_grant)
    record("D4", "Modified grant ID", not ok, detail)

    # Modified admin ID (sub)
    ids = bootstrap_support(conn)
    claims = base_claims(ids, sub=str(uuid.uuid4()))
    jwt = make_jwt(claims)
    ok, detail = try_open(conn, jwt, ids)
    record("D5", "Modified admin ID (sub)", not ok, detail)

    # Expired grant
    ids = bootstrap_support(conn)
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE public.support_access_grants SET expires_at = now() - interval '1 minute' WHERE id=%s",
            (ids["grant"],),
        )
    jwt = make_jwt(base_claims(ids))
    ok, detail = try_open(conn, jwt, ids)
    record("D6", "Expired grant", not ok, detail)

    # Revoked grant
    ids = bootstrap_support(conn)
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE public.support_access_grants SET revoked_at = now() WHERE id=%s",
            (ids["grant"],),
        )
    jwt = make_jwt(base_claims(ids))
    ok, detail = try_open(conn, jwt, ids)
    record("D7", "Revoked grant", not ok, detail)

    # Unapproved administrator / request
    ids = bootstrap_support(conn)
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE public.support_access_requests SET status='PENDING' WHERE id=%s",
            (ids["req"],),
        )
    jwt = make_jwt(base_claims(ids))
    ok, detail = try_open(conn, jwt, ids)
    record("D8", "Unapproved administrator request", not ok, detail)

    # Expired SSA
    ids = bootstrap_support(conn)
    now = int(time.time())
    jwt = make_jwt(base_claims(ids, iat=now - 600, exp=now - 300))
    ok, detail = try_open(conn, jwt, ids)
    record("D9", "Expired SSA", not ok, detail)

    # Wrong issuer
    ids = bootstrap_support(conn)
    jwt = make_jwt(base_claims(ids, iss="evil-issuer"))
    ok, detail = try_open(conn, jwt, ids)
    record("D10", "Wrong issuer", not ok, detail)

    # Wrong audience
    ids = bootstrap_support(conn)
    jwt = make_jwt(base_claims(ids, aud="wrong-aud"))
    ok, detail = try_open(conn, jwt, ids)
    record("D11", "Wrong audience", not ok, detail)

    # Invalid algorithm
    ids = bootstrap_support(conn)
    jwt = make_jwt(base_claims(ids), alg="none")
    ok, detail = try_open(conn, jwt, ids)
    record("D12", "Invalid algorithm/typ", not ok, detail)

    # Replayed JTI
    ids = bootstrap_support(conn)
    jti = str(uuid.uuid4())
    jwt1 = make_jwt(base_claims(ids, jti=jti))
    ok1, d1 = try_open(conn, jwt1, ids)
    # new challenge for second open attempt with same jti
    challenge2 = uuid.uuid4()
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO dcmp_security.support_session_challenges
              (challenge_id, platform_admin_id, organization_id, grant_id, expires_at)
            VALUES (%s, %s, %s, %s, now() + interval '5 minutes')
            """,
            (challenge2, ids["admin"], ORG_A, ids["grant"]),
        )
    jwt2 = make_jwt(base_claims(ids, jti=jti))
    ok2, d2 = try_open(conn, jwt2, ids, challenge=challenge2)
    record("D13", "Replayed request/JTI identifier", ok1 and (not ok2), f"first={d1}; second={d2}")

    # GUC forgery without open_support_session
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute("SET SESSION AUTHORIZATION dcmp_platform_admin")
        cur.execute("SELECT set_config('app.current_organization_id', %s, false)", (str(ORG_A),))
        cur.execute("SELECT set_config('app.active_support_grant_id', %s, false)", (str(uuid.uuid4()),))
        cur.execute("SELECT set_config('app.authenticated_admin_id', %s, false)", (str(uuid.uuid4()),))
        cur.execute("SELECT set_config('app.support_challenge_id', %s, false)", (str(uuid.uuid4()),))
        cur.execute("SELECT set_config('app.support_signature', %s, false)", ("deadbeef" * 8,))
        cur.execute("SELECT dcmp_security.verify_support_signature()")
        forged = cur.fetchone()[0]
        cur.execute("RESET SESSION AUTHORIZATION")
    record(
        "D14",
        "Arbitrary GUC cannot grant support authorization",
        forged is False,
        f"verify_support_signature={forged}",
    )

    # Missing DPoP where required — gateway not implemented
    cases.append(
        {
            "id": "D15",
            "name": "Missing/invalid DPoP proof where required",
            "status": "NOT RUN",
            "detail": "Gateway authentication / DPoP binding for support access not implemented",
            "notes": "SQL function path only; end-to-end NOT RUN",
        }
    )

    cases.append(
        {
            "id": "D16",
            "name": "Administrator identity authenticated by trusted gateway",
            "status": "NOT RUN",
            "detail": "Trusted gateway JWT issuance path not present; SSA HMAC validated in DB only",
        }
    )

    conn.close()
    summary = {
        "group": "D_support_authorization",
        "scope_note": "SQL function validation against open_support_session/verify_support_signature. Gateway E2E NOT RUN.",
        "passed": sum(1 for c in cases if c.get("status") == "PASSED"),
        "failed": sum(1 for c in cases if c.get("status") == "FAILED"),
        "not_run": sum(1 for c in cases if c.get("status") == "NOT RUN"),
        "cases": cases,
    }
    write_json("D_support_results.json", summary)
    return summary


if __name__ == "__main__":
    import pprint

    pprint.pp(run())
