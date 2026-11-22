"""C — DPoP / gateway integration harness.

Auth HTTP gateway and DPoP verifier are not implemented in this repository.
This harness documents ordering contradictions vs ADRs, runs DB-level jkt
binding checks available today, and marks full HTTP DPoP cases NOT RUN.
"""
from __future__ import annotations

from dbutil import connect, write_json
from refresh_protocol import refresh_once, reset_seed

ORDERING_DOCUMENTED = [
    "1. Signature and claim validation (Gateway/DPoP — NOT IMPLEMENTED)",
    "2. Idempotency lookup (PostgreSQL — implemented in harness)",
    "3. Nonce and replay validation (Gateway — NOT IMPLEMENTED)",
    "4. PostgreSQL token/session state validation (implemented in harness)",
    "5. Token rotation (conditional UPDATE — implemented in harness)",
    "6. Durable idempotency record persistence (implemented in harness)",
]

CONTRADICTIONS = [
    {
        "topic": "DPoP HTTP gateway",
        "finding": "No AuthModule /refresh endpoint or RFC 9449 verifier exists in repo; cannot execute HTTP DPoP cases.",
        "impact": "DB-SEC-018/019 and most DPoP matrix rows remain NOT RUN",
    },
    {
        "topic": "Ordering vs harness",
        "finding": "Harness starts at step 2 (idempotency) because steps 1 and 3 have no application code.",
        "impact": "Concurrency results validate PG authority only, not full DPoP admission control",
    },
]


def run() -> dict:
    conn = connect()
    cases = []

    seed = reset_seed(conn, "c-jkt")
    r1 = refresh_once(seed, seed.fp_a, seed.token_hash)
    r2 = refresh_once(seed, seed.fp_a, seed.token_hash, dpop_jkt="wrong-jkt")
    cases.append(
        {
            "id": "C-JKT/DB-SEC-095",
            "name": "Wrong DPoP key thumbprint on recovery",
            "status": "PASSED" if (r1.http_status == 200 and r2.http_status == 401) else "FAILED",
            "type": "application-harness",
            "actual": {"r1": r1.__dict__, "r2": r2.__dict__},
        }
    )

    seed = reset_seed(conn, "c-same")
    r1 = refresh_once(seed, seed.fp_a, seed.token_hash)
    r2 = refresh_once(seed, seed.fp_a, seed.token_hash)
    cases.append(
        {
            "id": "C-SAME",
            "name": "Same-proof retry (PG fingerprint path)",
            "status": "PASSED" if r2.outcome == "RECOVERED" else "FAILED",
            "type": "application-harness",
            "actual": {"r1": r1.__dict__, "r2": r2.__dict__},
        }
    )

    not_run = [
        ("C-VALID", "Valid DPoP proof", "No HTTP DPoP verifier"),
        ("C-BADSIG", "Invalid signature", "No HTTP DPoP verifier"),
        ("C-METHOD", "Wrong HTTP method", "No HTTP gateway"),
        ("C-URI", "Wrong HTTP URI", "No HTTP gateway"),
        ("C-EXPIRED", "Expired proof", "No HTTP DPoP verifier"),
        ("C-JTI", "Reused proof JTI", "No nonce/JTI store in app"),
        ("C-CONCUR-SAME", "Concurrent same-proof HTTP", "Covered at PG layer by A1; HTTP NOT RUN"),
        ("C-DIVERGENT", "Divergent proof HTTP", "Covered at PG layer by A2; HTTP NOT RUN"),
        ("C-REVOKED-RETRY", "Session revoked before retry", "Covered by A9; HTTP NOT RUN"),
        ("C-REDIS", "Redis unavailable during proof processing", "SIMULATED in B; no DPoP layer"),
    ]
    for cid, name, reason in not_run:
        cases.append(
            {
                "id": cid,
                "name": name,
                "status": "NOT RUN",
                "type": "integration",
                "blocker": reason,
            }
        )

    conn.close()
    summary = {
        "group": "C_dpop_gateway",
        "documented_ordering": ORDERING_DOCUMENTED,
        "contradictions": CONTRADICTIONS,
        "cases": cases,
        "passed": sum(1 for c in cases if c.get("status") == "PASSED"),
        "failed": sum(1 for c in cases if c.get("status") == "FAILED"),
        "not_run": sum(1 for c in cases if c.get("status") == "NOT RUN"),
    }
    write_json("C_dpop_results.json", summary)
    return summary


if __name__ == "__main__":
    import pprint

    pprint.pp(run())
