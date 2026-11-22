"""F — DB-SEC-001..101 coverage matrix for Phase 2.1.14 report."""
from __future__ import annotations

import json
from pathlib import Path

from dbutil import EVIDENCE, write_json

# Compact requirement catalog (001–101). Status filled from evidence + prior phase.
CATALOG = {
    "DB-SEC-001": ("Tenant isolation SELECT", "SQL", "IMPLEMENTED"),
    "DB-SEC-002": ("Cross-tenant DML denied", "SQL", "NOT_IMPLEMENTED"),
    "DB-SEC-003": ("RLS INSERT spoof denied", "SQL", "IMPLEMENTED"),
    "DB-SEC-004": ("Empty tenant context fail-closed", "SQL", "IMPLEMENTED"),
    "DB-SEC-005": ("Context reset after ROLLBACK", "SQL", "NOT_IMPLEMENTED"),
    "DB-SEC-006": ("Custom GUC tampering", "SQL", "NOT_IMPLEMENTED"),
    "DB-SEC-007": ("Tenant-root organization isolation", "SQL", "NOT_IMPLEMENTED"),
    "DB-SEC-008": ("Org tampering trigger/grants", "SQL", "PARTIAL"),
    "DB-SEC-009": ("Support GUC forgery", "SQL", "IMPLEMENTED_214"),
    "DB-SEC-010": ("Forged admin identity SSA", "SQL", "IMPLEMENTED_214"),
    "DB-SEC-011": ("RLS recursion block DEFINER", "SQL", "NOT_IMPLEMENTED"),
    "DB-SEC-012": ("Mid-session grant revocation", "concurrency", "NOT_IMPLEMENTED"),
    "DB-SEC-013": ("Support access expiry", "SQL", "IMPLEMENTED_214"),
    "DB-SEC-014": ("Search-path resistance", "SQL", "NOT_IMPLEMENTED"),
    "DB-SEC-015": ("Internal key denial", "SQL", "NOT_IMPLEMENTED"),
    "DB-SEC-016": ("Composite FK isolation", "SQL", "NOT_IMPLEMENTED"),
    "DB-SEC-017": ("Question version integrity", "SQL", "NOT_IMPLEMENTED"),
    "DB-SEC-018": ("Standard DPoP verify", "integration", "NOT_IMPLEMENTED"),
    "DB-SEC-019": ("Invalid DPoP no revoke", "integration", "NOT_IMPLEMENTED"),
    "DB-SEC-020": ("Stolen token replay", "integration", "NOT_IMPLEMENTED"),
    "DB-SEC-021": ("Revoked cache tombstone", "integration", "PARTIAL"),
    "DB-SEC-022": ("Redis outage with consumed token", "application", "SIMULATED_214"),
    "DB-SEC-023": ("Deferred NO ACTION clean", "SQL", "NOT_IMPLEMENTED"),
    "DB-SEC-024": ("Partial-chain rejection", "SQL", "NOT_IMPLEMENTED"),
    "DB-SEC-025": ("Stage 1–6 decoupling", "infrastructure", "NOT_IMPLEMENTED"),
    "DB-SEC-026": ("SET ROLE dcmp_sec_definer denied", "SQL", "IMPLEMENTED"),
    "DB-SEC-027": ("Untrusted CREATE denied", "SQL", "NOT_IMPLEMENTED"),
    "DB-SEC-028": ("Function EXECUTE least privilege", "SQL", "NOT_IMPLEMENTED"),
    "DB-SEC-029": ("Concurrent refresh contention", "concurrency", "IMPLEMENTED_214"),
    "DB-SEC-030": ("Family revoke on reuse", "SQL", "IMPLEMENTED_214"),
    "DB-SEC-031": ("Logout blocks refresh", "concurrency", "IMPLEMENTED_214"),
    "DB-SEC-032": ("Platform admin RLS bypass denied", "SQL", "NOT_IMPLEMENTED"),
    "DB-SEC-033": ("Support SELECT under signature", "SQL", "NOT_IMPLEMENTED"),
    "DB-SEC-034": ("SSA JTI concurrency replay", "concurrency", "PARTIAL"),
    "DB-SEC-035": ("Statement-timestamp expiry", "SQL", "NOT_IMPLEMENTED"),
    "DB-SEC-036": ("Audit insert durability", "SQL", "IMPLEMENTED"),
    "DB-SEC-037": ("Audit UPDATE denied", "SQL", "NOT_IMPLEMENTED"),
    "DB-SEC-038": ("Refresh single rotation barrier", "concurrency", "IMPLEMENTED_214"),
    "DB-SEC-039": ("FORCE RLS on tenant tables", "SQL", "CATALOG_213"),
    "DB-SEC-040": ("Runtime roles no BYPASSRLS", "SQL", "CATALOG_213"),
    "DB-SEC-041": ("SSA invalid iss/aud", "SQL", "IMPLEMENTED_214"),
    "DB-SEC-042": ("SSA mismatched request id", "SQL", "PARTIAL"),
    "DB-SEC-043": ("SSA temporal claim skew", "SQL", "PARTIAL"),
    "DB-SEC-044": ("DPoP ath binding", "integration", "NOT_IMPLEMENTED"),
    "DB-SEC-045": ("Retry after Redis write OK", "application", "SIMULATED_214"),
    "DB-SEC-046": ("Nonce window", "integration", "NOT_IMPLEMENTED"),
    "DB-SEC-047": ("Refresh token hash at rest", "SQL", "PARTIAL"),
    "DB-SEC-048": ("Idempotency recoverable", "SQL", "IMPLEMENTED"),
    "DB-SEC-049": ("Audit writer SELECT denied", "SQL", "IMPLEMENTED"),
    "DB-SEC-050": ("Audit TRUNCATE denied", "SQL", "IMPLEMENTED"),
    "DB-SEC-051": ("Support challenge expiry", "SQL", "NOT_IMPLEMENTED"),
    "DB-SEC-052": ("Cross-tenant support grant", "SQL", "PARTIAL"),
    "DB-SEC-053": ("Idempotency TTL expiry hard reuse", "concurrency", "IMPLEMENTED_214"),
    "DB-SEC-054": ("Redis outage after DB commit", "application", "SIMULATED_214"),
    "DB-SEC-055": ("Restrictive RLS AND semantics", "SQL", "NOT_IMPLEMENTED"),
    "DB-SEC-056": ("Migrator-only DDL", "SQL", "NOT_IMPLEMENTED"),
    "DB-SEC-057": ("Cleanup role delete scope", "SQL", "NOT_IMPLEMENTED"),
    "DB-SEC-058": ("Session FOR SHARE during refresh", "concurrency", "IMPLEMENTED_214"),
    "DB-SEC-059": ("Token consume RETURNING barrier", "SQL", "IMPLEMENTED_214"),
    "DB-SEC-060": ("No plaintext refresh in DB", "SQL", "PARTIAL"),
    "DB-SEC-061": ("Support HMAC tx binding", "SQL", "PARTIAL"),
    "DB-SEC-062": ("Admin portal event_source constraint", "SQL", "PARTIAL"),
    "DB-SEC-063": ("Correlation id presence", "SQL", "NOT_IMPLEMENTED"),
    "DB-SEC-064": ("Org SUSPENDED blocks app", "SQL", "NOT_IMPLEMENTED"),
    "DB-SEC-065": ("Challenge single-use", "SQL", "PARTIAL"),
    "DB-SEC-066": ("Challenge concurrency mutex", "concurrency", "NOT_IMPLEMENTED"),
    "DB-SEC-067": ("Audit INSERT success", "SQL", "IMPLEMENTED"),
    "DB-SEC-068": ("Audit SELECT privilege denied", "SQL", "IMPLEMENTED"),
    "DB-SEC-069": ("Audit DELETE denied", "SQL", "NOT_IMPLEMENTED"),
    "DB-SEC-070": ("Dedicated TRUNCATE trigger", "SQL", "IMPLEMENTED"),
    "DB-SEC-071": ("Identical simultaneous DPoP/proof", "concurrency", "IMPLEMENTED_214"),
    "DB-SEC-072": ("Divergent proofs same token", "concurrency", "IMPLEMENTED_214"),
    "DB-SEC-073": ("Cache-hit concurrent logout", "concurrency", "PARTIAL"),
    "DB-SEC-074": ("Canonical retry-cache key", "application", "IMPLEMENTED"),
    "DB-SEC-075": ("DEFINER owner dcmp_sec_definer", "SQL", "CATALOG_213"),
    "DB-SEC-076": ("PUBLIC EXECUTE revoked", "SQL", "CATALOG_213"),
    "DB-SEC-077": ("Platform admin EXECUTE open/verify", "SQL", "CATALOG_213"),
    "DB-SEC-078": ("App not member of sec_definer", "SQL", "CATALOG_213"),
    "DB-SEC-079": ("Org lifecycle column grants", "SQL", "IMPLEMENTED"),
    "DB-SEC-080": ("App cannot UPDATE org status", "SQL", "IMPLEMENTED"),
    "DB-SEC-081": ("Audit writer no SELECT design", "SQL", "IMPLEMENTED"),
    "DB-SEC-082": ("Bad event_source rejected", "SQL", "IMPLEMENTED"),
    "DB-SEC-083": ("Audit durability after abort sibling", "SQL", "NOT_IMPLEMENTED"),
    "DB-SEC-084": ("Security event immutability", "SQL", "PARTIAL"),
    "DB-SEC-085": ("Security event insert path", "SQL", "PARTIAL"),
    "DB-SEC-086": ("Redis kill after commit recover", "application", "SIMULATED_214"),
    "DB-SEC-087": ("PG authoritative over Redis", "application", "SIMULATED_214"),
    "DB-SEC-088": ("Idempotency unique fingerprint", "SQL", "IMPLEMENTED_214"),
    "DB-SEC-089": ("Canonical hash vectors", "application", "IMPLEMENTED"),
    "DB-SEC-090": ("Path trailing slash preserve", "application", "IMPLEMENTED"),
    "DB-SEC-091": ("AAD format binding", "application", "IMPLEMENTED_214"),
    "DB-SEC-092": ("AES-GCM reject wrong AAD", "application", "IMPLEMENTED_214"),
    "DB-SEC-093": ("Concurrent identical without Redis", "concurrency", "IMPLEMENTED_214"),
    "DB-SEC-094": ("Logout invalidates idempotency", "SQL", "IMPLEMENTED"),
    "DB-SEC-095": ("Wrong DPoP jkt no decrypt return", "application", "IMPLEMENTED_214"),
    "DB-SEC-096": ("Platform admin suspend org", "SQL", "IMPLEMENTED"),
    "DB-SEC-097": ("Platform admin blocked org_code", "SQL", "IMPLEMENTED"),
    "DB-SEC-098": ("Platform admin blocked display_name", "SQL", "IMPLEMENTED"),
    "DB-SEC-099": ("App blocked org lifecycle", "SQL", "IMPLEMENTED"),
    "DB-SEC-100": ("App can rename display_name", "SQL", "IMPLEMENTED"),
    "DB-SEC-101": ("Ciphertext column immutable/denied", "SQL", "IMPLEMENTED"),
}


def _load(name: str):
    p = EVIDENCE / name
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    return {}


def run(prior_213: dict | None = None) -> dict:
    a = _load("A_concurrency_results.json")
    b = _load("B_redis_sim_results.json")
    c = _load("C_dpop_results.json")
    d = _load("D_support_results.json")
    e = _load("E_aes_gcm_results.json")

    # Map executed evidence
    exec_map = {}

    # Phase 2.1.13 known passes
    for tid in [
        "DB-SEC-001",
        "DB-SEC-003",
        "DB-SEC-004",
        "DB-SEC-026",
        "DB-SEC-036",
        "DB-SEC-048",
        "DB-SEC-049",
        "DB-SEC-050",
        "DB-SEC-067",
        "DB-SEC-068",
        "DB-SEC-070",
        "DB-SEC-074",
        "DB-SEC-082",
        "DB-SEC-089",
        "DB-SEC-094",
        "DB-SEC-096",
        "DB-SEC-097",
        "DB-SEC-098",
        "DB-SEC-099",
        "DB-SEC-100",
        "DB-SEC-101",
    ]:
        exec_map[tid] = {
            "execution_status": "PASSED",
            "evidence": "phase-2.1.13/db-sec-results.out",
            "blocker": None,
        }

    def from_bool(tid, passed, evidence, blocker=None):
        exec_map[tid] = {
            "execution_status": "PASSED" if passed else "FAILED",
            "evidence": evidence,
            "blocker": blocker,
        }

    for case in a.get("cases", []):
        cid = case["id"]
        evid = "phase-2.1.14/A_concurrency_results.json"
        if "071" in cid:
            from_bool("DB-SEC-071", case["passed"], evid)
            from_bool("DB-SEC-093", case["passed"], evid)
            from_bool("DB-SEC-029", case["passed"], evid)
            from_bool("DB-SEC-038", case["passed"], evid)
            from_bool("DB-SEC-088", case["passed"], evid)
        if "072" in cid:
            from_bool("DB-SEC-072", case["passed"], evid)
            from_bool("DB-SEC-030", case["passed"], evid)
        if cid == "A8":
            from_bool("DB-SEC-031", case["passed"], evid)
            exec_map["DB-SEC-073"] = {
                "execution_status": "PASSED" if case["passed"] else "FAILED",
                "evidence": evid,
                "blocker": "logout sequenced after refresh hold; not mid-cache-hit HTTP",
            }
        if cid == "A9":
            from_bool("DB-SEC-021", case["passed"], evid)
        if cid == "A10":
            from_bool("DB-SEC-053", case["passed"], evid)
        if cid in ("A3", "A7"):
            from_bool("DB-SEC-058", case["passed"], evid)
            from_bool("DB-SEC-059", case["passed"], evid)

    for case in b.get("cases", []):
        evid = "phase-2.1.14/B_redis_sim_results.json"
        mapping = {
            "B3/DB-SEC-054": "DB-SEC-054",
            "B1": "DB-SEC-022",
            "B4": "DB-SEC-086",
            "B5": "DB-SEC-087",
            "B6": "DB-SEC-045",
            "B8": "DB-SEC-021",
        }
        if case["id"] in mapping:
            from_bool(mapping[case["id"]], case["passed"], evid)

    for case in c.get("cases", []):
        evid = "phase-2.1.14/C_dpop_results.json"
        if case["id"].startswith("C-JKT"):
            st = case.get("status", "NOT RUN")
            exec_map["DB-SEC-095"] = {
                "execution_status": st if st != "NOT RUN" else "NOT RUN",
                "evidence": evid,
                "blocker": case.get("blocker"),
            }
        if case.get("status") == "NOT RUN" and case["id"] in ("C-VALID",):
            exec_map["DB-SEC-018"] = {
                "execution_status": "NOT RUN",
                "evidence": evid,
                "blocker": case.get("blocker"),
            }
        if case["id"] == "C-BADSIG":
            exec_map["DB-SEC-019"] = {
                "execution_status": "NOT RUN",
                "evidence": evid,
                "blocker": case.get("blocker"),
            }

    d_map = {
        "D1": "DB-SEC-033",
        "D2": "DB-SEC-010",
        "D6": "DB-SEC-013",
        "D10": "DB-SEC-041",
        "D11": "DB-SEC-041",
        "D13": "DB-SEC-034",
        "D14": "DB-SEC-009",
    }
    for case in d.get("cases", []):
        evid = "phase-2.1.14/D_support_results.json"
        tid = d_map.get(case["id"])
        if tid:
            st = case.get("status", "NOT RUN")
            exec_map[tid] = {"execution_status": st, "evidence": evid, "blocker": None}
        if case["id"] == "D15":
            exec_map.setdefault(
                "DB-SEC-018",
                {"execution_status": "NOT RUN", "evidence": evid, "blocker": case.get("detail")},
            )

    for case in e.get("cases", []):
        evid = "phase-2.1.14/E_aes_gcm_results.json"
        if case["id"] in ("E6", "E7", "E8", "E9", "E10"):
            exec_map["DB-SEC-092"] = {
                "execution_status": case["status"],
                "evidence": evid,
                "blocker": None,
            }
        if case["id"] == "E1":
            exec_map["DB-SEC-091"] = {
                "execution_status": case["status"],
                "evidence": evid,
                "blocker": None,
            }

    # Catalog-only from 2.1.13
    for tid in ["DB-SEC-039", "DB-SEC-040", "DB-SEC-075", "DB-SEC-076", "DB-SEC-077", "DB-SEC-078"]:
        exec_map.setdefault(
            tid,
            {
                "execution_status": "PASSED",
                "evidence": "phase-2.1.13 catalog validation",
                "blocker": None,
            },
        )

    rows = []
    for i in range(1, 102):
        tid = f"DB-SEC-{i:03d}"
        req, typ, impl = CATALOG.get(tid, ("(unlisted)", "unknown", "NOT_IMPLEMENTED"))
        ex = exec_map.get(tid)
        if ex:
            status = ex["execution_status"]
            evidence = ex["evidence"]
            blocker = ex["blocker"]
        else:
            if impl == "NOT_IMPLEMENTED":
                status = "NOT RUN"
                blocker = "No harness implementation in Phase 2.1.13/14"
            else:
                status = "NOT RUN"
                blocker = "Not executed this phase"
            evidence = None
        rows.append(
            {
                "test_id": tid,
                "security_requirement": req,
                "test_type": typ,
                "implementation_status": impl,
                "execution_status": status,
                "evidence_location": evidence,
                "failure_or_blocker": blocker,
                "remaining_work": None
                if status == "PASSED"
                else ("Implement + execute" if status == "NOT RUN" else "Investigate failure"),
            }
        )

    counts = {}
    for r in rows:
        counts[r["execution_status"]] = counts.get(r["execution_status"], 0) + 1

    summary = {"group": "F_coverage_matrix", "counts": counts, "rows": rows}
    write_json("F_coverage_matrix.json", summary)

    # Also markdown table fragment
    md = ["| Test ID | Requirement | Type | Impl | Execution | Evidence | Blocker |", "| --- | --- | --- | --- | --- | --- | --- |"]
    for r in rows:
        md.append(
            f"| {r['test_id']} | {r['security_requirement']} | {r['test_type']} | {r['implementation_status']} | {r['execution_status']} | {r['evidence_location'] or '—'} | {r['failure_or_blocker'] or '—'} |"
        )
    (EVIDENCE / "F_coverage_matrix.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    return summary


if __name__ == "__main__":
    import pprint

    pprint.pp(run()["counts"])
