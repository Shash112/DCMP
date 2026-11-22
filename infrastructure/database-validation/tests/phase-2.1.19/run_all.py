"""Run Phase 2.1.19 harnesses A–D and emit combined matrix."""
from __future__ import annotations

import csv
import json
from pathlib import Path

from dbutil import EVIDENCE, write_json
import test_a_audit_gaps
import test_b_full_rls
import test_c_pool_isolation
import test_d_support_ssa

BASELINE_18 = Path(__file__).resolve().parents[2] / "evidence" / "phase-2.1.18" / "db_sec_matrix.csv"


def load_baseline() -> list[dict]:
    if not BASELINE_18.exists():
        return []
    with BASELINE_18.open(encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    return [r for r in rows if any((v or "").strip() for v in r.values())]


def main() -> None:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    a = test_a_audit_gaps.run()
    b = test_b_full_rls.run()
    c = test_c_pool_isolation.run()
    d = test_d_support_ssa.run()

    baseline = load_baseline()
    # Carry forward baseline rows with provenance
    carried = []
    for row in baseline:
        tid = row.get("test_id") or row.get("TEST_id")
        if not tid:
            continue
        carried.append(
            {
                "test_id": tid,
                "category": row.get("category", ""),
                "status": row.get("status", "NOT_RUN"),
                "detail": row.get("detail", ""),
                "phase": "2.1.18-carry-forward",
                "database": "dcmp_full_schema_validation",
            }
        )

    executed = []
    for bundle, phase_tag in (
        (a["cases"], "2.1.19-A"),
        (b["results"], "2.1.19-B"),
        (c["cases"], "2.1.19-C"),
        (d["cases"], "2.1.19-D"),
    ):
        for row in bundle:
            executed.append(
                {
                    "test_id": row["test_id"],
                    "category": row.get("operation") or row.get("name") or "",
                    "status": row["status"],
                    "detail": row.get("detail", ""),
                    "phase": phase_tag,
                    "database": row.get("database", "dcmp_full_schema_validation"),
                }
            )

    # Prefer newly executed IDs over carry-forward when same ID retested
    by_id: dict[str, dict] = {}
    for row in carried:
        by_id[row["test_id"]] = row
    for row in executed:
        prev = by_id.get(row["test_id"])
        if prev and prev.get("phase", "").startswith("2.1.18") and row["status"] == "NOT_RUN":
            # keep prior carry-forward rather than overwriting with accidental NOT_RUN
            continue
        by_id[row["test_id"]] = row

    matrix = sorted(by_id.values(), key=lambda r: r["test_id"])
    summary: dict[str, int] = {}
    for r in matrix:
        summary[r["status"]] = summary.get(r["status"], 0) + 1

    # New-execution-only summary
    new_summary: dict[str, int] = {}
    for r in executed:
        new_summary[r["status"]] = new_summary.get(r["status"], 0) + 1

    payload = {
        "phase": "2.1.19",
        "baseline_2_1_18": {"PASSED": 47, "NOT_RUN": 71, "FAILED": 0},
        "new_execution_summary": new_summary,
        "combined_matrix_summary": summary,
        "workstreams": {
            "A": a["summary"],
            "B": b["summary"],
            "C": c["summary"],
            "D": d["summary"],
        },
        "matrix": matrix,
    }
    write_json("db_sec_matrix_2_1_19.json", payload)

    csv_path = EVIDENCE / "db_sec_matrix_2_1_19.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(
            f, fieldnames=["test_id", "category", "status", "detail", "phase", "database"]
        )
        w.writeheader()
        w.writerows(matrix)

    print(json.dumps({"new": new_summary, "combined": summary}, indent=2))


if __name__ == "__main__":
    main()
