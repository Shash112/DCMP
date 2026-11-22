"""Phase 2.1.14 orchestration — execute all harness groups and write env evidence."""
from __future__ import annotations

import json
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path

from dbutil import EVIDENCE, connect, verify_env, write_json


def main() -> int:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    conn = connect()
    env = verify_env(conn)
    conn.close()
    write_json(
        "00_environment.json",
        {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "env": env,
            "docker": "NOT USED / unavailable — EDB PostgreSQL 16.10 local binaries",
            "redis": "NO real Redis instance detected; RedisSim used for group B",
            "harness_venv": "infrastructure/database-validation/.venv (psycopg, cryptography)",
        },
    )

    if env["database"] != "dcmp_validation" or env["port"] != 55432:
        print("REFUSING: unexpected database/port", env)
        return 2
    if "16.10" not in env["version"]:
        print("REFUSING: unexpected PostgreSQL version", env["version"])
        return 2

    results = {"env": env, "groups": {}}
    for name, mod in [
        ("A", "test_a_concurrency"),
        ("B", "test_b_redis"),
        ("C", "test_c_dpop"),
        ("D", "test_d_support"),
        ("E", "test_e_aes_gcm"),
    ]:
        print(f"=== Running group {name} ===")
        try:
            m = __import__(mod)
            summary = m.run()
            results["groups"][name] = {
                "passed": summary.get("passed"),
                "failed": summary.get("failed"),
                "not_run": summary.get("not_run"),
                "total": summary.get("total") or len(summary.get("cases", [])),
            }
            print(json.dumps(results["groups"][name]))
        except Exception:
            tb = traceback.format_exc()
            (EVIDENCE / f"{name}_ERROR.txt").write_text(tb, encoding="utf-8")
            results["groups"][name] = {"error": tb.splitlines()[-1]}
            print(tb)
            return 1

    print("=== Building coverage matrix F ===")
    import test_f_coverage as f

    fsum = f.run()
    results["groups"]["F"] = fsum["counts"]
    write_json("00_run_summary.json", results)
    print("DONE", json.dumps(results["groups"], indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
