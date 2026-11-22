"""Shared helpers for Phase 2.1.19 validation against dcmp_full_schema_validation."""
from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

import psycopg
from psycopg.rows import dict_row

HOST = "127.0.0.1"
PORT = 55432
DB = "dcmp_full_schema_validation"
USER = "dcmp_val_super"
ORG_A = UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
ORG_B = UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
USER_A = UUID("11111111-1111-4111-8111-111111111111")
USER_B = UUID("22222222-2222-4222-8222-222222222222")
EVIDENCE = Path(__file__).resolve().parents[2] / "evidence" / "phase-2.1.19"


def connect(**kwargs) -> psycopg.Connection:
    kw = dict(
        host=HOST,
        port=PORT,
        dbname=kwargs.get("dbname", DB),
        user=USER,
        autocommit=False,
    )
    if kwargs.get("dict_rows", True):
        kw["row_factory"] = dict_row
    return psycopg.connect(**kw)


def write_json(name: str, payload: object) -> Path:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    path = EVIDENCE / name
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return path


def set_tenant(cur, org_id: UUID | None) -> None:
    if org_id is None:
        cur.execute("SELECT set_config('app.current_organization_id', '', true)")
    else:
        cur.execute(
            "SELECT set_config('app.current_organization_id', %s, true)",
            (str(org_id),),
        )
