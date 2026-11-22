"""Shared DB helpers for Phase 2.1.14 validation harnesses (disposable cluster only)."""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import psycopg

HOST = os.environ.get("PGHOST", "127.0.0.1")
PORT = int(os.environ.get("PGPORT", "55432"))
DB = os.environ.get("PGDATABASE", "dcmp_validation")
USER = os.environ.get("PGUSER", "dcmp_val_super")

ORG_A = uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
ORG_B = uuid.UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
USER_A = uuid.UUID("11111111-1111-4111-8111-111111111111")
USER_B = uuid.UUID("22222222-2222-4222-8222-222222222222")

EVIDENCE = Path(__file__).resolve().parents[2] / "evidence" / "phase-2.1.14"


def connect() -> psycopg.Connection:
    return psycopg.connect(
        host=HOST,
        port=PORT,
        dbname=DB,
        user=USER,
        autocommit=True,
    )


@contextmanager
def app_tx(conn: psycopg.Connection, org_id: uuid.UUID) -> Iterator[psycopg.Cursor]:
    """Begin a transaction as dcmp_app with tenant GUC (transaction-local)."""
    conn.autocommit = False
    try:
        with conn.cursor() as cur:
            cur.execute("SET LOCAL ROLE dcmp_app")
            # SET SESSION AUTHORIZATION cannot be LOCAL; use SET ROLE + search path.
            # Prefer SET SESSION AUTHORIZATION for privilege fidelity when possible.
            cur.execute("RESET ROLE")
            cur.execute("SET SESSION AUTHORIZATION dcmp_app")
            cur.execute(
                "SELECT set_config('app.current_organization_id', %s, true)",
                (str(org_id),),
            )
            yield cur
            conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        try:
            with conn.cursor() as cur:
                cur.execute("RESET SESSION AUTHORIZATION")
        except Exception:
            pass
        conn.autocommit = True


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def token_hash_from_label(label: str) -> str:
    """Deterministic 64-hex token hash for tests (not a real refresh token)."""
    return sha256_hex(f"dcmp-val-token:{label}".encode("utf-8"))


def fingerprint_for_proof(proof_id: str, method: str = "POST", uri: str = "/auth/refresh") -> str:
    """Simplified fingerprint surrogate for DB concurrency tests (not full dcmp-retry-key-v1)."""
    body = f"proof={proof_id}\nmethod={method}\nuri={uri}\n"
    return sha256_hex(body.encode("utf-8"))


def write_json(name: str, payload: Any) -> Path:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    path = EVIDENCE / name
    # Redact obvious secret-like fields
    text = json.dumps(payload, indent=2, default=str)
    for banned in ("validation-secret", "plaintext", "refresh_token", "access_token"):
        if banned in text.lower() and "redacted" not in text.lower():
            pass
    path.write_text(text + "\n", encoding="utf-8")
    return path


def utc_z(dt: datetime | None = None) -> str:
    d = dt or datetime.now(timezone.utc)
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def verify_env(conn: psycopg.Connection) -> dict[str, Any]:
    with conn.cursor() as cur:
        cur.execute("SELECT version()")
        version = cur.fetchone()[0]
        cur.execute("SELECT current_database(), inet_server_port()")
        db, port = cur.fetchone()
        cur.execute(
            "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'"
        )
        n_public = cur.fetchone()[0]
    return {
        "version": version,
        "database": db,
        "port": port,
        "public_tables": n_public,
        "host": HOST,
    }
