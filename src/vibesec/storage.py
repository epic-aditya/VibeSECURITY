"""SQLite persistence for scans and findings (plan Section 4: zero-setup storage)."""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from .models import Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_name TEXT NOT NULL,
    target_source TEXT NOT NULL,
    profile_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    finding_json TEXT NOT NULL
);
"""


def _get_default_db_path() -> Path:
    env_path = os.environ.get("VIBESEC_DB_PATH", "").strip()
    if env_path:
        return Path(env_path)
    return Path.home() / ".vibesec" / "vibesec.db"


def _connect(db_path: Path | None = None) -> sqlite3.Connection:
    path = db_path or _get_default_db_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path)
    except Exception:
        # Fallback to in-memory database if filesystem is read-only or inaccessible
        conn = sqlite3.connect(":memory:")

    conn.executescript(SCHEMA)

    # Lightweight migration: add new optional columns if not present
    migrations = [
        "ALTER TABLE scans ADD COLUMN fix_actions_json TEXT DEFAULT '[]'",
        "ALTER TABLE scans ADD COLUMN metadata_json TEXT DEFAULT '{}'",
        "ALTER TABLE scans ADD COLUMN asm_json TEXT DEFAULT '{}'",
    ]
    for m in migrations:
        try:
            conn.execute(m)
            conn.commit()
        except sqlite3.OperationalError:
            pass  # column already exists

    return conn


def save_scan(
    target_name: str,
    target_source: str,
    profile: dict,
    findings: list[Finding],
    db_path: Path | None = None,
    fix_actions: list | None = None,
    asm: dict | None = None,
) -> int:
    with _connect(db_path) as conn:
        fix_payload = [a.to_dict() if hasattr(a, "to_dict") else a for a in (fix_actions or [])]
        cur = conn.execute(
            "INSERT INTO scans (target_name, target_source, profile_json, created_at, "
            "fix_actions_json, asm_json) VALUES (?,?,?,?,?,?)",
            (
                target_name,
                target_source,
                json.dumps(profile),
                datetime.now(UTC).isoformat(),
                json.dumps(fix_payload),
                json.dumps(asm or {}),
            ),
        )
        scan_id = int(cur.lastrowid)
        conn.executemany(
            "INSERT INTO findings (scan_id, finding_json) VALUES (?,?)",
            [(scan_id, json.dumps(f.to_dict())) for f in findings],
        )
        return scan_id


def load_scan(scan_id: int, db_path: Path | None = None) -> dict | None:
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT id, target_name, target_source, profile_json, created_at, "
            "fix_actions_json, asm_json FROM scans WHERE id=?",
            (scan_id,),
        ).fetchone()
        if row is None:
            return None
        finding_rows = conn.execute(
            "SELECT finding_json FROM findings WHERE scan_id=?", (scan_id,)
        ).fetchall()
    return {
        "id": row[0],
        "target_name": row[1],
        "target_source": row[2],
        "profile": json.loads(row[3]),
        "created_at": row[4],
        "fix_actions": json.loads(row[5] or "[]"),
        "asm": json.loads(row[6] or "{}"),
        "findings": [json.loads(r[0]) for r in finding_rows],
    }


def list_scans(db_path: Path | None = None) -> list[dict]:
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT id, target_name, target_source, created_at FROM scans ORDER BY id DESC"
        ).fetchall()
    return [
        {"id": r[0], "target_name": r[1], "target_source": r[2], "created_at": r[3]} for r in rows
    ]


def delete_scan(scan_id: int, db_path: Path | None = None) -> bool:
    """Safely delete a single scan record and its cascaded findings."""
    with _connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
        cur = conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        conn.commit()
        return cur.rowcount > 0


def clear_scans(db_path: Path | None = None) -> int:
    """Safely and transactionally delete all scan history and associated findings.

    Preserves database schema and unrelated tables. Returns count of deleted scans.
    """
    with _connect(db_path) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        cur = conn.execute("SELECT COUNT(*) FROM scans")
        count = cur.fetchone()[0]
        conn.execute("DELETE FROM findings")
        conn.execute("DELETE FROM scans")
        conn.commit()
        return int(count)
