#!/usr/bin/env python3
"""One-shot migration: timestamptz / TEXT timestamp columns -> BIGINT
(Unix epoch seconds), and timestamp fields embedded in `certificates.data`
are rewritten from RFC 3339 strings to integer epoch seconds.

Idempotent in the sense that re-running on already-migrated tables is
detected by inspecting `information_schema.columns` and skipped.

Encrypted columns (master_keys.key_encrypted, secrets.value, the
key_pem_encrypted fields inside cert JSON blobs) are pass-through.
"""

import json
import os
import sys
from datetime import datetime, timezone

import psycopg2
from psycopg2.extras import RealDictCursor

DSN = os.environ.get(
    "SEKISHO_PG_DSN",
    "postgresql://sekisho:971ec6bf05f2180e77a2e2c783009d237da3545333d77685"
    "@127.0.0.1:5433/sekisho",
)

# (table, column) pairs whose type flips from timestamptz -> BIGINT.
# Listed explicitly so the migration script and the application DDL stay
# in lock-step; a missed pair would surface as a runtime
# `mismatched types` error from sqlx, but enumerating it here gives us a
# pre-flight catch.
TIMESTAMP_COLUMNS = [
    ("routes", "created_at"),
    ("routes", "updated_at"),
    ("identity_providers", "created_at"),
    ("identity_providers", "updated_at"),
    ("global_config", "updated_at"),
    ("sessions", "expires_at"),
    ("sessions", "created_at"),
    ("sessions", "last_accessed_at"),
    ("certificates", "expires_at"),
    ("certificates", "created_at"),
    ("certificates", "updated_at"),
    ("secrets", "created_at"),
    ("api_keys", "created_at"),
    ("api_keys", "last_used_at"),
    ("policies", "created_at"),
    ("policies", "updated_at"),
    ("schema_versions", "updated_at"),
    ("acme_challenges", "created_at"),
    ("acme_leader_election", "updated_at"),
    ("pending_auth", "created_at"),
    ("pending_auth", "expires_at"),
    ("acme_queue", "enqueued_at"),
    ("acme_queue", "picked_at"),
    ("acme_queue", "completed_at"),
    ("master_keys", "created_at"),
    ("master_keys", "retired_at"),
]

# Volatile / in-flight tables: cleared before the type swap so the
# `USING` clause has nothing to convert. Their rows are recreated on
# next use (sessions = next login, ACME queue = next /certs request,
# etc.).
TRUNCATE_TABLES = [
    "sessions",
    "pending_auth",
    "acme_challenges",
    "acme_queue",
    "acme_leader_election",
]

# JSON-blob columns whose contents include nested timestamps that the
# new model deserializes as integer epoch seconds. The list of fields
# per table mirrors the `#[serde(with = "ts_seconds")]` annotations on
# the model structs in `crates/sekishod/src/models/`.
JSON_BLOB_TIMESTAMPS = {
    "certificates": ("data", ["issued_at", "expires_at"]),
}


def column_is_bigint(cur, table, column):
    cur.execute(
        "SELECT data_type FROM information_schema.columns "
        "WHERE table_name = %s AND column_name = %s",
        (table, column),
    )
    row = cur.fetchone()
    if row is None:
        return None  # column doesn't exist
    return row["data_type"] == "bigint"


def parse_to_epoch(value):
    """Accept an RFC 3339 string or epoch int and return epoch seconds.

    Already-migrated rows store ints; mid-migration retries on a
    partially-converted DB therefore stay correct.
    """
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        # `fromisoformat` handles `2026-05-02T09:31:05.123456+00:00`.
        # Also accept the SQLite space-separated form just in case
        # operator dumped/restored data through an intermediate tool.
        s = value.replace(" ", "T")
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    raise TypeError(f"unexpected timestamp value type: {type(value)} ({value!r})")


def rewrite_json_blob(blob_text, fields):
    obj = json.loads(blob_text)
    changed = False
    for f in fields:
        if f in obj:
            new = parse_to_epoch(obj[f])
            if obj[f] != new:
                obj[f] = new
                changed = True
    if not changed:
        return None
    # `separators=(",", ":")` keeps the blob compact; serde tolerates
    # whitespace either way so it doesn't matter for correctness.
    return json.dumps(obj, separators=(",", ":"))


def migrate(conn):
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        # Pre-flight: are we already migrated? If every listed column
        # already reports `bigint`, exit clean.
        all_bigint = True
        any_present = False
        for table, column in TIMESTAMP_COLUMNS:
            state = column_is_bigint(cur, table, column)
            if state is None:
                # Schema differs; surface but don't abort — a missing
                # column might just mean the schema was never created.
                print(f"  note: {table}.{column} not present; skipping")
                continue
            any_present = True
            if not state:
                all_bigint = False
        if any_present and all_bigint:
            print("All timestamp columns already BIGINT — nothing to do.")
            return

        # Step 1: truncate volatile tables so the type-change USING
        # clause has nothing to evaluate against (and so leftover
        # in-flight rows from the old binary don't leak forward).
        print("Truncating volatile tables...")
        for t in TRUNCATE_TABLES:
            cur.execute(f"TRUNCATE TABLE {t}")
            print(f"  truncated {t}")

        # Step 2: rewrite JSON blobs in tables we're keeping. Done
        # before the column type swap purely so any parse failure
        # surfaces while the row data is still in its original form
        # (easier to inspect manually if something looks off).
        print("Rewriting JSON-blob timestamps...")
        for table, (col, fields) in JSON_BLOB_TIMESTAMPS.items():
            cur.execute(f"SELECT id, {col} FROM {table}")
            rows = cur.fetchall()
            for r in rows:
                rewritten = rewrite_json_blob(r[col], fields)
                if rewritten is None:
                    continue
                cur.execute(
                    f"UPDATE {table} SET {col} = %s WHERE id = %s",
                    (rewritten, r["id"]),
                )
            print(f"  rewrote {len(rows)} rows in {table}.{col}")

        # Step 3: in-place type swap. Each ALTER COLUMN converts the
        # existing timestamptz value to its epoch-second integer; for
        # the truncated tables this collapses to a no-op USING because
        # the column is empty. NULL values pass through unchanged
        # (Option<DateTime> -> Option<i64>).
        print("Converting column types to BIGINT...")
        for table, column in TIMESTAMP_COLUMNS:
            state = column_is_bigint(cur, table, column)
            if state is None or state:
                continue
            # Drop the timestamptz-typed DEFAULT first; Postgres won't
            # auto-cast a `NOW()` default to a bigint expression. The
            # caller-side step 4 below re-attaches the new
            # epoch-flavoured DEFAULT.
            cur.execute(
                f"ALTER TABLE {table} "
                f"ALTER COLUMN {column} DROP DEFAULT, "
                f"ALTER COLUMN {column} TYPE BIGINT "
                f"USING EXTRACT(EPOCH FROM {column})::BIGINT"
            )
            print(f"  {table}.{column} -> BIGINT")

        # Step 4: re-attach defaults using the new function. The old
        # `DEFAULT NOW()` was dropped automatically by the type change.
        print("Re-attaching DEFAULT clauses...")
        defaulted = [
            ("routes", "created_at"),
            ("routes", "updated_at"),
            ("identity_providers", "created_at"),
            ("identity_providers", "updated_at"),
            ("global_config", "updated_at"),
            ("sessions", "created_at"),
            ("certificates", "created_at"),
            ("certificates", "updated_at"),
            ("secrets", "created_at"),
            ("api_keys", "created_at"),
            ("policies", "created_at"),
            ("policies", "updated_at"),
            ("schema_versions", "updated_at"),
            ("acme_challenges", "created_at"),
            ("acme_leader_election", "updated_at"),
            ("acme_queue", "enqueued_at"),
            ("master_keys", "created_at"),
        ]
        for table, column in defaulted:
            cur.execute(
                f"ALTER TABLE {table} "
                f"ALTER COLUMN {column} SET DEFAULT EXTRACT(EPOCH FROM NOW())::BIGINT"
            )

    conn.commit()
    print("Migration committed.")


def main():
    print(f"Connecting: {DSN.split('@')[-1]}")
    conn = psycopg2.connect(DSN)
    try:
        migrate(conn)
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()
