"""SQLite connection and schema initialization.

This lab uses a single SQLite file (`vulnerable_app.db` at the repo root) as
its only datastore. The file is auto-created on first launch by init_db(),
which runs once from main.py at startup.

Why SQLite and not Postgres/MySQL? The app is an educational lab meant to be
clonable and runnable with zero infrastructure. SQLite ships with Python,
needs no server, and lets students reset the data layer with a single `rm`.
"""

import sqlite3
import os

# Absolute path to the database file: <repo>/vulnerable_app.db.
# The four `..` segments climb from this file (backend/app/db/session.py)
# back up to the project root. We resolve this at import time so the path
# is stable regardless of which directory uvicorn was launched from.
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", "vulnerable_app.db")


def get_db():
    """Open a fresh SQLite connection.

    Callers are responsible for closing the returned connection (use
    try/finally or `with`). Each handler opens its own connection so we
    do not need a connection pool -- SQLite's file-level locking is
    sufficient for a single-process educational lab.

    - check_same_thread=False: required because FastAPI runs handlers on
      an asyncio event loop that may dispatch them across threads. SQLite
      objects are not normally thread-safe; this flag tells sqlite3 to
      trust us to serialize access ourselves (we do, by opening one
      connection per request and never sharing it).
    - row_factory = sqlite3.Row: makes cursor.fetchone() return a Row
      object that supports both `row[0]` and `row["username"]` access,
      so auth_service.login() can read `user["password"]` by column name.
    """
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create -- or upgrade -- the users table.

    Called once from main.py at app startup. Idempotent and row-preserving:
    a fresh DB gets the full schema below; a pre-existing DB (e.g. from
    v1.0.2, before Continue-with-Google) is migrated IN PLACE by adding any
    of the four OAuth columns that are missing. No row is ever dropped.

    Schema notes:
    - `username TEXT UNIQUE`: signup relies on this to surface
      "Username already exists" via sqlite3.IntegrityError.
    - `password TEXT` (NULLABLE): local accounts store the bcrypt hash
      string; Google (OAuth-only) accounts store NULL -- there is no weak
      hash to leak, and the unchanged password login() fails closed on a
      NULL hash, so such accounts simply cannot log in with a password.
    - `google_id TEXT UNIQUE`: the user's stable Google subject id, or NULL
      for local accounts. SQLite allows multiple NULLs under UNIQUE, so
      local users coexist freely.
    - `name` / `picture`: the Google profile display name and avatar URL
      (stored, not rendered in this release).
    - `auth_provider TEXT DEFAULT 'local'`: 'local' or 'google'.
    """
    conn = get_db()
    conn.execute(
        """CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE,
            email         TEXT,
            password      TEXT,
            google_id     TEXT UNIQUE,
            name          TEXT,
            picture       TEXT,
            auth_provider TEXT DEFAULT 'local'
        )"""
    )

    # Migrate older databases in place: add any missing OAuth columns. Note
    # that ALTER TABLE ADD COLUMN cannot carry a UNIQUE constraint in SQLite,
    # so a migrated `google_id` lacks the table-level UNIQUE; uniqueness is
    # still enforced in practice because the service always SELECTs by
    # google_id before inserting. Fresh DBs get UNIQUE from CREATE TABLE above.
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
    migrations = {
        "google_id": "ALTER TABLE users ADD COLUMN google_id TEXT",
        "name": "ALTER TABLE users ADD COLUMN name TEXT",
        "picture": "ALTER TABLE users ADD COLUMN picture TEXT",
        "auth_provider": "ALTER TABLE users ADD COLUMN auth_provider TEXT DEFAULT 'local'",
    }
    for column, ddl in migrations.items():
        if column not in existing:
            conn.execute(ddl)

    conn.commit()
    conn.close()
