"""
database.py
-----------
Lightweight SQLite setup for the AI Resource Acquisition Agent.

We use the Python standard-library `sqlite3` module directly (no ORM
dependency required) wrapped behind simple repository functions, so the
rest of the app never writes raw SQL inline.

Schema mirrors `data-model.md`:
    Requirement -> Candidate -> Approval -> Download -> InspectionReport
                                                     (and) ProvenanceManifest
"""

import sqlite3
import os
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "resource_agent.db")
DB_PATH = os.path.abspath(DB_PATH)

SCHEMA = """
CREATE TABLE IF NOT EXISTS requirements (
    id TEXT PRIMARY KEY,
    raw_text TEXT NOT NULL,
    resource_types TEXT NOT NULL,      -- JSON-encoded list
    topics TEXT NOT NULL,              -- JSON-encoded list
    preferred_formats TEXT NOT NULL,   -- JSON-encoded list
    license_preference TEXT,
    max_size_mb INTEGER,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS candidates (
    id TEXT PRIMARY KEY,
    requirement_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    source_url TEXT NOT NULL,
    version_or_commit TEXT NOT NULL,
    title TEXT,
    description TEXT,
    format TEXT,
    size_bytes INTEGER,
    license TEXT,
    license_evidence TEXT,
    relevance_score REAL,
    score_breakdown TEXT,              -- JSON-encoded dict
    discovered_at TEXT NOT NULL,
    FOREIGN KEY (requirement_id) REFERENCES requirements (id)
);

CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL,
    approved_version_or_commit TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    approved_at TEXT NOT NULL,
    status TEXT NOT NULL,              -- 'active' | 'invalidated'
    invalidated_reason TEXT,
    FOREIGN KEY (candidate_id) REFERENCES candidates (id)
);

CREATE TABLE IF NOT EXISTS downloads (
    id TEXT PRIMARY KEY,
    approval_id TEXT NOT NULL,
    status TEXT NOT NULL,              -- pending|validated|quarantined|failed|complete
    local_path TEXT,
    sha256 TEXT,
    mime_detected TEXT,
    size_bytes INTEGER,
    downloaded_at TEXT,
    validation_notes TEXT,             -- JSON-encoded dict
    FOREIGN KEY (approval_id) REFERENCES approvals (id)
);

CREATE TABLE IF NOT EXISTS inspection_reports (
    id TEXT PRIMARY KEY,
    download_id TEXT NOT NULL,
    format TEXT,
    schema_preview TEXT,               -- JSON-encoded
    record_count INTEGER,
    encoding TEXT,
    generated_at TEXT NOT NULL,
    FOREIGN KEY (download_id) REFERENCES downloads (id)
);

CREATE TABLE IF NOT EXISTS provenance_manifests (
    id TEXT PRIMARY KEY,
    download_id TEXT NOT NULL,
    provider TEXT,
    original_source TEXT,
    revision TEXT,
    approved_by TEXT,
    approved_at TEXT,
    license_evidence TEXT,
    sha256 TEXT,
    size_bytes INTEGER,
    detected_format TEXT,
    FOREIGN KEY (download_id) REFERENCES downloads (id)
);
"""


def get_connection() -> sqlite3.Connection:
    """Create a new SQLite connection with row access by column name."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def db_session():
    """Context manager yielding a connection, committing on success."""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create all tables if they do not already exist. Safe to call repeatedly."""
    with db_session() as conn:
        conn.executescript(SCHEMA)


if __name__ == "__main__":
    init_db()
    print(f"Database initialized at: {DB_PATH}")
