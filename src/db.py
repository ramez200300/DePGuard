import os
import sqlite3

DB_PATH = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "data", "depguard.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,              -- 'url' أو 'manifest'
    value TEXT NOT NULL,             -- الرابط أو اسم الملف
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY,
    target_id INTEGER NOT NULL,
    scan_type TEXT NOT NULL,         -- 'url' أو 'sca'
    sbom_path TEXT,
    risk_score INTEGER,
    risk_level TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (target_id) REFERENCES targets(id)
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
"""


def connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


SCAN_COLUMNS = {"sbom_path": "TEXT", "risk_score": "INTEGER", "risk_level": "TEXT"}


def scan_column_names(conn):
    rows = conn.execute("PRAGMA table_info(scans)").fetchall()
    return [row["name"] for row in rows]


def add_missing_columns(conn):
    for name, kind in SCAN_COLUMNS.items():
        if name in scan_column_names(conn):
            continue
        try:
            conn.execute("ALTER TABLE scans ADD COLUMN " + name + " " + kind)
        except sqlite3.OperationalError:
    
            if name not in scan_column_names(conn):
                raise


def init_db():
    conn = connect()
    try:
        conn.executescript(SCHEMA)
        add_missing_columns(conn)
        conn.commit()
    finally:
        conn.close()


def get_or_create_target(kind, value):
    conn = connect()
    row = conn.execute(
        "SELECT id FROM targets WHERE kind = ? AND value = ?", (kind, value)
    ).fetchone()
    if row:
        conn.close()
        return row["id"]
    cursor = conn.execute(
        "INSERT INTO targets (kind, value) VALUES (?, ?)", (kind, value)
    )
    conn.commit()
    target_id = cursor.lastrowid
    conn.close()
    return target_id


def add_scan(target_id, scan_type, sbom_path=None, risk_score=None, risk_level=None):
    conn = connect()
    cursor = conn.execute(
        "INSERT INTO scans (target_id, scan_type, sbom_path, risk_score, risk_level) "
        "VALUES (?, ?, ?, ?, ?)",
        (target_id, scan_type, sbom_path, risk_score, risk_level),
    )
    conn.commit()
    scan_id = cursor.lastrowid
    conn.close()
    return scan_id


def add_vulnerabilities(scan_id, findings):
    conn = connect()
    for finding in findings:
        conn.execute(
            "INSERT INTO vulnerabilities (scan_id, title, severity, description) VALUES (?, ?, ?, ?)",
            (scan_id, finding["title"], finding["severity"], finding["description"]),
        )
    conn.commit()
    conn.close()


def save_scan(kind, scan_type, value, findings, sbom_path=None,
              risk_score=None, risk_level=None):
    target_id = get_or_create_target(kind, value)
    scan_id = add_scan(target_id, scan_type, sbom_path, risk_score, risk_level)
    add_vulnerabilities(scan_id, findings)
    return scan_id


def list_scans():
    conn = connect()
    rows = conn.execute(
        "SELECT scans.id, scans.scan_type, scans.created_at, scans.risk_score, "
        "scans.risk_level, targets.value, "
        "(SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = scans.id) AS total "
        "FROM scans JOIN targets ON targets.id = scans.target_id "
        "ORDER BY scans.id DESC"
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_scan(scan_id):
    conn = connect()
    row = conn.execute(
        "SELECT scans.id, scans.scan_type, scans.created_at, scans.sbom_path, "
        "scans.risk_score, scans.risk_level, targets.value "
        "FROM scans JOIN targets ON targets.id = scans.target_id WHERE scans.id = ?",
        (scan_id,),
    ).fetchone()
    conn.close()
    if row:
        return dict(row)
    return None


def list_vulnerabilities(scan_id):
    conn = connect()
    rows = conn.execute(
        "SELECT title, severity, description FROM vulnerabilities "
        "WHERE scan_id = ? ORDER BY id",
        (scan_id,),
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def add_report(scan_id, file_path):
    conn = connect()
    conn.execute(
        "INSERT INTO reports (scan_id, file_path) VALUES (?, ?)",
        (scan_id, file_path),
    )
    conn.commit()
    conn.close()
