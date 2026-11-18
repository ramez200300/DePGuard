import os
import sqlite3

# قاعدة البيانات في مجلد data المجاور لمجلد src
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
    # row_factory يسمح بقراءة الأعمدة بالاسم مثل row["title"]
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    # IF NOT EXISTS تجعل التشغيل المتكرر آمنًا
    conn = connect()
    conn.executescript(SCHEMA)
    conn.commit()
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


def add_scan(target_id, scan_type):
    conn = connect()
    cursor = conn.execute(
        "INSERT INTO scans (target_id, scan_type) VALUES (?, ?)",
        (target_id, scan_type),
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


def save_scan(kind, scan_type, value, findings):
    target_id = get_or_create_target(kind, value)
    scan_id = add_scan(target_id, scan_type)
    add_vulnerabilities(scan_id, findings)
    return scan_id


def list_scans():
    conn = connect()
    rows = conn.execute(
        "SELECT scans.id, scans.scan_type, scans.created_at, targets.value, "
        "(SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = scans.id) AS total "
        "FROM scans JOIN targets ON targets.id = scans.target_id "
        "ORDER BY scans.id DESC"
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_scan(scan_id):
    conn = connect()
    row = conn.execute(
        "SELECT scans.id, scans.scan_type, scans.created_at, targets.value "
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
