import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "phishguard.db"


def connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                subject TEXT,
                classification TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                confidence INTEGER NOT NULL,
                reasons TEXT NOT NULL,
                urls TEXT NOT NULL
            )
        ''')
        conn.commit()


def save_scan(item):
    init_db()
    # Keep only the latest scan. This prevents old scans from returning after refresh.
    with connection() as conn:
        conn.execute('DELETE FROM scans')
        conn.execute('''
            INSERT INTO scans
            (timestamp, subject, classification, risk_score, confidence, reasons, urls)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            item["timestamp"],
            item.get("subject", ""),
            item["classification"],
            item["risk_score"],
            item["confidence"],
            " | ".join(item["reasons"]),
            " | ".join(item["urls"])
        ))
        conn.commit()


def clear_scans():
    init_db()
    with connection() as conn:
        conn.execute('DELETE FROM scans')
        conn.commit()


def recent_scans(limit=50):
    with connection() as conn:
        rows = conn.execute('''
            SELECT id, timestamp, subject, classification, risk_score,
                   confidence, reasons, urls
            FROM scans ORDER BY id DESC LIMIT ?
        ''', (limit,)).fetchall()
    return [dict(row) for row in rows]
