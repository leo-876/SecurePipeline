import os
import sqlite3
import logging
from contextlib import contextmanager
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("DB_PATH", "/tmp/app.db")


@contextmanager
def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def fetch_one(query: str, params: tuple = ()) -> Optional[Dict[str, Any]]:
    with get_connection() as conn:
        row = conn.execute(query, params).fetchone()
        return dict(row) if row else None


def fetch_all(query: str, params: tuple = ()) -> List[Dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]


def execute(query: str, params: tuple = ()) -> int:
    with get_connection() as conn:
        cur = conn.execute(query, params)
        return cur.lastrowid
