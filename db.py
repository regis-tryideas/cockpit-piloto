import sqlite3
import secrets
import time
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(__file__).parent / "cockpit.db"
SESSION_TTL_SECONDS = 8 * 3600


@contextmanager
def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init():
    with connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                remote_addr TEXT
            );
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                success INTEGER NOT NULL,
                remote_addr TEXT,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_login_attempts_created
                ON login_attempts(created_at);
            """
        )


def create_session(username: str, remote_addr: str) -> str:
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    with connect() as conn:
        conn.execute(
            "INSERT INTO sessions (token, username, created_at, expires_at, remote_addr) "
            "VALUES (?, ?, ?, ?, ?)",
            (token, username, now, now + SESSION_TTL_SECONDS, remote_addr),
        )
    return token


def get_session(token: str | None):
    if not token:
        return None
    now = int(time.time())
    with connect() as conn:
        row = conn.execute(
            "SELECT username, expires_at FROM sessions WHERE token = ?",
            (token,),
        ).fetchone()
    if not row or row["expires_at"] < now:
        return None
    return {"username": row["username"]}


def destroy_session(token: str | None):
    if not token:
        return
    with connect() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))


def purge_expired_sessions():
    now = int(time.time())
    with connect() as conn:
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))


def record_login_attempt(username: str, success: bool, remote_addr: str):
    with connect() as conn:
        conn.execute(
            "INSERT INTO login_attempts (username, success, remote_addr, created_at) "
            "VALUES (?, ?, ?, ?)",
            (username, 1 if success else 0, remote_addr, int(time.time())),
        )


def recent_failed_attempts(remote_addr: str, window_seconds: int = 300) -> int:
    cutoff = int(time.time()) - window_seconds
    with connect() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS c FROM login_attempts "
            "WHERE remote_addr = ? AND success = 0 AND created_at > ?",
            (remote_addr, cutoff),
        ).fetchone()
    return row["c"] if row else 0
