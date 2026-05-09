import sqlite3
import secrets
import time
from contextlib import contextmanager
from pathlib import Path

DB_PATH = Path(__file__).parent / "cockpit.db"
SESSION_TTL_SECONDS = 8 * 3600
HISTORY_RETENTION_SECONDS = 72 * 3600


@contextmanager
def connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init():
    with connect() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
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

            CREATE TABLE IF NOT EXISTS metrics_cpu (
                ts INTEGER PRIMARY KEY,
                busy REAL, iowait REAL, sys REAL, usr REAL,
                load1 REAL, load5 REAL, load15 REAL
            );

            CREATE TABLE IF NOT EXISTS metrics_mem (
                ts INTEGER PRIMARY KEY,
                used_pct REAL, swap_pct REAL,
                used_kb INTEGER, available_kb INTEGER, total_kb INTEGER,
                buffers_kb INTEGER, cached_kb INTEGER
            );

            CREATE TABLE IF NOT EXISTS metrics_disk (
                ts INTEGER NOT NULL,
                device TEXT NOT NULL,
                util REAL, r_iops REAL, w_iops REAL,
                r_kbs REAL, w_kbs REAL,
                r_await REAL, w_await REAL, aqu_sz REAL,
                PRIMARY KEY (ts, device)
            );
            CREATE INDEX IF NOT EXISTS idx_disk_ts ON metrics_disk(ts);

            CREATE TABLE IF NOT EXISTS metrics_net (
                ts INTEGER NOT NULL,
                iface TEXT NOT NULL,
                rx_kbps REAL, tx_kbps REAL,
                rx_pps REAL, tx_pps REAL,
                rx_errors INTEGER, tx_errors INTEGER,
                PRIMARY KEY (ts, iface)
            );
            CREATE INDEX IF NOT EXISTS idx_net_ts ON metrics_net(ts);

            CREATE TABLE IF NOT EXISTS metrics_psi (
                ts INTEGER PRIMARY KEY,
                cpu_some10 REAL,
                mem_some10 REAL, mem_full10 REAL,
                io_some10 REAL,  io_full10 REAL
            );

            CREATE TABLE IF NOT EXISTS metrics_zfs_pool (
                ts INTEGER NOT NULL,
                pool TEXT NOT NULL,
                capacity_pct REAL, alloc_b INTEGER, free_b INTEGER,
                read_iops REAL, write_iops REAL,
                read_bw REAL, write_bw REAL,
                fragmentation_pct REAL,
                PRIMARY KEY (ts, pool)
            );
            CREATE INDEX IF NOT EXISTS idx_zfs_pool_ts ON metrics_zfs_pool(ts);

            CREATE TABLE IF NOT EXISTS metrics_zfs_arc (
                ts INTEGER PRIMARY KEY,
                size_b INTEGER, c_max_b INTEGER,
                fill_pct REAL,
                hit_ratio REAL,
                hits_delta INTEGER, misses_delta INTEGER,
                mfu_size_b INTEGER, mru_size_b INTEGER,
                l2_hit_ratio REAL
            );

            CREATE TABLE IF NOT EXISTS metrics_procs (
                ts INTEGER PRIMARY KEY,
                total INTEGER, threads INTEGER,
                running INTEGER, sleeping INTEGER, disk_sleep INTEGER,
                zombie INTEGER, stopped INTEGER, idle INTEGER,
                fd_allocated INTEGER, fd_used_pct REAL
            );

            CREATE TABLE IF NOT EXISTS replication_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                source_vg TEXT NOT NULL,
                source_thin_pool TEXT NOT NULL,
                source_lv TEXT NOT NULL,
                dest_kind TEXT NOT NULL,        -- 'ssh' | 'pve'
                dest_host TEXT NOT NULL,
                dest_user TEXT NOT NULL DEFAULT 'root',
                dest_vg TEXT NOT NULL,
                dest_thin_pool TEXT NOT NULL,
                dest_lv TEXT NOT NULL,
                schedule TEXT,                  -- crontab-like; null = manual
                enabled INTEGER NOT NULL DEFAULT 1,
                keep_snapshots INTEGER NOT NULL DEFAULT 3,
                last_snapshot TEXT,             -- nome do último snapshot enviado com sucesso
                last_run_at INTEGER,
                last_run_status TEXT,           -- 'ok' | 'error' | null
                last_error TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS replication_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id INTEGER NOT NULL,
                started_at INTEGER NOT NULL,
                finished_at INTEGER,
                status TEXT NOT NULL,           -- 'running' | 'ok' | 'error'
                bytes_sent INTEGER,
                error_message TEXT,
                snapshot_name TEXT,
                mode TEXT,                      -- 'full' | 'incremental'
                FOREIGN KEY (job_id) REFERENCES replication_jobs(id)
            );
            CREATE INDEX IF NOT EXISTS idx_repl_runs_job
                ON replication_runs(job_id, started_at);

            CREATE TABLE IF NOT EXISTS metrics_pve_vm (
                ts INTEGER NOT NULL,
                vmid INTEGER NOT NULL,
                type TEXT, name TEXT, status TEXT,
                cpu_pct REAL, cpu_cores INTEGER,
                mem_used_b INTEGER, mem_max_b INTEGER,
                diskread_b INTEGER, diskwrite_b INTEGER,
                netin_b INTEGER, netout_b INTEGER,
                PRIMARY KEY (ts, vmid)
            );
            CREATE INDEX IF NOT EXISTS idx_pve_vm_ts ON metrics_pve_vm(ts);
            CREATE INDEX IF NOT EXISTS idx_pve_vm_vmid ON metrics_pve_vm(vmid);
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


HISTORY_TABLES = (
    "metrics_cpu", "metrics_mem", "metrics_disk", "metrics_net",
    "metrics_psi", "metrics_zfs_pool", "metrics_zfs_arc",
    "metrics_pve_vm", "metrics_procs",
)


def purge_history(retention_seconds: int = HISTORY_RETENTION_SECONDS):
    cutoff = int(time.time()) - retention_seconds
    with connect() as conn:
        for table in HISTORY_TABLES:
            conn.execute(f"DELETE FROM {table} WHERE ts < ?", (cutoff,))


def purge_non_physical_disks():
    """Remove devices não-físicos do histórico de metrics_disk.

    Usa o filtro canônico de collectors.disk._is_physical, então também
    remove nomes como sdaa/sdab/sdac que aparecem em alguns drivers e
    não são discos reais válidos.
    """
    try:
        from collectors.disk import _is_physical
    except ImportError:
        return
    with connect() as conn:
        rows = conn.execute(
            "SELECT DISTINCT device FROM metrics_disk"
        ).fetchall()
        invalid = [r["device"] for r in rows if not _is_physical(r["device"])]
        if invalid:
            placeholders = ",".join("?" * len(invalid))
            conn.execute(
                f"DELETE FROM metrics_disk WHERE device IN ({placeholders})",
                invalid,
            )


def fetch_history(table: str, window_seconds: int,
                  group_col: str | None = None) -> list[dict]:
    if table not in HISTORY_TABLES:
        raise ValueError(f"tabela inválida: {table}")
    cutoff = int(time.time()) - window_seconds
    with connect() as conn:
        rows = conn.execute(
            f"SELECT * FROM {table} WHERE ts >= ? ORDER BY ts ASC",
            (cutoff,),
        ).fetchall()
    return [dict(r) for r in rows]


def insert_many(table: str, rows: list[dict]):
    if not rows:
        return
    cols = list(rows[0].keys())
    placeholders = ",".join(["?"] * len(cols))
    sql = f"INSERT OR REPLACE INTO {table} ({','.join(cols)}) VALUES ({placeholders})"
    with connect() as conn:
        conn.executemany(sql, [tuple(r[c] for c in cols) for r in rows])
