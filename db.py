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

            CREATE TABLE IF NOT EXISTS pg_config (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                enabled INTEGER NOT NULL DEFAULT 0,
                host TEXT,
                port INTEGER NOT NULL DEFAULT 5432,
                username TEXT,
                password TEXT,
                dbname TEXT,
                schema_name TEXT NOT NULL DEFAULT 'public',
                table_prefix TEXT,
                retention_days INTEGER NOT NULL DEFAULT 30,
                last_test_at INTEGER, last_test_ok INTEGER, last_test_msg TEXT,
                last_init_at INTEGER, last_init_msg TEXT,
                updated_at INTEGER
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


def fetch_history_range(table: str, from_ts: int, to_ts: int) -> list[dict]:
    """Lê histórico entre [from_ts, to_ts]. Usa PG se habilitado."""
    if table not in HISTORY_TABLES:
        raise ValueError(f"tabela inválida: {table}")
    try:
        cfg = pg_get_config()
        if cfg.get("enabled") and cfg.get("host"):
            rows = pg_fetch_history_range(table, from_ts, to_ts)
            if rows is not None:
                return rows
    except Exception:
        pass
    with connect() as conn:
        rows = conn.execute(
            f"SELECT * FROM {table} WHERE ts >= ? AND ts <= ? ORDER BY ts ASC",
            (from_ts, to_ts),
        ).fetchall()
    return [dict(r) for r in rows]


def pg_fetch_history_range(table: str, from_ts: int, to_ts: int) -> list[dict] | None:
    cfg = pg_get_config()
    if not (cfg.get("enabled") and cfg.get("host")):
        return None
    if table not in _PG_TABLE_DEFS:
        return None
    try:
        conn, _ = _pg_connect()
    except Exception:
        return None
    rows = []
    try:
        full = pg_full_table_name(cfg, table)
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT * FROM {full} WHERE ts BETWEEN %s AND %s ORDER BY ts ASC",
                (from_ts, to_ts),
            )
            cols = [d[0] for d in cur.description]
            for r in cur.fetchall():
                rows.append(dict(zip(cols, r)))
        return rows
    except Exception:
        return None
    finally:
        try:
            conn.close()
        except Exception:
            pass


def fetch_history(table: str, window_seconds: int,
                  group_col: str | None = None) -> list[dict]:
    if table not in HISTORY_TABLES:
        raise ValueError(f"tabela inválida: {table}")
    cutoff = int(time.time()) - window_seconds

    # Se PG remoto está habilitado, lê de lá (é onde os dados estão)
    try:
        cfg = pg_get_config()
        if cfg.get("enabled") and cfg.get("host"):
            rows = pg_fetch_history(table, cutoff)
            if rows is not None:
                return rows
    except Exception:
        pass  # fallback para SQLite

    with connect() as conn:
        rows = conn.execute(
            f"SELECT * FROM {table} WHERE ts >= ? ORDER BY ts ASC",
            (cutoff,),
        ).fetchall()
    return [dict(r) for r in rows]


def pg_fetch_history(table: str, cutoff_ts: int) -> list[dict] | None:
    """SELECT * FROM <prefix>_<table> WHERE ts >= cutoff ORDER BY ts ASC."""
    cfg = pg_get_config()
    if not (cfg.get("enabled") and cfg.get("host")):
        return None
    if table not in _PG_TABLE_DEFS:
        return None
    try:
        conn, _ = _pg_connect()
    except Exception:
        return None
    rows = []
    try:
        full = pg_full_table_name(cfg, table)
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT * FROM {full} WHERE ts >= %s ORDER BY ts ASC",
                (cutoff_ts,),
            )
            cols = [d[0] for d in cur.description]
            for r in cur.fetchall():
                rows.append(dict(zip(cols, r)))
        return rows
    except Exception:
        return None
    finally:
        try:
            conn.close()
        except Exception:
            pass


def insert_many(table: str, rows: list[dict]):
    """Grava rows na tabela.

    - Para tabelas de histórico (metrics_*): se PG remoto está habilitado,
      grava APENAS no PG (SQLite local é pulado para evitar duplicação).
      Caso contrário, grava no SQLite local.
    - Para outras tabelas (sessions, login_attempts, replication_*, pg_config,
      etc.): sempre no SQLite local — são estado interno do cockpit.
    """
    if not rows:
        return
    is_metric = table.startswith("metrics_")
    pg_active = False
    if is_metric:
        try:
            cfg = pg_get_config()
            pg_active = bool(cfg.get("enabled") and cfg.get("host"))
        except Exception:
            pg_active = False
        if pg_active:
            pg_insert_many(table, rows)
            return  # NÃO grava no SQLite quando PG está ativo

    cols = list(rows[0].keys())
    placeholders = ",".join(["?"] * len(cols))
    sql = f"INSERT OR REPLACE INTO {table} ({','.join(cols)}) VALUES ({placeholders})"
    with connect() as conn:
        conn.executemany(sql, [tuple(r[c] for c in cols) for r in rows])


# =========================================================================
# PostgreSQL remoto (opcional) — armazenamento de histórico de longo prazo
# =========================================================================
import re as _re_pg
import socket as _socket_pg


def _safe_prefix(s: str) -> str:
    """Sanitiza string para nome de identificador PG (snake_case)."""
    if not s:
        return "host"
    return _re_pg.sub(r"[^a-zA-Z0-9_]", "_", s).strip("_").lower() or "host"


def pg_default_prefix() -> str:
    return _safe_prefix(_socket_pg.gethostname())


def pg_get_config() -> dict:
    with connect() as conn:
        row = conn.execute("SELECT * FROM pg_config WHERE id = 1").fetchone()
    if not row:
        return {
            "enabled": False, "host": "", "port": 5432, "username": "",
            "password": "", "dbname": "", "schema_name": "public",
            "table_prefix": pg_default_prefix(),
            "retention_days": 30,
        }
    d = dict(row)
    d["enabled"] = bool(d.get("enabled"))
    if not d.get("table_prefix"):
        d["table_prefix"] = pg_default_prefix()
    return d


def pg_save_config(**fields) -> None:
    now = int(time.time())
    cfg = pg_get_config()
    cfg.update({k: v for k, v in fields.items() if v is not None})
    cfg["enabled"] = 1 if cfg.get("enabled") else 0
    cfg["updated_at"] = now
    with connect() as conn:
        conn.execute(
            "INSERT INTO pg_config (id, enabled, host, port, username, "
            "password, dbname, schema_name, table_prefix, retention_days, "
            "updated_at) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET "
            "enabled=excluded.enabled, host=excluded.host, port=excluded.port,"
            "username=excluded.username, password=excluded.password, "
            "dbname=excluded.dbname, schema_name=excluded.schema_name, "
            "table_prefix=excluded.table_prefix, "
            "retention_days=excluded.retention_days, "
            "updated_at=excluded.updated_at",
            (cfg["enabled"], cfg["host"], cfg["port"], cfg["username"],
             cfg["password"], cfg["dbname"], cfg["schema_name"],
             cfg["table_prefix"], cfg["retention_days"], cfg["updated_at"]),
        )


def _pg_connect():
    try:
        import psycopg2  # type: ignore
    except ImportError as e:
        raise RuntimeError(f"psycopg2 não instalado: {e}")
    cfg = pg_get_config()
    if not (cfg["host"] and cfg["username"] and cfg["dbname"]):
        raise RuntimeError("Config PG incompleta (host/user/dbname obrigatórios)")
    return psycopg2.connect(
        host=cfg["host"], port=cfg["port"] or 5432,
        user=cfg["username"], password=cfg["password"] or "",
        dbname=cfg["dbname"], connect_timeout=8,
    ), cfg


# Tipo SQL para cada tabela do histórico (mapeia SQLite → PG)
_PG_TABLE_DEFS = {
    "metrics_cpu": (
        "ts BIGINT, busy DOUBLE PRECISION, iowait DOUBLE PRECISION, "
        "sys DOUBLE PRECISION, usr DOUBLE PRECISION, load1 DOUBLE PRECISION, "
        "load5 DOUBLE PRECISION, load15 DOUBLE PRECISION, PRIMARY KEY (ts)"
    ),
    "metrics_mem": (
        "ts BIGINT, used_pct DOUBLE PRECISION, swap_pct DOUBLE PRECISION, "
        "used_kb BIGINT, available_kb BIGINT, total_kb BIGINT, "
        "buffers_kb BIGINT, cached_kb BIGINT, PRIMARY KEY (ts)"
    ),
    "metrics_disk": (
        "ts BIGINT, device TEXT, util DOUBLE PRECISION, r_iops DOUBLE PRECISION, "
        "w_iops DOUBLE PRECISION, r_kbs DOUBLE PRECISION, w_kbs DOUBLE PRECISION, "
        "r_await DOUBLE PRECISION, w_await DOUBLE PRECISION, aqu_sz DOUBLE PRECISION, "
        "PRIMARY KEY (ts, device)"
    ),
    "metrics_net": (
        "ts BIGINT, iface TEXT, rx_kbps DOUBLE PRECISION, tx_kbps DOUBLE PRECISION, "
        "rx_pps DOUBLE PRECISION, tx_pps DOUBLE PRECISION, "
        "rx_errors BIGINT, tx_errors BIGINT, PRIMARY KEY (ts, iface)"
    ),
    "metrics_psi": (
        "ts BIGINT, cpu_some10 DOUBLE PRECISION, mem_some10 DOUBLE PRECISION, "
        "mem_full10 DOUBLE PRECISION, io_some10 DOUBLE PRECISION, "
        "io_full10 DOUBLE PRECISION, PRIMARY KEY (ts)"
    ),
    "metrics_zfs_pool": (
        "ts BIGINT, pool TEXT, capacity_pct DOUBLE PRECISION, alloc_b BIGINT, "
        "free_b BIGINT, read_iops DOUBLE PRECISION, write_iops DOUBLE PRECISION, "
        "read_bw DOUBLE PRECISION, write_bw DOUBLE PRECISION, "
        "fragmentation_pct DOUBLE PRECISION, PRIMARY KEY (ts, pool)"
    ),
    "metrics_zfs_arc": (
        "ts BIGINT, size_b BIGINT, c_max_b BIGINT, fill_pct DOUBLE PRECISION, "
        "hit_ratio DOUBLE PRECISION, hits_delta BIGINT, misses_delta BIGINT, "
        "mfu_size_b BIGINT, mru_size_b BIGINT, l2_hit_ratio DOUBLE PRECISION, "
        "PRIMARY KEY (ts)"
    ),
    "metrics_pve_vm": (
        "ts BIGINT, vmid INTEGER, type TEXT, name TEXT, status TEXT, "
        "cpu_pct DOUBLE PRECISION, cpu_cores INTEGER, mem_used_b BIGINT, "
        "mem_max_b BIGINT, diskread_b BIGINT, diskwrite_b BIGINT, "
        "netin_b BIGINT, netout_b BIGINT, PRIMARY KEY (ts, vmid)"
    ),
    "metrics_procs": (
        "ts BIGINT, total INTEGER, threads INTEGER, running INTEGER, "
        "sleeping INTEGER, disk_sleep INTEGER, zombie INTEGER, stopped INTEGER, "
        "idle INTEGER, fd_allocated INTEGER, fd_used_pct DOUBLE PRECISION, "
        "PRIMARY KEY (ts)"
    ),
}


def pg_full_table_name(cfg: dict, table: str) -> str:
    """Nome final no Postgres: <schema>.<prefix>_<table>"""
    prefix = _safe_prefix(cfg.get("table_prefix") or pg_default_prefix())
    schema = _safe_prefix(cfg.get("schema_name") or "public")
    return f'"{schema}"."{prefix}_{table}"'


def pg_test_connection() -> tuple[bool, str]:
    cfg = pg_get_config()
    if not cfg.get("host"):
        return False, "host não configurado"
    try:
        conn, _ = _pg_connect()
        with conn.cursor() as cur:
            cur.execute("SELECT version()")
            ver = cur.fetchone()[0]
        conn.close()
        msg = f"OK: {ver.split(',')[0]}"
        with connect() as c:
            c.execute(
                "UPDATE pg_config SET last_test_at=?, last_test_ok=1, last_test_msg=? WHERE id=1",
                (int(time.time()), msg),
            )
        return True, msg
    except Exception as e:
        msg = str(e).strip().splitlines()[0][:300]
        with connect() as c:
            c.execute(
                "UPDATE pg_config SET last_test_at=?, last_test_ok=0, last_test_msg=? WHERE id=1",
                (int(time.time()), msg),
            )
        return False, msg


def pg_init_schema() -> tuple[bool, str]:
    """Cria schema (se preciso) e CREATE TABLE IF NOT EXISTS para tudo."""
    cfg = pg_get_config()
    try:
        conn, _ = _pg_connect()
    except Exception as e:
        return False, str(e)
    created = []
    try:
        with conn:
            with conn.cursor() as cur:
                schema = _safe_prefix(cfg["schema_name"] or "public")
                if schema != "public":
                    cur.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')
                for table, cols in _PG_TABLE_DEFS.items():
                    full = pg_full_table_name(cfg, table)
                    cur.execute(f"CREATE TABLE IF NOT EXISTS {full} ({cols})")
                    cur.execute(
                        f"CREATE INDEX IF NOT EXISTS "
                        f'"idx_{_safe_prefix(cfg["table_prefix"])}_{table}_ts" '
                        f'ON {full} (ts)'
                    )
                    created.append(table)
    except Exception as e:
        conn.close()
        msg = str(e).strip().splitlines()[0][:300]
        with connect() as c:
            c.execute(
                "UPDATE pg_config SET last_init_at=?, last_init_msg=? WHERE id=1",
                (int(time.time()), f"ERRO: {msg}"),
            )
        return False, msg
    conn.close()
    msg = f"{len(created)} tabela(s) verificada(s)/criada(s)"
    with connect() as c:
        c.execute(
            "UPDATE pg_config SET last_init_at=?, last_init_msg=? WHERE id=1",
            (int(time.time()), msg),
        )
    return True, msg


def pg_insert_many(table: str, rows: list[dict]):
    """Insere rows na tabela equivalente do Postgres remoto (dual-write).

    Falha silenciosa se PG não estiver habilitado/acessível — local nunca é
    impactado. Use ON CONFLICT DO NOTHING para idempotência.
    """
    if not rows:
        return
    if table not in _PG_TABLE_DEFS:
        return
    cfg = pg_get_config()
    if not cfg["enabled"]:
        return
    try:
        conn, _ = _pg_connect()
    except Exception:
        return
    try:
        full = pg_full_table_name(cfg, table)
        cols = list(rows[0].keys())
        placeholders = ",".join(["%s"] * len(cols))
        cols_quoted = ",".join(f'"{c}"' for c in cols)
        sql_stmt = (f"INSERT INTO {full} ({cols_quoted}) VALUES ({placeholders}) "
                    "ON CONFLICT DO NOTHING")
        with conn:
            with conn.cursor() as cur:
                cur.executemany(
                    sql_stmt,
                    [tuple(r.get(c) for c in cols) for r in rows],
                )
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def pg_purge_retention():
    """Apaga rows > retention_days do PG remoto."""
    cfg = pg_get_config()
    if not cfg["enabled"] or not cfg.get("retention_days"):
        return
    cutoff = int(time.time()) - int(cfg["retention_days"]) * 86400
    try:
        conn, _ = _pg_connect()
    except Exception:
        return
    try:
        with conn:
            with conn.cursor() as cur:
                for table in _PG_TABLE_DEFS:
                    full = pg_full_table_name(cfg, table)
                    cur.execute(f"DELETE FROM {full} WHERE ts < %s", (cutoff,))
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def pg_list_existing_tables() -> list[dict]:
    """Lista tabelas no PG com o prefix configurado + tamanho aproximado."""
    cfg = pg_get_config()
    try:
        conn, _ = _pg_connect()
    except Exception as e:
        return []
    prefix = _safe_prefix(cfg.get("table_prefix") or pg_default_prefix())
    schema = _safe_prefix(cfg.get("schema_name") or "public")
    rows = []
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT relname, pg_size_pretty(pg_total_relation_size(c.oid)), "
                "(SELECT count(*) FROM pg_stat_user_tables s WHERE s.relid=c.oid) "
                "FROM pg_class c "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = %s AND c.relname LIKE %s AND c.relkind = 'r' "
                "ORDER BY relname",
                (schema, f"{prefix}_%"),
            )
            for name, size, _ in cur.fetchall():
                # Conta rows via SELECT count(*) (mais preciso que stat)
                cur.execute(f'SELECT COUNT(*) FROM "{schema}"."{name}"')
                count = cur.fetchone()[0]
                rows.append({"name": name, "size": size, "rows": count})
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass
    return rows
