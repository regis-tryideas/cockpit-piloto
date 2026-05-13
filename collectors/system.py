import os
import platform
import socket
import subprocess
import time

import psutil

DISTRO_FILE = "/etc/os-release"


def _distro() -> dict:
    info = {"pretty_name": None, "id": None, "version": None}
    try:
        with open(DISTRO_FILE) as f:
            for line in f:
                if "=" not in line:
                    continue
                k, v = line.strip().split("=", 1)
                v = v.strip().strip('"')
                if k == "PRETTY_NAME":
                    info["pretty_name"] = v
                elif k == "ID":
                    info["id"] = v
                elif k == "VERSION":
                    info["version"] = v
    except OSError:
        pass
    return info


def info() -> dict:
    boot = psutil.boot_time()
    uptime_s = int(time.time() - boot)
    return {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "kernel": platform.release(),
        "kernel_version": platform.version(),
        "arch": platform.machine(),
        "python": platform.python_version(),
        "distro": _distro(),
        "uptime_s": uptime_s,
        "boot_ts": int(boot),
        "logical_cpus": psutil.cpu_count(logical=True),
        "physical_cpus": psutil.cpu_count(logical=False),
    }


def process_states() -> dict:
    states = {"R": 0, "S": 0, "D": 0, "Z": 0, "T": 0, "I": 0, "X": 0}
    total = 0
    threads = 0
    try:
        with os.scandir("/proc") as it:
            for entry in it:
                if not entry.name.isdigit():
                    continue
                try:
                    with open(f"/proc/{entry.name}/stat") as f:
                        fields = f.read().split()
                    state = fields[2]
                    states[state] = states.get(state, 0) + 1
                    total += 1
                    threads += int(fields[19])
                except (FileNotFoundError, PermissionError, IndexError, ValueError):
                    continue
    except OSError:
        pass
    return {
        "total": total,
        "threads": threads,
        "running": states.get("R", 0),
        "sleeping": states.get("S", 0),
        "disk_sleep": states.get("D", 0),
        "zombie": states.get("Z", 0),
        "stopped": states.get("T", 0),
        "idle": states.get("I", 0),
    }


def d_state_processes(limit: int = 30) -> list[dict]:
    """Lista processos em D-state (uninterruptible sleep).

    D-state significa que o processo está bloqueado em I/O ou lock no kernel
    e NÃO pode ser interrompido (nem com SIGKILL). Picos curtos são normais;
    processos sustentados em D indicam gargalo real de disco ou bug de driver.
    """
    rows = []
    try:
        ticks_per_sec = os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError):
        ticks_per_sec = 100

    try:
        with os.scandir("/proc") as it:
            for entry in it:
                if not entry.name.isdigit():
                    continue
                try:
                    with open(f"/proc/{entry.name}/stat") as f:
                        line = f.read()
                    # Parse cuidadoso: o comm está entre parênteses mas pode
                    # conter espaços. Separamos pelos parênteses.
                    open_paren = line.find("(")
                    close_paren = line.rfind(")")
                    if open_paren < 0 or close_paren < 0:
                        continue
                    comm = line[open_paren + 1:close_paren]
                    rest = line[close_paren + 2:].split()
                    state = rest[0]
                    if state != "D":
                        continue
                    blkio_ticks = int(rest[39]) if len(rest) > 39 else 0
                    blkio_seconds = round(blkio_ticks / ticks_per_sec, 2)
                except (FileNotFoundError, PermissionError, IndexError, ValueError):
                    continue
                try:
                    with open(f"/proc/{entry.name}/wchan") as f:
                        wchan = f.read().strip()
                except OSError:
                    wchan = "?"
                try:
                    with open(f"/proc/{entry.name}/cmdline", "rb") as f:
                        raw = f.read()
                    cmdline = raw.replace(b"\x00", b" ").decode(
                        errors="replace").strip()
                except OSError:
                    cmdline = ""
                rows.append({
                    "pid": int(entry.name),
                    "comm": comm,
                    "cmdline": cmdline or f"[{comm}]",
                    "wchan": wchan or "?",
                    "blkio_seconds": blkio_seconds,
                    "is_kthread": not cmdline,
                })
    except OSError:
        pass

    # Ordena por blkio_seconds desc (mais bloqueados em IO no topo)
    rows.sort(key=lambda r: r["blkio_seconds"], reverse=True)
    return rows[:limit]


def fd_stats() -> dict:
    try:
        with open("/proc/sys/fs/file-nr") as f:
            allocated, free, max_fd = f.read().split()
        return {
            "allocated": int(allocated),
            "free": int(free),
            "max": int(max_fd),
            "used_pct": round(100.0 * int(allocated) / int(max_fd), 2) if int(max_fd) else 0.0,
        }
    except OSError:
        return {}


def logged_users() -> list[dict]:
    users = []
    for u in psutil.users():
        users.append({
            "name": u.name,
            "terminal": u.terminal,
            "host": u.host or "",
            "started_ts": int(u.started),
        })
    return users


def top_processes(limit: int = 15) -> dict:
    """Devolve top por CPU% (com janela de 1s) e por memória.

    Usa psutil: a primeira chamada cpu_percent(interval=None) retorna 0.0,
    então fazemos um warmup, dormimos 1s e medimos de novo.
    """
    snapshot = []
    for p in psutil.process_iter(["pid", "name", "username"]):
        try:
            p.cpu_percent(interval=None)  # warmup
            snapshot.append(p)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    time.sleep(1.0)

    cpu_count = psutil.cpu_count() or 1
    rows = []
    for p in snapshot:
        try:
            with p.oneshot():
                cpu = p.cpu_percent(interval=None)
                mi = p.memory_info()
                rows.append({
                    "pid": p.pid,
                    "name": p.info.get("name") or "",
                    "user": p.info.get("username") or "",
                    "cpu_pct": round(cpu, 2),
                    "cpu_normalized_pct": round(cpu / cpu_count, 2),
                    "rss_b": mi.rss,
                    "vms_b": mi.vms,
                    "num_threads": p.num_threads(),
                    "status": p.status(),
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    by_cpu = sorted(rows, key=lambda r: r["cpu_pct"], reverse=True)[:limit]
    by_mem = sorted(rows, key=lambda r: r["rss_b"], reverse=True)[:limit]

    total_mem = psutil.virtual_memory().total or 1
    for r in by_mem:
        r["mem_pct"] = round(100.0 * r["rss_b"] / total_mem, 2)
    for r in by_cpu:
        r["mem_pct"] = round(100.0 * r["rss_b"] / total_mem, 2)

    return {"by_cpu": by_cpu, "by_mem": by_mem}


def collect(top_limit: int = 15) -> dict:
    top = top_processes(limit=top_limit)
    return {
        "info": info(),
        "states": process_states(),
        "fds": fd_stats(),
        "users": logged_users(),
        "top_cpu": top["by_cpu"],
        "top_mem": top["by_mem"],
    }
