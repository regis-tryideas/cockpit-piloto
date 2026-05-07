import json
import shutil
import subprocess
import time

PRIORITY_LABELS = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]
DEFAULT_LINES = 200
MAX_LINES = 2000

WINDOW_PRESETS = {
    "10m": "10 minutes ago",
    "1h":  "1 hour ago",
    "6h":  "6 hours ago",
    "24h": "1 day ago",
    "7d":  "7 days ago",
}


def has_journalctl() -> bool:
    return shutil.which("journalctl") is not None


def has_dmesg() -> bool:
    return shutil.which("dmesg") is not None


def list_units(prefix: str = "", limit: int = 200) -> list[str]:
    """Lista de units conhecidas pelo journal (para autocompletar)."""
    if not has_journalctl():
        return []
    try:
        out = subprocess.check_output(
            ["journalctl", "--field=_SYSTEMD_UNIT"],
            stderr=subprocess.DEVNULL, timeout=5,
        ).decode(errors="replace")
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return []
    units = sorted({u for u in out.splitlines() if u and (not prefix or prefix in u)})
    return units[:limit]


def journal(priority: int = 7, unit: str | None = None, since: str = "1h",
            search: str = "", lines: int = DEFAULT_LINES) -> dict:
    if not has_journalctl():
        return {"error": "journalctl não está disponível.", "rows": []}

    lines = max(1, min(int(lines), MAX_LINES))
    since_arg = WINDOW_PRESETS.get(since, since)

    cmd = [
        "journalctl", "--output=json", "--no-pager",
        f"--lines={lines}",
        f"--priority={priority}",
        f"--since={since_arg}",
    ]
    if unit:
        cmd += ["-u", unit]
    if search:
        # --grep usa regex Perl-like; escapar é mais seguro pelo input do usuário
        cmd += [f"--grep={search}"]

    try:
        out = subprocess.check_output(
            cmd, stderr=subprocess.STDOUT, timeout=20,
        ).decode(errors="replace")
    except subprocess.TimeoutExpired:
        return {"error": "journalctl excedeu o tempo limite (20s).", "rows": []}
    except subprocess.CalledProcessError as e:
        return {"error": f"journalctl falhou: {e.output.decode(errors='replace')[:200]}", "rows": []}

    rows = []
    for line in out.splitlines():
        if not line.strip():
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        ts_us = d.get("__REALTIME_TIMESTAMP")
        try:
            ts = int(ts_us) // 1_000_000 if ts_us else None
        except (TypeError, ValueError):
            ts = None
        try:
            prio = int(d.get("PRIORITY", "6"))
        except (TypeError, ValueError):
            prio = 6
        unit_name = d.get("_SYSTEMD_UNIT") or d.get("UNIT") or ""
        rows.append({
            "ts": ts,
            "priority": prio,
            "priority_label": PRIORITY_LABELS[prio] if 0 <= prio < 8 else str(prio),
            "unit": unit_name,
            "comm": d.get("_COMM") or d.get("SYSLOG_IDENTIFIER") or "",
            "pid": d.get("_PID") or "",
            "host": d.get("_HOSTNAME") or "",
            "message": d.get("MESSAGE") or "",
        })
    return {"rows": rows, "total": len(rows)}


def kernel_buffer(lines: int = DEFAULT_LINES, search: str = "") -> dict:
    """dmesg — kernel ring buffer."""
    if not has_dmesg():
        return {"error": "dmesg não está disponível.", "rows": []}

    lines = max(1, min(int(lines), MAX_LINES))

    cmd = ["dmesg", "--time-format=iso", "--color=never"]
    try:
        out = subprocess.check_output(
            cmd, stderr=subprocess.STDOUT, timeout=10,
        ).decode(errors="replace")
    except subprocess.CalledProcessError as e:
        # Em alguns kernels dmesg sem privilégio falha; tentar fallback.
        return {"error": f"dmesg falhou: {e.output.decode(errors='replace')[:200]}", "rows": []}
    except subprocess.TimeoutExpired:
        return {"error": "dmesg excedeu o tempo limite.", "rows": []}

    all_lines = out.splitlines()
    rows = []
    for line in all_lines:
        if not line.strip():
            continue
        if search and search.lower() not in line.lower():
            continue
        ts_str = ""
        msg = line
        # Formato esperado: "2026-04-28T08:26:45,123456-0300 mensagem..."
        # Quando time-format=iso, dmesg não envolve em colchetes.
        parts = line.split(" ", 1)
        if parts and "T" in parts[0] and len(parts) == 2:
            ts_str = parts[0]
            msg = parts[1]
        rows.append({"ts": ts_str, "message": msg})

    # Mantém só as últimas N
    rows = rows[-lines:]
    return {"rows": rows, "total": len(rows)}
