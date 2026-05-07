import platform
import subprocess
from pathlib import Path

SYSCTL_GROUPS = [
    ("Memória / VM", [
        "vm.swappiness",
        "vm.dirty_ratio",
        "vm.dirty_background_ratio",
        "vm.overcommit_memory",
        "vm.overcommit_ratio",
        "vm.min_free_kbytes",
        "vm.vfs_cache_pressure",
        "vm.nr_hugepages",
        "vm.zone_reclaim_mode",
    ]),
    ("Processos / IPC", [
        "kernel.pid_max",
        "kernel.threads-max",
        "kernel.sched_migration_cost_ns",
        "kernel.shmmax",
        "kernel.shmall",
        "kernel.msgmax",
        "kernel.sem",
    ]),
    ("Filesystem / FDs", [
        "fs.file-max",
        "fs.nr_open",
        "fs.aio-max-nr",
        "fs.inotify.max_user_watches",
        "fs.inotify.max_user_instances",
    ]),
    ("Rede", [
        "net.core.somaxconn",
        "net.core.netdev_max_backlog",
        "net.core.rmem_max",
        "net.core.wmem_max",
        "net.ipv4.tcp_max_syn_backlog",
        "net.ipv4.tcp_fin_timeout",
        "net.ipv4.tcp_keepalive_time",
        "net.ipv4.tcp_tw_reuse",
        "net.ipv4.ip_local_port_range",
        "net.ipv4.ip_forward",
    ]),
]


def _read(path: Path) -> str | None:
    try:
        return path.read_text().strip()
    except OSError:
        return None


def info() -> dict:
    return {
        "release": platform.release(),
        "version_full": _read(Path("/proc/version")) or "",
        "cmdline": _read(Path("/proc/cmdline")) or "",
        "arch": platform.machine(),
        "ostype": _read(Path("/proc/sys/kernel/ostype")) or "",
        "hostname_kernel": _read(Path("/proc/sys/kernel/hostname")) or "",
    }


def modules() -> list[dict]:
    raw = _read(Path("/proc/modules"))
    if not raw:
        return []
    rows = []
    for line in raw.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 4:
            continue
        try:
            size = int(parts[1])
            instances = int(parts[2])
        except ValueError:
            continue
        depends = parts[3] if parts[3] != "-" else ""
        state = parts[4] if len(parts) > 4 else ""
        rows.append({
            "name": parts[0],
            "size_b": size,
            "size_kb": round(size / 1024, 1),
            "instances": instances,
            "depends": depends,
            "state": state,
        })
    return rows


def sysctls() -> list[dict]:
    """Devolve grupos de sysctls relevantes com seus valores."""
    groups = []
    for label, keys in SYSCTL_GROUPS:
        entries = []
        for key in keys:
            path = Path("/proc/sys") / key.replace(".", "/")
            value = _read(path)
            entries.append({"key": key, "value": value})
        groups.append({"label": label, "entries": entries})
    return groups


def taint() -> dict:
    """Estado de taint do kernel — bits setados indicam módulos não-livres,
    crashes registrados, etc."""
    raw = _read(Path("/proc/sys/kernel/tainted"))
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return {"value": 0, "flags": [], "raw": raw}
    flags = []
    bits = [
        (0,  "P",  "módulo proprietário carregado"),
        (1,  "F",  "módulo forçado"),
        (2,  "S",  "SMP com CPU não certificada"),
        (3,  "R",  "módulo removido à força"),
        (4,  "M",  "MCE — Machine Check Exception"),
        (5,  "B",  "página BAD"),
        (6,  "U",  "user requested taint"),
        (7,  "D",  "kernel oops"),
        (8,  "A",  "ACPI table overridden"),
        (9,  "W",  "kernel issued warning"),
        (10, "C",  "staging driver carregado"),
        (12, "O",  "out-of-tree module"),
        (13, "E",  "unsigned module loaded"),
        (14, "K",  "kernel live-patched"),
    ]
    for bit, sym, desc in bits:
        if value & (1 << bit):
            flags.append({"bit": bit, "symbol": sym, "desc": desc})
    return {"value": value, "flags": flags, "raw": raw}


def collect() -> dict:
    mods = modules()
    return {
        "info": info(),
        "modules_count": len(mods),
        "top_modules": sorted(mods, key=lambda m: m["size_b"], reverse=True)[:20],
        "sysctls": sysctls(),
        "taint": taint(),
    }
