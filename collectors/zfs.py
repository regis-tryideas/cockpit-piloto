import shutil
import subprocess
from pathlib import Path

ARCSTATS_PATH = Path("/proc/spl/kstat/zfs/arcstats")


def available() -> dict:
    """Detecta o estado do ZFS no host."""
    has_kmod = ARCSTATS_PATH.exists()
    has_zpool = shutil.which("zpool") is not None
    has_zfs = shutil.which("zfs") is not None
    return {
        "kmod": has_kmod,
        "zpool": has_zpool,
        "zfs": has_zfs,
        "ok": has_kmod and has_zpool and has_zfs,
    }


def _run(cmd: list[str], timeout: int = 5) -> str | None:
    try:
        return subprocess.check_output(
            cmd, stderr=subprocess.STDOUT, timeout=timeout
        ).decode(errors="replace")
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _bytes_to_gib(n: int) -> float:
    return round(n / (1024**3), 2)


def pools() -> list[dict]:
    """zpool list -H -p -o name,size,alloc,free,frag,cap,dedup,health"""
    out = _run([
        "zpool", "list", "-H", "-p", "-o",
        "name,size,alloc,free,fragmentation,capacity,dedupratio,health",
    ])
    if not out:
        return []
    rows = []
    for line in out.strip().splitlines():
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        try:
            size = int(parts[1])
            alloc = int(parts[2])
            free = int(parts[3])
        except ValueError:
            size = alloc = free = 0
        rows.append({
            "name": parts[0],
            "size_gib": _bytes_to_gib(size),
            "alloc_gib": _bytes_to_gib(alloc),
            "free_gib": _bytes_to_gib(free),
            "fragmentation": parts[4],
            "capacity": parts[5],
            "dedup": parts[6],
            "health": parts[7],
        })
    return rows


def pool_status(name: str) -> dict:
    """zpool status -p <pool> — devolve health, errors e a árvore de vdevs."""
    out = _run(["zpool", "status", "-p", name])
    if not out:
        return {}

    info = {"raw": out, "vdevs": [], "errors": None}
    in_config = False
    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("errors:"):
            info["errors"] = stripped[len("errors:"):].strip()
        if stripped.startswith("config:"):
            in_config = True
            continue
        if in_config:
            if not stripped:
                if info["vdevs"]:
                    in_config = False
                continue
            if stripped.startswith("NAME"):
                continue
            cols = stripped.split()
            if len(cols) < 5:
                continue
            indent = len(line) - len(line.lstrip())
            info["vdevs"].append({
                "indent": indent,
                "name": cols[0],
                "state": cols[1],
                "read": cols[2],
                "write": cols[3],
                "cksum": cols[4],
            })
    return info


def datasets() -> list[dict]:
    """zfs list -H -p -t filesystem,volume -o name,used,avail,refer,mountpoint,compressratio"""
    out = _run([
        "zfs", "list", "-H", "-p", "-t", "filesystem,volume", "-o",
        "name,used,available,referenced,mountpoint,compressratio",
    ])
    if not out:
        return []
    rows = []
    for line in out.strip().splitlines():
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        try:
            used = int(parts[1])
            avail = int(parts[2])
            refer = int(parts[3])
        except ValueError:
            continue
        rows.append({
            "name": parts[0],
            "used_gib": _bytes_to_gib(used),
            "avail_gib": _bytes_to_gib(avail),
            "referenced_gib": _bytes_to_gib(refer),
            "mountpoint": parts[4],
            "compressratio": parts[5],
        })
    return rows


def arc_stats() -> dict:
    """Lê /proc/spl/kstat/zfs/arcstats e devolve métricas-chave."""
    if not ARCSTATS_PATH.exists():
        return {}
    info = {}
    try:
        for line in ARCSTATS_PATH.read_text().splitlines()[2:]:
            parts = line.split()
            if len(parts) >= 3 and parts[1] == "4":
                try:
                    info[parts[0]] = int(parts[2])
                except ValueError:
                    continue
    except OSError:
        return {}

    size = info.get("size", 0)
    cmax = info.get("c_max", 0)
    cmin = info.get("c_min", 0)
    hits = info.get("hits", 0)
    misses = info.get("misses", 0)
    total = hits + misses
    hit_ratio = round(100.0 * hits / total, 2) if total else 0.0

    return {
        "size_gib": _bytes_to_gib(size),
        "c_max_gib": _bytes_to_gib(cmax),
        "c_min_gib": _bytes_to_gib(cmin),
        "fill_pct": round(100.0 * size / cmax, 2) if cmax else 0.0,
        "hits": hits,
        "misses": misses,
        "hit_ratio_pct": hit_ratio,
        "demand_data_hits": info.get("demand_data_hits", 0),
        "demand_metadata_hits": info.get("demand_metadata_hits", 0),
        "prefetch_data_hits": info.get("prefetch_data_hits", 0),
        "l2_hits": info.get("l2_hits", 0),
        "l2_misses": info.get("l2_misses", 0),
    }


def pool_io(interval: int = 1) -> list[dict]:
    """zpool iostat -H -p <interval> 2 — usa segunda amostra (média do intervalo)."""
    out = _run(
        ["zpool", "iostat", "-H", "-p", str(interval), "2"],
        timeout=interval + 5,
    )
    if not out:
        return []
    blocks = []
    cur = []
    for line in out.splitlines():
        if line.strip() == "":
            if cur:
                blocks.append(cur)
                cur = []
            continue
        cur.append(line)
    if cur:
        blocks.append(cur)

    sample = blocks[1] if len(blocks) >= 2 else (blocks[0] if blocks else [])
    rows = []
    for line in sample:
        parts = line.split("\t") if "\t" in line else line.split()
        if len(parts) < 7:
            continue
        try:
            rows.append({
                "name": parts[0],
                "alloc_gib": _bytes_to_gib(int(parts[1])),
                "free_gib": _bytes_to_gib(int(parts[2])),
                "read_iops": int(parts[3]),
                "write_iops": int(parts[4]),
                "read_bw": int(parts[5]),
                "write_bw": int(parts[6]),
            })
        except ValueError:
            continue
    return rows


def collect(interval: int = 1) -> dict:
    state = available()
    if not state["ok"]:
        return {"available": state, "error": _availability_message(state)}

    pool_list = pools()
    statuses = {p["name"]: pool_status(p["name"]) for p in pool_list}
    return {
        "available": state,
        "interval": interval,
        "pools": pool_list,
        "statuses": statuses,
        "datasets": datasets(),
        "arc": arc_stats(),
        "io": pool_io(interval),
    }


def _availability_message(state: dict) -> str:
    missing = []
    if not state["kmod"]:
        missing.append("módulo kernel zfs (instale zfs-dkms ou zfs-modules)")
    if not state["zpool"]:
        missing.append("comando zpool (pacote zfsutils-linux)")
    if not state["zfs"]:
        missing.append("comando zfs (pacote zfsutils-linux)")
    return "ZFS indisponível: " + ", ".join(missing)
