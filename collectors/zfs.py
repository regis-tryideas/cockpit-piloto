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

    def _ratio(num, denom):
        return round(100.0 * num / denom, 2) if denom else 0.0

    size = info.get("size", 0)
    cmax = info.get("c_max", 0)
    cmin = info.get("c_min", 0)
    hits = info.get("hits", 0)
    misses = info.get("misses", 0)
    total = hits + misses

    dd_hits = info.get("demand_data_hits", 0)
    dd_miss = info.get("demand_data_misses", 0)
    dm_hits = info.get("demand_metadata_hits", 0)
    dm_miss = info.get("demand_metadata_misses", 0)
    pd_hits = info.get("prefetch_data_hits", 0)
    pd_miss = info.get("prefetch_data_misses", 0)
    pm_hits = info.get("prefetch_metadata_hits", 0)
    pm_miss = info.get("prefetch_metadata_misses", 0)

    l2_hits = info.get("l2_hits", 0)
    l2_misses = info.get("l2_misses", 0)
    l2_total = l2_hits + l2_misses

    return {
        "size_gib": _bytes_to_gib(size),
        "c_max_gib": _bytes_to_gib(cmax),
        "c_min_gib": _bytes_to_gib(cmin),
        "fill_pct": _ratio(size, cmax),
        "hits": hits,
        "misses": misses,
        "hit_ratio_pct": _ratio(hits, total),

        "mfu_size_b": info.get("mfu_size", 0),
        "mru_size_b": info.get("mru_size", 0),
        "mfu_size_gib": _bytes_to_gib(info.get("mfu_size", 0)),
        "mru_size_gib": _bytes_to_gib(info.get("mru_size", 0)),
        "mfu_ghost_hits": info.get("mfu_ghost_hits", 0),
        "mru_ghost_hits": info.get("mru_ghost_hits", 0),

        "demand_data": {
            "hits": dd_hits, "misses": dd_miss,
            "hit_ratio_pct": _ratio(dd_hits, dd_hits + dd_miss),
        },
        "demand_metadata": {
            "hits": dm_hits, "misses": dm_miss,
            "hit_ratio_pct": _ratio(dm_hits, dm_hits + dm_miss),
        },
        "prefetch_data": {
            "hits": pd_hits, "misses": pd_miss,
            "hit_ratio_pct": _ratio(pd_hits, pd_hits + pd_miss),
        },
        "prefetch_metadata": {
            "hits": pm_hits, "misses": pm_miss,
            "hit_ratio_pct": _ratio(pm_hits, pm_hits + pm_miss),
        },

        "l2_size_gib": _bytes_to_gib(info.get("l2_size", 0)),
        "l2_hits": l2_hits,
        "l2_misses": l2_misses,
        "l2_hit_ratio_pct": _ratio(l2_hits, l2_total),
        "l2_read_bytes": info.get("l2_read_bytes", 0),
        "l2_write_bytes": info.get("l2_write_bytes", 0),

        "compressed_size_gib": _bytes_to_gib(info.get("compressed_size", 0)),
        "uncompressed_size_gib": _bytes_to_gib(info.get("uncompressed_size", 0)),
        "compress_ratio": (
            round(info.get("uncompressed_size", 0) / info.get("compressed_size", 1), 2)
            if info.get("compressed_size") else 0.0
        ),

        "memory_throttle_count": info.get("memory_throttle_count", 0),
    }


def vdev_io(interval: int = 1) -> list[dict]:
    """zpool iostat -v -p <interval> 2 — IO por vdev (segunda amostra)."""
    out = _run(
        ["zpool", "iostat", "-v", "-p", str(interval), "2"],
        timeout=interval + 5,
    )
    if not out:
        return []
    blocks = []
    cur = []
    for line in out.splitlines():
        if line.startswith("---"):
            continue
        if line.strip() == "":
            if cur:
                blocks.append(cur)
                cur = []
            continue
        cur.append(line)
    if cur:
        blocks.append(cur)
    if not blocks:
        return []
    sample = blocks[-1]
    rows = []
    current_pool = None
    for line in sample:
        if line.startswith("pool") or line.lstrip().startswith("capacity"):
            continue
        indent = len(line) - len(line.lstrip())
        parts = line.split()
        if len(parts) < 7:
            continue
        try:
            row = {
                "name": parts[0],
                "indent": indent,
                "alloc_gib": _bytes_to_gib(int(parts[1])),
                "free_gib": _bytes_to_gib(int(parts[2])),
                "read_iops": int(parts[3]),
                "write_iops": int(parts[4]),
                "read_bw": int(parts[5]),
                "write_bw": int(parts[6]),
            }
        except (ValueError, IndexError):
            continue
        if indent == 0:
            current_pool = row["name"]
        row["pool"] = current_pool
        rows.append(row)
    return rows


def pool_latency(interval: int = 1) -> list[dict]:
    """zpool iostat -p -l <interval> 2 — latências (read_wait, write_wait, etc).

    Disponível em ZFS 0.7+.
    """
    out = _run(
        ["zpool", "iostat", "-H", "-p", "-l", str(interval), "2"],
        timeout=interval + 5,
    )
    if not out:
        return []
    blocks = []
    cur = []
    for line in out.splitlines():
        if not line.strip():
            if cur:
                blocks.append(cur)
                cur = []
            continue
        cur.append(line)
    if cur:
        blocks.append(cur)
    sample = blocks[-1] if blocks else []
    rows = []
    for line in sample:
        parts = line.split("\t") if "\t" in line else line.split()
        if len(parts) < 13:
            continue
        try:
            rows.append({
                "name": parts[0],
                "total_wait_read_ns": _parse_int(parts[7]),
                "total_wait_write_ns": _parse_int(parts[8]),
                "disk_wait_read_ns": _parse_int(parts[9]),
                "disk_wait_write_ns": _parse_int(parts[10]),
                "syncq_wait_read_ns": _parse_int(parts[11]),
                "syncq_wait_write_ns": _parse_int(parts[12]),
            })
        except (ValueError, IndexError):
            continue
    return rows


def _parse_int(v: str) -> int:
    try:
        return int(v)
    except ValueError:
        return 0


def scrub_status(name: str) -> dict | None:
    """Extrai status de scrub/resilver de 'zpool status'."""
    out = _run(["zpool", "status", name])
    if not out:
        return None
    info = {"action": None, "progress_pct": None, "examined": None,
            "to_examine": None, "speed": None, "eta": None, "completed": None,
            "errors_repaired": None}
    in_scan = False
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("scan:"):
            in_scan = True
            rest = s[len("scan:"):].strip()
            if rest:
                info["action"] = rest
            continue
        if in_scan:
            if s.startswith(("config:", "errors:")):
                in_scan = False
                continue
            low = s.lower()
            if "no requested" in low:
                info["action"] = "nenhum scrub solicitado"
                in_scan = False
            elif "scrub repaired" in low or "resilvered" in low:
                info["completed"] = s
            elif "scan in progress" in low or "resilver in progress" in low:
                info["action"] = s
            elif "%" in s and ("done" in low or "issued" in low):
                info["progress_pct"] = _extract_pct(s)
                info["examined"] = s
            elif "to go" in low:
                info["eta"] = s
            elif "/s" in s and ("read" in low or "issued" in low):
                info["speed"] = s
    if all(v is None for v in info.values()):
        return None
    return info


def _extract_pct(text: str) -> float | None:
    import re
    m = re.search(r"(\d+(?:[.,]\d+)?)\s*%", text)
    if not m:
        return None
    return float(m.group(1).replace(",", "."))


def snapshot_summary() -> dict:
    """Conta snapshots e soma o espaço usado."""
    out = _run([
        "zfs", "list", "-H", "-p", "-t", "snapshot", "-o", "used",
    ], timeout=10)
    if out is None:
        return {"count": 0, "total_used_gib": 0.0}
    lines = [l for l in out.strip().splitlines() if l]
    total = 0
    for line in lines:
        try:
            total += int(line.strip())
        except ValueError:
            continue
    return {"count": len(lines), "total_used_gib": _bytes_to_gib(total)}


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
    scrubs = {p["name"]: scrub_status(p["name"]) for p in pool_list}
    return {
        "available": state,
        "interval": interval,
        "pools": pool_list,
        "statuses": statuses,
        "scrubs": scrubs,
        "datasets": datasets(),
        "arc": arc_stats(),
        "io": pool_io(interval),
        "vdev_io": vdev_io(interval),
        "latency": pool_latency(interval),
        "snapshots": snapshot_summary(),
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
