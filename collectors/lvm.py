import json
import shutil
import subprocess


def has_lvm() -> bool:
    return shutil.which("lvs") is not None and shutil.which("vgs") is not None


def has_thin_tools() -> bool:
    """thin_send/thin_recv vêm do pacote thin-provisioning-tools."""
    return (shutil.which("thin_send") is not None
            and shutil.which("thin_recv") is not None
            and shutil.which("thin_delta") is not None)


def _run_json(cmd: list[str], timeout: int = 5):
    try:
        out = subprocess.check_output(
            cmd, stderr=subprocess.STDOUT, timeout=timeout,
        )
        return json.loads(out)
    except (subprocess.CalledProcessError, FileNotFoundError,
            subprocess.TimeoutExpired, json.JSONDecodeError):
        return None


def list_vgs() -> list[dict]:
    """Lista volume groups."""
    data = _run_json([
        "vgs", "--reportformat=json", "--units=b",
        "-o", "vg_name,vg_size,vg_free,pv_count,lv_count",
    ])
    if not data:
        return []
    rows = []
    for r in (data.get("report") or [{}])[0].get("vg", []):
        try:
            rows.append({
                "name": r["vg_name"],
                "size_b": int(r["vg_size"].rstrip("B")),
                "free_b": int(r["vg_free"].rstrip("B")),
                "pv_count": int(r["pv_count"]),
                "lv_count": int(r["lv_count"]),
            })
        except (KeyError, ValueError):
            continue
    return rows


def list_thin_pools() -> list[dict]:
    """Lista thin pools no host (necessários pra thin_send/recv)."""
    data = _run_json([
        "lvs", "--reportformat=json", "--units=b",
        "-o", "vg_name,lv_name,lv_size,data_percent,metadata_percent,segtype",
        "-S", "segtype=thin-pool",
    ])
    if not data:
        return []
    rows = []
    for r in (data.get("report") or [{}])[0].get("lv", []):
        try:
            rows.append({
                "vg": r["vg_name"],
                "name": r["lv_name"],
                "size_b": int(r["lv_size"].rstrip("B")),
                "data_pct": float(r.get("data_percent") or 0),
                "metadata_pct": float(r.get("metadata_percent") or 0),
            })
        except (KeyError, ValueError):
            continue
    return rows


def list_thin_volumes(vg: str | None = None,
                      pool: str | None = None) -> list[dict]:
    """Lista volumes thin (origem=<pool>) — candidatos a serem replicados."""
    sel = "lv_layout=thin"
    if vg and pool:
        sel += f" && pool_lv={pool} && vg_name={vg}"
    data = _run_json([
        "lvs", "--reportformat=json", "--units=b",
        "-o", "vg_name,lv_name,pool_lv,lv_size,data_percent,origin,lv_attr",
        "-S", sel,
    ])
    if not data:
        return []
    rows = []
    for r in (data.get("report") or [{}])[0].get("lv", []):
        try:
            attr = r.get("lv_attr") or ""
            # 'V' = thin volume; 't' = thin pool. Filtra só volumes.
            if not attr.startswith("V"):
                continue
            rows.append({
                "vg": r["vg_name"],
                "name": r["lv_name"],
                "pool": r["pool_lv"],
                "size_b": int(r["lv_size"].rstrip("B")),
                "data_pct": float(r.get("data_percent") or 0),
                "origin": r.get("origin") or None,
                "is_snapshot": bool(r.get("origin")),
            })
        except (KeyError, ValueError):
            continue
    return rows


def collect() -> dict:
    """Snapshot da topologia LVM relevante."""
    if not has_lvm():
        return {
            "available": False,
            "error": "LVM não instalado (lvm2 ausente).",
        }
    return {
        "available": True,
        "thin_tools": has_thin_tools(),
        "vgs": list_vgs(),
        "thin_pools": list_thin_pools(),
        "thin_volumes": list_thin_volumes(),
    }
