import json
import re
import shutil
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

PVE_DIR = Path("/etc/pve")
DISK_KEYS = ("scsi", "sata", "ide", "virtio", "efidisk", "tpmstate", "rootfs", "mp")

_cache = {"storages": None, "storages_ts": 0}
_CACHE_TTL = 60


def detect() -> dict:
    """Detecta se este host é um Proxmox VE node."""
    has_pve_dir = PVE_DIR.exists()
    has_pvesh = shutil.which("pvesh") is not None
    has_qm = shutil.which("qm") is not None
    version = None
    if shutil.which("pveversion") is not None:
        try:
            version = subprocess.check_output(
                ["pveversion"], stderr=subprocess.STDOUT, timeout=3
            ).decode(errors="replace").strip().splitlines()[0]
        except Exception:
            pass
    node_name = socket.gethostname() if has_pve_dir else None
    return {
        "pve_dir": has_pve_dir,
        "pvesh": has_pvesh,
        "qm": has_qm,
        "version": version,
        "node": node_name,
        "ok": has_pve_dir and has_pvesh,
    }


def _run_json(cmd: list[str], timeout: int = 10):
    try:
        out = subprocess.check_output(
            cmd, stderr=subprocess.STDOUT, timeout=timeout
        )
        return json.loads(out)
    except (subprocess.CalledProcessError, FileNotFoundError,
            subprocess.TimeoutExpired, json.JSONDecodeError):
        return None


def _run_text(cmd: list[str], timeout: int = 5) -> str | None:
    try:
        return subprocess.check_output(
            cmd, stderr=subprocess.STDOUT, timeout=timeout
        ).decode(errors="replace")
    except (subprocess.CalledProcessError, FileNotFoundError,
            subprocess.TimeoutExpired):
        return None


def cluster_vms() -> list[dict]:
    """pvesh get /cluster/resources --type vm — retorna QEMU + LXC."""
    data = _run_json([
        "pvesh", "get", "/cluster/resources",
        "--type", "vm", "--output-format=json",
    ])
    return data or []


def storages() -> list[dict]:
    """Lista storages com cache (mudam pouco)."""
    now = time.time()
    if _cache["storages"] and (now - _cache["storages_ts"] < _CACHE_TTL):
        return _cache["storages"]
    data = _run_json(["pvesh", "get", "/storage", "--output-format=json"])
    if data is None:
        data = []
    _cache["storages"] = data
    _cache["storages_ts"] = now
    return data


def _storage_index() -> dict:
    return {s["storage"]: s for s in storages()}


def _vm_config(vmid: int, vm_type: str) -> dict:
    """Lê config da VM (qm) ou container (pct) e retorna dict bruto."""
    cmd = ["qm" if vm_type == "qemu" else "pct", "config", str(vmid)]
    raw = _run_text(cmd, timeout=5)
    if not raw:
        return {}
    cfg = {}
    for line in raw.splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        cfg[k.strip()] = v.strip()
    return cfg


def _parse_disk_value(value: str) -> dict:
    """'local-zfs:vm-100-disk-0,size=32G,backup=0' -> {storage, volume, size, ...}."""
    parts = value.split(",")
    head = parts[0]
    extras = {}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            extras[k.strip()] = v.strip()
    storage, _, volume = head.partition(":")
    return {"storage": storage, "volume": volume, **extras}


def vm_disks(vmid: int, vm_type: str) -> list[dict]:
    """Extrai discos da config + resolve dataset ZFS quando aplicável."""
    cfg = _vm_config(vmid, vm_type)
    if not cfg:
        return []

    storages_idx = _storage_index()
    disks = []
    for key, value in cfg.items():
        if not any(key.startswith(p) for p in DISK_KEYS):
            continue
        if not value:
            continue
        # Ignora 'none' e mídias removíveis vazias
        if value.startswith("none") or "media=cdrom" in value:
            continue
        d = _parse_disk_value(value)
        d["slot"] = key
        st = storages_idx.get(d.get("storage"), {})
        d["storage_type"] = st.get("type")
        if st.get("type") == "zfspool" and st.get("pool") and d.get("volume"):
            d["zfs_dataset"] = f"{st['pool']}/{d['volume']}"
        elif st.get("type") == "dir" and st.get("path"):
            d["host_path"] = f"{st['path']}/images/{vmid}/{d.get('volume','')}"
        disks.append(d)
    return disks


_ZFS_USAGE_CACHE = {"data": None, "ts": 0}


def _zfs_dataset_usage() -> dict[str, dict]:
    """Mapa dataset -> {used_b, refer_b, compressratio} via 'zfs list -p'."""
    now = time.time()
    if _ZFS_USAGE_CACHE["data"] and (now - _ZFS_USAGE_CACHE["ts"] < 30):
        return _ZFS_USAGE_CACHE["data"]
    if shutil.which("zfs") is None:
        _ZFS_USAGE_CACHE["data"] = {}
        _ZFS_USAGE_CACHE["ts"] = now
        return {}
    raw = _run_text([
        "zfs", "list", "-H", "-p", "-t", "filesystem,volume",
        "-o", "name,used,referenced,compressratio",
    ], timeout=8)
    out = {}
    if raw:
        for line in raw.strip().splitlines():
            parts = line.split("\t")
            if len(parts) < 4:
                continue
            try:
                out[parts[0]] = {
                    "used_b": int(parts[1]),
                    "referenced_b": int(parts[2]),
                    "compressratio": parts[3],
                }
            except ValueError:
                continue
    _ZFS_USAGE_CACHE["data"] = out
    _ZFS_USAGE_CACHE["ts"] = now
    return out


def collect() -> dict:
    state = detect()
    if not state["ok"]:
        return {"available": state, "error": _msg(state)}

    vms = cluster_vms()
    # Filtra VMs deste node (ignora outras do cluster, se houver)
    node = state["node"]
    if node:
        vms = [v for v in vms if v.get("node") == node or not v.get("node")]

    zfs_usage = _zfs_dataset_usage()
    enriched = []
    zfs_groups: dict[str, list[dict]] = {}

    total_cpu_used = 0.0
    total_cpu_max = 0
    total_mem_used = 0
    total_mem_max = 0

    for v in vms:
        vmid = int(v.get("vmid", 0))
        vm_type = v.get("type", "qemu")
        disks = vm_disks(vmid, vm_type)
        for d in disks:
            ds = d.get("zfs_dataset")
            if ds:
                usage = zfs_usage.get(ds)
                if usage:
                    d["zfs_used_b"] = usage["used_b"]
                    d["zfs_referenced_b"] = usage["referenced_b"]
                    d["zfs_compressratio"] = usage["compressratio"]
                pool = ds.split("/")[0] if "/" in ds else ds
                zfs_groups.setdefault(pool, []).append({
                    "vmid": vmid, "name": v.get("name"),
                    "type": vm_type, "slot": d["slot"],
                    "dataset": ds, "size": d.get("size"),
                    "used_b": d.get("zfs_used_b"),
                    "compressratio": d.get("zfs_compressratio"),
                })

        cpu_frac = v.get("cpu") or 0.0
        maxcpu = v.get("maxcpu") or 0
        mem = v.get("mem") or 0
        maxmem = v.get("maxmem") or 0

        if v.get("status") == "running":
            total_cpu_used += cpu_frac * (maxcpu or 1)
            total_cpu_max += maxcpu or 0
            total_mem_used += mem
            total_mem_max += maxmem

        enriched.append({
            "vmid": vmid,
            "name": v.get("name", f"vm{vmid}"),
            "type": vm_type,
            "status": v.get("status"),
            "node": v.get("node"),
            "cpu_pct": round(cpu_frac * 100, 2),
            "cpu_cores": maxcpu,
            "mem_used_b": mem,
            "mem_max_b": maxmem,
            "mem_pct": round(100.0 * mem / maxmem, 2) if maxmem else 0.0,
            "disk_used_b": v.get("disk", 0),
            "disk_max_b": v.get("maxdisk", 0),
            "diskread_b": v.get("diskread", 0),
            "diskwrite_b": v.get("diskwrite", 0),
            "netin_b": v.get("netin", 0),
            "netout_b": v.get("netout", 0),
            "uptime_s": v.get("uptime", 0),
            "disks": disks,
        })

    # Conta snapshots em paralelo (cada chamada é ~200ms)
    def _count(v):
        try:
            return v["vmid"], vm_snapshot_count(v["vmid"], v["type"])
        except Exception:
            return v["vmid"], None

    if enriched:
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(_count, v) for v in enriched]
            counts = {}
            for fut in as_completed(futures, timeout=15):
                try:
                    vmid, c = fut.result()
                    counts[vmid] = c
                except Exception:
                    pass
        for v in enriched:
            v["snapshot_count"] = counts.get(v["vmid"])

    enriched.sort(key=lambda x: (x["status"] != "running", -x["cpu_pct"]))

    impact = {
        "running_count": sum(1 for v in enriched if v["status"] == "running"),
        "total_count": len(enriched),
        "cpu_used_cores": round(total_cpu_used, 2),
        "cpu_alloc_cores": total_cpu_max,
        "mem_used_b": total_mem_used,
        "mem_alloc_b": total_mem_max,
    }

    return {
        "available": state,
        "vms": enriched,
        "zfs_groups": zfs_groups,
        "impact": impact,
        "storages": storages(),
    }


def _msg(state: dict) -> str:
    if not state["pve_dir"]:
        return "Proxmox VE não detectado neste host (/etc/pve ausente)."
    if not state["pvesh"]:
        return "Comando pvesh não está disponível — instale proxmox-ve."
    return "Proxmox VE indisponível."


def vm_snapshots(vmid: int, vm_type: str) -> list[dict]:
    """Lista snapshots de uma VM (QEMU) ou container (LXC)."""
    state = detect()
    if not state["ok"] or not state["node"]:
        return []
    kind = "lxc" if vm_type == "lxc" else "qemu"
    data = _run_json([
        "pvesh", "get",
        f"/nodes/{state['node']}/{kind}/{vmid}/snapshot",
        "--output-format=json",
    ], timeout=8)
    if not data:
        return []
    rows = []
    for s in data:
        # 'current' é sempre a entrada virtual "você está aqui" — não conta
        if s.get("name") == "current":
            continue
        rows.append({
            "name":        s.get("name"),
            "description": s.get("description"),
            "snaptime":    s.get("snaptime"),
            "parent":      s.get("parent"),
            "vmstate":     bool(s.get("vmstate", 0)),
        })
    rows.sort(key=lambda r: r.get("snaptime") or 0, reverse=True)
    return rows


def vm_snapshot_count(vmid: int, vm_type: str) -> int:
    return len(vm_snapshots(vmid, vm_type))


def vm_tasks(vmid: int, limit: int = 20) -> list[dict]:
    """Tasks do PVE relacionadas à VM (start/stop/migrate/backup/...)."""
    state = detect()
    if not state["ok"] or not state["node"]:
        return []
    data = _run_json([
        "pvesh", "get", f"/nodes/{state['node']}/tasks",
        f"--vmid={vmid}", f"--limit={limit}",
        "--output-format=json",
    ], timeout=10)
    if not data:
        return []
    rows = []
    for t in data:
        rows.append({
            "upid":      t.get("upid"),
            "type":      t.get("type"),
            "user":      t.get("user"),
            "node":      t.get("node"),
            "starttime": t.get("starttime"),
            "endtime":   t.get("endtime"),
            "status":    t.get("status"),  # 'OK' / 'ERROR ...' / null se em curso
            "id":        t.get("id"),
        })
    return rows


def vm_logs(vmid: int, vm_type: str = "qemu", since: str = "1h",
            lines: int = 200) -> dict:
    """Logs da VM via journalctl filtrando pelo .scope/.service do systemd.

    QEMU: roda em <vmid>.scope dentro de qemu.slice.
    LXC : roda em pve-container@<vmid>.service dentro de lxc.slice.
    """
    from . import logs as logs_col

    if vm_type == "lxc":
        candidates = [f"pve-container@{vmid}.service", f"{vmid}.scope"]
    else:
        candidates = [f"{vmid}.scope", f"qemu-{vmid}.scope"]

    last_error = None
    for unit in candidates:
        result = logs_col.journal(
            priority=7, unit=unit, since=since, lines=lines,
        )
        if result.get("error"):
            last_error = result["error"]
            continue
        if result.get("rows"):
            return {"unit": unit, **result}
    return {"unit": candidates[0], "rows": [],
            "error": last_error or "nenhum log encontrado"}
    """Devolve linhas prontas pra inserção em metrics_pve_vm."""
    return [{
        "vmid": v["vmid"],
        "type": v["type"],
        "name": v["name"],
        "status": v["status"],
        "cpu_pct": v["cpu_pct"],
        "cpu_cores": v["cpu_cores"],
        "mem_used_b": v["mem_used_b"],
        "mem_max_b": v["mem_max_b"],
        "diskread_b": v["diskread_b"],
        "diskwrite_b": v["diskwrite_b"],
        "netin_b": v["netin_b"],
        "netout_b": v["netout_b"],
    } for v in vms]
