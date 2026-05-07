import os
from pathlib import Path

NODE_DIR = Path("/sys/devices/system/node")
PCI_CLASS_LABELS = {
    "01": "Storage",
    "02": "Network",
    "03": "Display",
    "0c": "Serial bus (USB etc)",
    "06": "Bridge",
    "00": "Unclassified",
}


def _read_text(p: Path) -> str | None:
    try:
        return p.read_text().strip()
    except OSError:
        return None


def _read_meminfo(node_dir: Path) -> dict:
    info = {}
    f = node_dir / "meminfo"
    if not f.exists():
        return info
    for line in f.read_text().splitlines():
        # "Node 0 MemTotal:   8130328 kB"
        if ":" not in line:
            continue
        head, _, rest = line.partition(":")
        parts = head.split()
        if len(parts) < 3:
            continue
        key = parts[2]  # ignora "Node N"
        value = rest.strip().split()
        if not value:
            continue
        try:
            info[key] = int(value[0])
        except ValueError:
            continue
    return info


def _expand_cpulist(cpulist: str) -> list[int]:
    """'0-3,8' -> [0,1,2,3,8]"""
    out = []
    for part in cpulist.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            try:
                out.extend(range(int(a), int(b) + 1))
            except ValueError:
                continue
        else:
            try:
                out.append(int(part))
            except ValueError:
                continue
    return out


def _hugepages(node_dir: Path) -> list[dict]:
    hp_dir = node_dir / "hugepages"
    if not hp_dir.exists():
        return []
    rows = []
    for entry in sorted(hp_dir.iterdir()):
        if not entry.is_dir():
            continue
        # nome tipo "hugepages-2048kB"
        size = entry.name.replace("hugepages-", "")
        nr = _read_text(entry / "nr_hugepages") or "0"
        free = _read_text(entry / "free_hugepages") or "0"
        try:
            rows.append({
                "size": size,
                "nr": int(nr),
                "free": int(free),
            })
        except ValueError:
            continue
    return rows


def _distance(node_dir: Path) -> list[int]:
    raw = _read_text(node_dir / "distance")
    if not raw:
        return []
    out = []
    for token in raw.split():
        try:
            out.append(int(token))
        except ValueError:
            continue
    return out


def _devices_for_node(node_id: int) -> dict:
    """Cataloga NICs, blocks e PCI devices ligados ao nó."""
    result = {"net": [], "block": [], "pci": []}

    # NICs
    net_dir = Path("/sys/class/net")
    if net_dir.exists():
        for iface in sorted(net_dir.iterdir()):
            nn = _read_text(iface / "device" / "numa_node")
            if nn is not None and int(nn) == node_id:
                result["net"].append(iface.name)

    # Block devices
    block_dir = Path("/sys/block")
    if block_dir.exists():
        for blk in sorted(block_dir.iterdir()):
            if blk.name.startswith(("loop", "ram", "dm-")):
                continue
            nn = _read_text(blk / "device" / "numa_node")
            if nn is not None and int(nn) == node_id:
                result["block"].append(blk.name)

    # PCI devices (resumido por classe)
    pci_dir = Path("/sys/bus/pci/devices")
    if pci_dir.exists():
        class_count = {}
        for dev in pci_dir.iterdir():
            nn = _read_text(dev / "numa_node")
            if nn is None or int(nn) != node_id:
                continue
            cls = _read_text(dev / "class")  # 0xCCSSPP
            if not cls:
                continue
            cls_high = cls[2:4]  # ex: '01' = Storage
            label = PCI_CLASS_LABELS.get(cls_high, f"class {cls_high}")
            class_count[label] = class_count.get(label, 0) + 1
        result["pci"] = [
            {"class": k, "count": v} for k, v in sorted(class_count.items())
        ]

    return result


def _online_nodes() -> list[int]:
    raw = _read_text(NODE_DIR / "online")
    if not raw:
        return []
    return _expand_cpulist(raw)


def collect() -> dict:
    if not NODE_DIR.exists():
        return {"error": "Sysfs NUMA indisponível neste kernel."}

    nodes_ids = _online_nodes()
    nodes = []
    for nid in nodes_ids:
        node_dir = NODE_DIR / f"node{nid}"
        if not node_dir.exists():
            continue
        mem = _read_meminfo(node_dir)
        cpulist_raw = _read_text(node_dir / "cpulist") or ""
        cpus = _expand_cpulist(cpulist_raw)
        total_kb = mem.get("MemTotal", 0)
        free_kb = mem.get("MemFree", 0)
        used_kb = mem.get("MemUsed", total_kb - free_kb if total_kb else 0)
        nodes.append({
            "id": nid,
            "cpu_count": len(cpus),
            "cpu_list_raw": cpulist_raw,
            "cpu_list": cpus,
            "mem_total_kb": total_kb,
            "mem_free_kb": free_kb,
            "mem_used_kb": used_kb,
            "mem_used_pct": round(100.0 * used_kb / total_kb, 2) if total_kb else 0.0,
            "active_kb": mem.get("Active", 0),
            "inactive_kb": mem.get("Inactive", 0),
            "filepages_kb": mem.get("FilePages", 0),
            "anonpages_kb": mem.get("AnonPages", 0),
            "shmem_kb": mem.get("Shmem", 0),
            "hugepages": _hugepages(node_dir),
            "distance": _distance(node_dir),
            "devices": _devices_for_node(nid),
        })

    return {
        "node_count": len(nodes),
        "nodes": nodes,
        "is_uma": len(nodes) <= 1,
    }
