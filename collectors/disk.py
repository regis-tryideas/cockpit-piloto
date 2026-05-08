import json
import re
import subprocess

from . import logical_disk

# Aceita apenas nomes "canônicos" de discos físicos:
# - sd[a-z]   (sda..sdz, mas NÃO sdaa, sdab, sdaz — esses são driver junk)
# - vd[a-z]   (vda..vdz)
# - hd[a-z]   (hda..hdz)
# - xvd[a-z]  (xvda..xvdz)
# - nvmeNnM   (namespace NVMe, ex: nvme0n1)
PHYSICAL_RE = re.compile(r"^(?:nvme\d+n\d+|sd[a-z]|vd[a-z]|hd[a-z]|xvd[a-z])$")
HIDDEN_PREFIXES = ("dm-", "zd", "md", "loop", "ram", "sr")


def _is_physical(name: str) -> bool:
    if not name:
        return False
    if name.startswith(HIDDEN_PREFIXES):
        return False
    return bool(PHYSICAL_RE.match(name))


def list_devices() -> list[str]:
    """Lista devices de bloco (tirando partições e loopbacks)."""
    devs = []
    try:
        with open("/proc/diskstats") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 14:
                    continue
                name = parts[2]
                if name.startswith(("loop", "ram", "dm-")):
                    continue
                if name and name[-1].isdigit() and any(
                    name.startswith(p) for p in ("sd", "vd", "hd", "xvd")
                ):
                    continue
                devs.append(name)
    except OSError:
        pass
    return sorted(set(devs))


def collect(interval: int = 1, devices: list[str] | None = None) -> dict:
    """Roda iostat -dxk e devolve métricas por device.

    Usa 2 amostras: a primeira reflete acumulado desde o boot (descartada),
    a segunda reflete o intervalo informado. Se ``devices`` for informado,
    filtra a saída para esses devices.
    """
    try:
        out = subprocess.check_output(
            ["iostat", "-dxk", "-o", "JSON", str(interval), "2"],
            stderr=subprocess.STDOUT,
            timeout=interval + 5,
        )
    except subprocess.CalledProcessError as e:
        return {"error": f"iostat falhou: {e.output.decode(errors='replace')}"}
    except FileNotFoundError:
        return {"error": "iostat não está instalado (pacote sysstat)."}
    except subprocess.TimeoutExpired:
        return {"error": "iostat excedeu o tempo limite."}

    try:
        data = json.loads(out)
        host = data["sysstat"]["hosts"][0]
        sample = host["statistics"][1]
        disks = sample.get("disk", [])
    except (KeyError, IndexError, json.JSONDecodeError) as e:
        return {"error": f"Falha ao interpretar saída do iostat: {e}"}

    remote = logical_disk.remote_block_devices()
    selected = set(devices) if devices else None
    physical_rows = []
    for d in disks:
        name = d.get("disk_device")
        if name in remote:
            continue
        if not _is_physical(name):
            continue
        if selected is not None and name not in selected:
            continue
        r_s = d.get("r/s", 0.0)
        w_s = d.get("w/s", 0.0)
        r_await = d.get("r_await", 0.0)
        w_await = d.get("w_await", 0.0)
        total_iops = r_s + w_s
        # Latência média ponderada por IOPS — quando há tráfego mix
        if total_iops > 0:
            avg_latency = (r_await * r_s + w_await * w_s) / total_iops
        else:
            avg_latency = 0.0
        physical_rows.append({
            "device": name,
            "r_s": r_s,
            "w_s": w_s,
            "total_iops": total_iops,
            "rkB_s": d.get("rkB/s", 0.0),
            "wkB_s": d.get("wkB/s", 0.0),
            "r_await": r_await,
            "w_await": w_await,
            "avg_latency": round(avg_latency, 2),
            "aqu_sz": d.get("aqu-sz", 0.0),
            "util": d.get("util", 0.0),
        })

    physical_rows.sort(key=lambda r: r["util"], reverse=True)
    rows = physical_rows

    usage = []
    remote_paths = {f"/dev/{d}" for d in remote}
    try:
        df = subprocess.check_output(
            ["df", "-PT", "-x", "tmpfs", "-x", "devtmpfs", "-x", "squashfs"],
            timeout=5,
        ).decode()
        for line in df.strip().splitlines()[1:]:
            parts = line.split()
            if len(parts) < 7:
                continue
            if parts[0] in remote_paths:
                continue
            usage.append({
                "filesystem": parts[0],
                "type": parts[1],
                "size_kb": int(parts[2]),
                "used_kb": int(parts[3]),
                "avail_kb": int(parts[4]),
                "use_pct": parts[5],
                "mount": parts[6],
            })
    except Exception:
        usage = []

    all_devices = [d.get("disk_device", "?") for d in disks
                   if d.get("disk_device") not in remote
                   and _is_physical(d.get("disk_device"))]
    return {
        "hostname": host.get("nodename", ""),
        "interval": interval,
        "devices": rows,
        "physical_devices": physical_rows,
        "filesystems": usage,
        "all_devices": all_devices,
        "selected_devices": sorted(selected) if selected else [],
    }
