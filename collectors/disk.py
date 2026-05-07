import json
import subprocess

from . import logical_disk

PHYSICAL_PREFIXES = ("nvme", "sd", "vd", "hd", "xvd")
LOGICAL_PREFIXES = ("md", "dm-")


def _classify(name: str) -> str:
    """Retorna 'physical', 'logical' ou 'other'."""
    if name.startswith(PHYSICAL_PREFIXES):
        return "physical"
    if name.startswith(LOGICAL_PREFIXES):
        return "logical"
    return "other"


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
    logical_rows = []
    other_rows = []
    for d in disks:
        name = d.get("disk_device")
        if name in remote:
            continue
        if selected is not None and name not in selected:
            continue
        family = _classify(name)
        row = {
            "device": name or "?",
            "family": family,
            "r_s": d.get("r/s", 0.0),
            "w_s": d.get("w/s", 0.0),
            "rkB_s": d.get("rkB/s", 0.0),
            "wkB_s": d.get("wkB/s", 0.0),
            "r_await": d.get("r_await", 0.0),
            "w_await": d.get("w_await", 0.0),
            "aqu_sz": d.get("aqu-sz", 0.0),
            "util": d.get("util", 0.0),
        }
        if family == "physical":
            physical_rows.append(row)
        elif family == "logical":
            logical_rows.append(row)
        else:
            other_rows.append(row)

    rows = physical_rows + logical_rows + other_rows
    physical_rows.sort(key=lambda r: r["util"], reverse=True)
    logical_rows.sort(key=lambda r: r["util"], reverse=True)
    other_rows.sort(key=lambda r: r["util"], reverse=True)

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
                   if d.get("disk_device") not in remote]
    return {
        "hostname": host.get("nodename", ""),
        "interval": interval,
        "devices": rows,
        "physical_devices": physical_rows,
        "logical_devices": logical_rows,
        "other_devices": other_rows,
        "filesystems": usage,
        "all_devices": all_devices,
        "selected_devices": sorted(selected) if selected else [],
    }
