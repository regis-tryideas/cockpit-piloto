"""NVMe over Fabrics (NVMe-oF) management.

Suporta transports: tcp, rdma, fc. O default e mais comum em VMs/PVE é
TCP. Porta padrão NVMe-oF: 4420.

Requer pacote nvme-cli (apt install -y nvme-cli) e módulos kernel:
- nvme, nvme_core
- nvme_tcp (para transport TCP)
- nvme_rdma (RDMA)
- nvme_fc (Fibre Channel)
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

DEFAULT_NVME_PORT = 4420


def has_nvme_cli() -> bool:
    return shutil.which("nvme") is not None


def loaded_modules() -> dict:
    """Verifica módulos kernel relevantes."""
    out = {"nvme_tcp": False, "nvme_rdma": False, "nvme_fc": False, "nvme": False}
    try:
        with open("/proc/modules") as f:
            mods = {line.split()[0] for line in f}
    except OSError:
        return out
    for k in out:
        out[k] = k in mods
    return out


def _run(cmd: list[str], timeout: int = 15) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "command not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def list_subsystems() -> list[dict]:
    """nvme list-subsys -o json"""
    if not has_nvme_cli():
        return []
    rc, out, _ = _run(["nvme", "list-subsys", "-o", "json"], timeout=8)
    if rc != 0:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    # Estrutura pode variar entre versões do nvme-cli; normalizamos
    subs = []
    items = data if isinstance(data, list) else [data]
    for entry in items:
        for sub in entry.get("Subsystems", []) or []:
            paths = []
            for path in sub.get("Paths", []) or []:
                paths.append({
                    "name":    path.get("Name"),
                    "transport": path.get("Transport"),
                    "address":   path.get("Address"),
                    "state":     path.get("State"),
                })
            subs.append({
                "nqn":     sub.get("NQN") or sub.get("Subsystem"),
                "name":    sub.get("Name") or sub.get("Subsystem"),
                "iopolicy": sub.get("IOPolicy"),
                "model":   sub.get("Model"),
                "paths":   paths,
            })
    return subs


def list_devices() -> list[dict]:
    """nvme list -o json — namespaces/discos vistos pelo host."""
    if not has_nvme_cli():
        return []
    rc, out, _ = _run(["nvme", "list", "-o", "json"], timeout=8)
    if rc != 0:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    rows = []
    for dev in data.get("Devices", []) or []:
        rows.append({
            "node":           dev.get("DevicePath") or dev.get("Device"),
            "model":          dev.get("ModelNumber"),
            "serial":         dev.get("SerialNumber"),
            "firmware":       dev.get("Firmware"),
            "namespace":      dev.get("NameSpace") or dev.get("Namespace"),
            "size_b":         dev.get("PhysicalSize") or dev.get("UsedBytes") or 0,
            "transport":      dev.get("Transport"),
            "subsystem_nqn":  dev.get("SubsystemNQN"),
        })
    return rows


def discover(transport: str, addr: str, port: int = DEFAULT_NVME_PORT,
             nqn_filter: str = "") -> tuple[bool, list[dict] | str]:
    """nvme discover -t <transport> -a <addr> -s <port>"""
    if not has_nvme_cli():
        return False, "nvme-cli não instalado"
    rc, out, err = _run([
        "nvme", "discover",
        "-t", transport, "-a", addr, "-s", str(port),
    ], timeout=20)
    if rc != 0:
        return False, (err.strip() or out.strip() or f"exit={rc}")

    # Parse output texto. Cada entry tem: trtype/adrfam/subtype/portid/trsvcid/
    # subnqn/traddr/sectype
    entries = []
    cur = {}
    for line in out.splitlines():
        if line.startswith("==="):
            continue
        if ":" in line:
            k, _, v = line.partition(":")
            cur[k.strip()] = v.strip()
        elif not line.strip() and cur:
            entries.append(cur)
            cur = {}
    if cur:
        entries.append(cur)

    rows = []
    for e in entries:
        nqn = e.get("subnqn") or e.get("subnqn ")
        if not nqn:
            continue
        if nqn_filter and nqn_filter not in nqn:
            continue
        rows.append({
            "trtype":  e.get("trtype"),
            "adrfam":  e.get("adrfam"),
            "subtype": e.get("subtype"),
            "portid":  e.get("portid"),
            "trsvcid": e.get("trsvcid"),
            "nqn":     nqn,
            "traddr":  e.get("traddr"),
        })
    return True, rows


def connect(transport: str, addr: str, port: int, nqn: str,
            host_nqn: str = "") -> tuple[bool, str]:
    """nvme connect -t <transport> -a <addr> -s <port> -n <nqn>"""
    if not has_nvme_cli():
        return False, "nvme-cli não instalado"
    cmd = [
        "nvme", "connect",
        "-t", transport, "-a", addr, "-s", str(port), "-n", nqn,
    ]
    if host_nqn:
        cmd += ["-q", host_nqn]
    rc, out, err = _run(cmd, timeout=30)
    if rc != 0:
        return False, (err.strip() or out.strip() or f"exit={rc}")
    return True, "connect OK"


def disconnect(nqn: str) -> tuple[bool, str]:
    """nvme disconnect -n <nqn>"""
    if not has_nvme_cli():
        return False, "nvme-cli não instalado"
    rc, out, err = _run(["nvme", "disconnect", "-n", nqn], timeout=30)
    if rc != 0:
        return False, (err.strip() or out.strip() or f"exit={rc}")
    return True, "disconnect OK"


def hostnqn() -> str | None:
    """Lê o HostNQN deste initiator (default em /etc/nvme/hostnqn)."""
    p = Path("/etc/nvme/hostnqn")
    if p.exists():
        try:
            return p.read_text().strip()
        except OSError:
            return None
    return None


def collect() -> dict:
    if not has_nvme_cli():
        return {
            "available": False,
            "error": "nvme-cli não instalado. apt install -y nvme-cli",
        }
    mods = loaded_modules()
    subs = list_subsystems()
    devs = list_devices()
    # Filtra dispositivos fabric (transport != 'pcie')
    fabric_devs = [d for d in devs if d.get("transport") and d["transport"] != "pcie"]
    local_devs = [d for d in devs if d.get("transport") == "pcie" or not d.get("transport")]
    return {
        "available": True,
        "modules": mods,
        "subsystems": subs,
        "fabric_devices": fabric_devs,
        "local_devices": local_devs,
        "host_nqn": hostnqn(),
    }
