import json
import os
import subprocess
from pathlib import Path

REMOTE_TRANSPORTS = {"iscsi", "fc", "fcoe"}


def _run_lsblk() -> list[dict]:
    try:
        out = subprocess.check_output(
            ["lsblk", "-J", "-o",
             "NAME,TRAN,TYPE,SIZE,FSTYPE,MOUNTPOINT,VENDOR,MODEL,WWN,SERIAL"],
            stderr=subprocess.STDOUT,
            timeout=5,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    return data.get("blockdevices", [])


def _flatten(nodes: list[dict], parent: dict | None = None) -> list[dict]:
    out = []
    for n in nodes:
        n = dict(n)
        n["_parent"] = parent["name"] if parent else None
        out.append(n)
        children = n.get("children") or []
        if children:
            out.extend(_flatten(children, n))
    return out


def remote_block_devices() -> set[str]:
    """Conjunto de devices (e partições filhas) que vieram de transport remoto."""
    devs = set()
    for top in _run_lsblk():
        if top.get("tran") in REMOTE_TRANSPORTS:
            devs.add(top["name"])
            for child in top.get("children") or []:
                devs.add(child["name"])
    return devs


def _iscsi_session_metadata() -> dict[str, dict]:
    """Mapeia nome de device -> metadados da sessão iSCSI (IQN, portal, ...).

    Lê /sys/class/iscsi_session/sessionN/ e correlaciona com os blocos abaixo.
    Funciona sem iscsiadm (apenas leitura de sysfs).
    """
    base = Path("/sys/class/iscsi_session")
    if not base.exists():
        return {}

    result: dict[str, dict] = {}
    for sess in base.iterdir():
        info = {"session": sess.name}
        for attr in (
            "targetname", "tpgt", "state", "persistent_address",
            "persistent_port",
        ):
            f = sess / attr
            if f.exists():
                try:
                    info[attr] = f.read_text().strip()
                except OSError:
                    pass
        connection_dir = sess / "device"
        try:
            real = os.path.realpath(connection_dir)
            for entry in Path(real).rglob("block/*"):
                dev_name = entry.name
                if entry.parent.name == "block" and (entry / "..").exists():
                    result[dev_name] = info
        except OSError:
            continue
    return result


def _iostat_for(devices: set[str], interval: int) -> dict[str, dict]:
    if not devices:
        return {}
    try:
        out = subprocess.check_output(
            ["iostat", "-dxk", "-o", "JSON", str(interval), "2"],
            stderr=subprocess.STDOUT,
            timeout=interval + 5,
        )
        data = json.loads(out)
        sample = data["sysstat"]["hosts"][0]["statistics"][1]
        rows = sample.get("disk", [])
    except Exception:
        return {}
    result = {}
    for d in rows:
        name = d.get("disk_device")
        if name in devices:
            result[name] = {
                "r_s": d.get("r/s", 0.0),
                "w_s": d.get("w/s", 0.0),
                "rkB_s": d.get("rkB/s", 0.0),
                "wkB_s": d.get("wkB/s", 0.0),
                "r_await": d.get("r_await", 0.0),
                "w_await": d.get("w_await", 0.0),
                "aqu_sz": d.get("aqu-sz", 0.0),
                "util": d.get("util", 0.0),
            }
    return result


def collect(interval: int = 1) -> dict:
    nodes = _flatten(_run_lsblk())
    iscsi_meta = _iscsi_session_metadata()

    rows = []
    physical_disks = set()
    for n in nodes:
        if n.get("type") != "disk":
            continue
        tran = n.get("tran")
        if tran not in REMOTE_TRANSPORTS:
            continue
        physical_disks.add(n["name"])
        rows.append({
            "device": n["name"],
            "transport": tran,
            "size": n.get("size"),
            "vendor": (n.get("vendor") or "").strip() or None,
            "model": (n.get("model") or "").strip() or None,
            "wwn": n.get("wwn"),
            "serial": n.get("serial"),
            "iscsi": iscsi_meta.get(n["name"]),
            "partitions": [],
        })

    for n in nodes:
        if n.get("_parent") and n["_parent"] in physical_disks:
            for parent_row in rows:
                if parent_row["device"] == n["_parent"]:
                    parent_row["partitions"].append({
                        "name": n["name"],
                        "type": n.get("type"),
                        "size": n.get("size"),
                        "fstype": n.get("fstype"),
                        "mountpoint": n.get("mountpoint"),
                    })
                    break

    io = _iostat_for(physical_disks, interval) if physical_disks else {}
    for r in rows:
        r["io"] = io.get(r["device"])

    rows.sort(key=lambda r: r["device"])
    return {
        "interval": interval,
        "devices": rows,
        "iscsi_available": Path("/sys/class/iscsi_session").exists(),
    }
