import json
import re
import shutil
import subprocess
import time
from pathlib import Path

_CACHE = {"data": None, "ts": 0}
_CACHE_TTL = 60

# Mapeamento driver kernel (proc_name em /sys/class/scsi_host) → tipo smartctl
PROC_NAME_TO_SMART_TYPE = {
    "megaraid_sas": "megaraid",
    "megaraid": "megaraid",
    "mpt3sas": "megaraid",
    "cciss": "cciss",
    "hpsa": "cciss",
    "3w-9xxx": "3ware",
    "3w-sas": "3ware",
    "3w-xxxx": "3ware",
    "arcmsr": "areca",
    "aacraid": "aacraid",
}
# Quantos índices a tentar antes de desistir (cobre LSI 24-port + folga)
MAX_CONTROLLER_INDEX = 32
# Falhas consecutivas que indicam fim da numeração
CONTROLLER_FAIL_STREAK = 3


def has_smartctl() -> bool:
    return shutil.which("smartctl") is not None


def _device_label(d: dict) -> str:
    """Nome amigável do device.

    /dev/sda [SAT]                          -> sda
    /dev/bus/0 [megaraid_disk_00] [SAT]    -> megaraid_disk_00
    /dev/twa0 [3ware_disk_0]                -> 3ware_disk_0
    /dev/nvme0                              -> nvme0
    """
    name = d.get("name", "")
    info = d.get("info_name") or name
    m = re.search(r"\[([^\]]+_disk_\d+)\]", info)
    if m:
        return m.group(1)
    if name.startswith("/dev/"):
        return name[5:].replace("/", "_")
    return name


def _is_behind_controller(d: dict) -> bool:
    """True se o disco está atrás de um controlador HW RAID."""
    t = d.get("type") or ""
    return any(t.startswith(p) for p in (
        "megaraid", "cciss", "areca", "3ware", "aacraid", "hpsa", "hpt"
    ))


def _run_json(cmd: list[str], timeout: int = 8) -> dict | None:
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=timeout, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    out = proc.stdout
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


def scan_devices() -> list[dict]:
    """smartctl --scan-open -j: enumera todos os devices com SMART acessível.

    Inclui automaticamente discos atrás de controladoras HW (megaraid, cciss,
    3ware, areca, hpsa, etc.) reportando o tipo correto a usar com -d.
    """
    data = _run_json(["smartctl", "--scan-open", "-j"], timeout=15)
    if not data:
        return []
    return data.get("devices", [])


def detect_raid_controllers() -> list[dict]:
    """Detecta controladoras HW RAID via /sys/class/scsi_host/*/proc_name.

    Retorna lista de {host, proc_name, smart_type, base_paths} pra cada
    controladora encontrada — usada pra enumeração manual via -d <type>,N
    quando --scan-open não pega tudo.
    """
    found = []
    base = Path("/sys/class/scsi_host")
    if not base.exists():
        return []

    seen_types = set()
    for host_dir in sorted(base.iterdir()):
        proc_file = host_dir / "proc_name"
        if not proc_file.exists():
            continue
        try:
            proc_name = proc_file.read_text().strip().lower()
        except OSError:
            continue
        smart_type = PROC_NAME_TO_SMART_TYPE.get(proc_name)
        if not smart_type:
            continue
        if smart_type in seen_types:
            continue  # evita repetir enumeração quando há vários hosts do mesmo driver
        seen_types.add(smart_type)

        # Caminhos típicos onde smartctl recebe o -d <type>,N:
        #  - megaraid: /dev/bus/0, /dev/bus/1, ... ou /dev/sda
        #  - cciss/hpsa: /dev/sda (controlador expõe um único nó)
        #  - 3ware: /dev/twa0 ou /dev/sda
        #  - areca: /dev/sg2
        bases = _candidate_base_paths(smart_type)
        found.append({
            "host": host_dir.name,
            "proc_name": proc_name,
            "smart_type": smart_type,
            "base_paths": bases,
        })
    return found


def _candidate_base_paths(smart_type: str) -> list[str]:
    """Caminhos prováveis pra usar com -d <smart_type>,N."""
    paths = []
    if smart_type == "megaraid":
        for n in range(0, 8):
            p = f"/dev/bus/{n}"
            if Path(p).exists():
                paths.append(p)
    if smart_type == "areca":
        for sg in Path("/dev").glob("sg*"):
            paths.append(str(sg))
    if smart_type == "3ware":
        for n in range(0, 4):
            p = f"/dev/twa{n}"
            if Path(p).exists():
                paths.append(p)
            p2 = f"/dev/twe{n}"
            if Path(p2).exists():
                paths.append(p2)
    # cciss/hpsa e fallback geral: /dev/sda costuma funcionar
    if not paths or smart_type in ("cciss", "aacraid"):
        for letter in "abcdefghijklmnop":
            p = f"/dev/sd{letter}"
            if Path(p).exists():
                paths.append(p)
                break  # 1 base é suficiente; o índice -d N varia
    return paths or ["/dev/sda"]


def enumerate_controller_disks(controller: dict) -> list[dict]:
    """Para cada base_path do controller, tenta -d <type>,0..N até falhas
    consecutivas indicarem fim da numeração."""
    smart_type = controller["smart_type"]
    out = []
    seen_serials = set()
    for base_path in controller["base_paths"]:
        fails = 0
        for idx in range(MAX_CONTROLLER_INDEX):
            dtype = f"{smart_type},{idx}"
            descriptor = {
                "name": base_path,
                "type": dtype,
                "info_name": f"{base_path} [{smart_type}_disk_{idx:02d}]",
            }
            r = query_disk(descriptor)
            has_data = bool(r.get("model"))
            if has_data:
                # Deduplica por serial (caso o mesmo disco apareça em paths
                # diferentes do mesmo controller)
                sn = r.get("serial")
                if sn and sn in seen_serials:
                    fails += 1
                else:
                    if sn:
                        seen_serials.add(sn)
                    out.append(r)
                    fails = 0
            else:
                fails += 1
            if fails >= CONTROLLER_FAIL_STREAK:
                break
    return out


def query_disk(dev_or_descriptor, dtype: str | None = None) -> dict:
    """Coleta SMART de um device.

    Aceita:
    - string nome simples: 'sda' (assume /dev/sda, tipo auto)
    - string com path: '/dev/sda' (tipo auto)
    - dict com {name, type, info_name} vindo de scan_devices()
    """
    if isinstance(dev_or_descriptor, dict):
        path = dev_or_descriptor.get("name", "")
        dtype = dev_or_descriptor.get("type") or dtype
        label = _device_label(dev_or_descriptor)
        behind_controller = _is_behind_controller(dev_or_descriptor)
        protocol = dev_or_descriptor.get("protocol")
    else:
        name = str(dev_or_descriptor)
        path = name if name.startswith("/dev/") else f"/dev/{name}"
        label = name.split("/")[-1]
        behind_controller = False
        protocol = None

    cmd = ["smartctl", "-aj", path]
    if dtype:
        cmd.extend(["-d", dtype])

    data = _run_json(cmd, timeout=10)
    if not data:
        return {"device": label, "path": path, "type": dtype,
                "behind_controller": behind_controller,
                "error": "smartctl não retornou JSON"}

    sm = data.get("smartctl", {})
    exit_status = sm.get("exit_status")
    messages = sm.get("messages") or []
    # smartctl exit code é um bitfield. Bit 0 (=1) = "Command line did not parse" /
    # "device open failed". Quando isso acontece, normalmente não há dados úteis.
    if exit_status is not None and exit_status & 0x03:
        err_msgs = [m.get("string", "") for m in messages
                    if m.get("severity") == "error"]
        return {
            "device": label, "path": path, "type": dtype,
            "behind_controller": behind_controller,
            "error": "; ".join(err_msgs) or f"smartctl exit={exit_status}",
        }

    is_nvme = "nvme_smart_health_information_log" in data
    smart_status = data.get("smart_status") or {}

    result = {
        "device": label,
        "path": path,
        "type": dtype,
        "protocol": protocol,
        "behind_controller": behind_controller,
        "model": data.get("model_name") or (data.get("device") or {}).get("model_name"),
        "serial": data.get("serial_number"),
        "firmware": data.get("firmware_version"),
        "capacity_b": (data.get("user_capacity") or {}).get("bytes"),
        "rotation_rate": data.get("rotation_rate"),
        "is_ssd": data.get("rotation_rate") == 0,
        "is_nvme": is_nvme,
        "passed": smart_status.get("passed"),
        "temperature_c": (data.get("temperature") or {}).get("current"),
        "power_on_hours": None,
        "tbw_b": None,
        "tb_read_b": None,
        "errors": {},
        "warnings": [],
    }

    if is_nvme:
        h = data["nvme_smart_health_information_log"]
        result["power_on_hours"] = h.get("power_on_hours")
        # data_units_written: 1 unit = 1000 × 512 bytes
        duw = h.get("data_units_written")
        dur = h.get("data_units_read")
        if duw is not None:
            result["tbw_b"] = duw * 512_000
        if dur is not None:
            result["tb_read_b"] = dur * 512_000
        result["power_cycles"] = h.get("power_cycles")
        result["unsafe_shutdowns"] = h.get("unsafe_shutdowns")
        result["wear_pct_used"] = h.get("percentage_used")
        result["available_spare_pct"] = h.get("available_spare")
        result["available_spare_threshold_pct"] = h.get("available_spare_threshold")
        result["errors"] = {
            "media_errors": h.get("media_errors", 0),
            "num_err_log_entries": h.get("num_err_log_entries", 0),
            "critical_warning": h.get("critical_warning", 0),
            "warning_temp_time_min": h.get("warning_temp_time", 0),
            "critical_comp_temp_time_min": h.get("critical_comp_temp_time", 0),
        }
        if h.get("media_errors", 0) > 0:
            result["warnings"].append("media_errors > 0 — falha de mídia detectada")
        if h.get("critical_warning", 0) != 0:
            result["warnings"].append("critical_warning != 0 — verificar bits NVMe")
        if h.get("percentage_used", 0) >= 80:
            result["warnings"].append(f"wear-out em {h['percentage_used']}% (>=80%)")
        if h.get("available_spare", 100) < h.get("available_spare_threshold", 10):
            result["warnings"].append("available_spare abaixo do threshold")

    else:
        # ATA / SATA
        attrs = (data.get("ata_smart_attributes") or {}).get("table", [])
        by_id = {a["id"]: a for a in attrs}
        by_name = {a.get("name"): a for a in attrs}

        def raw_id(aid):
            a = by_id.get(aid)
            return a["raw"]["value"] if a and "raw" in a else None

        def raw_name(name):
            a = by_name.get(name)
            return a["raw"]["value"] if a and "raw" in a else None

        result["power_on_hours"] = (
            raw_id(9)
            or (data.get("power_on_time") or {}).get("hours")
        )

        # TBW: tenta vários atributos
        lba_written = raw_id(241) or raw_name("Total_LBAs_Written")
        if lba_written:
            result["tbw_b"] = lba_written * 512
        else:
            hw = raw_name("Host_Writes_32MiB")
            if hw:
                result["tbw_b"] = hw * 32 * 1024 * 1024
            else:
                gib = raw_name("Lifetime_Writes_GiB")
                if gib:
                    result["tbw_b"] = gib * (1024 ** 3)

        lba_read = raw_id(242) or raw_name("Total_LBAs_Read")
        if lba_read:
            result["tb_read_b"] = lba_read * 512

        result["power_cycles"] = raw_id(12)
        result["wear_leveling"] = raw_id(177) or raw_name("Wear_Leveling_Count")

        result["errors"] = {
            "reallocated_sectors":   raw_id(5)   or 0,
            "pending_sectors":       raw_id(197) or 0,
            "offline_uncorrectable": raw_id(198) or 0,
            "udma_crc_errors":       raw_id(199) or 0,
            "reported_uncorrect":    raw_id(187) or 0,
            "command_timeout":       raw_id(188) or 0,
        }
        if (raw_id(5) or 0) > 0:
            result["warnings"].append(
                f"{raw_id(5)} setores realocados — disco pode estar morrendo"
            )
        if (raw_id(197) or 0) > 0:
            result["warnings"].append(
                f"{raw_id(197)} setores pendentes — pré-falha"
            )
        if (raw_id(198) or 0) > 0:
            result["warnings"].append(
                f"{raw_id(198)} setores não-corrigíveis"
            )

        # SMART self-test log: erros recentes
        for a in attrs:
            if a.get("when_failed"):
                result["warnings"].append(
                    f"atributo {a['name']} marcado como FAILING ({a['when_failed']})"
                )

    return result


def _list_physical_devices() -> list[str]:
    """Lista devices físicos (nvme/sd/vd/hd/xvd) sem partições, sem loop/dm/zd."""
    try:
        from . import disk as disk_col
    except Exception:
        return []
    devs = []
    try:
        with open("/proc/diskstats") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 14:
                    continue
                name = parts[2]
                if not disk_col._is_physical(name):
                    continue
                # pula partições (sufixo numérico em sd/vd/hd/xvd, ou pNN em nvme)
                if name.startswith("nvme") and "p" in name:
                    continue
                if name and name[-1].isdigit() and not name.startswith("nvme"):
                    continue
                devs.append(name)
    except OSError:
        pass
    return sorted(set(devs))


def collect(devices: list[str] | None = None) -> dict:
    """Roda smartctl em todos os discos descobertos via --scan-open.

    Captura também discos atrás de controladoras HW (-d megaraid,N etc.).
    Resultados cacheados por 60s.
    """
    if not has_smartctl():
        return {
            "available": False,
            "error": "smartctl não está instalado (instale 'smartmontools').",
            "disks": [],
        }

    now = time.time()
    if (
        devices is None and _CACHE["data"] and (now - _CACHE["ts"] < _CACHE_TTL)
    ):
        return _CACHE["data"]

    rows = []
    controllers_used = []

    if devices is not None:
        for d in devices:
            try:
                rows.append(query_disk(d))
            except Exception as e:
                rows.append({"device": str(d), "error": f"exceção: {e}"})
    else:
        controllers = detect_raid_controllers()
        scanned = scan_devices()
        scan_caught_controller = any(_is_behind_controller(d) for d in scanned)

        # 1) Discos diretos (não-controlados) do --scan-open
        for d in scanned:
            if _is_behind_controller(d):
                continue
            info = d.get("info_name", "")
            # Pula disco virtual exposto pelo controller quando o scan
            # JÁ enxergou os discos físicos atrás (caso típico megaraid)
            if scan_caught_controller and any(s in info for s in (
                "MegaRAID", "PERC", "Smart Array", "AACRAID", "3ware", "Areca",
            )):
                continue
            try:
                rows.append(query_disk(d))
            except Exception as e:
                rows.append({
                    "device": _device_label(d), "path": d.get("name"),
                    "type": d.get("type"),
                    "error": f"exceção: {e}",
                })

        # 2) Discos atrás de controladora — pega via scan-open + enum manual
        if scan_caught_controller:
            for d in scanned:
                if _is_behind_controller(d):
                    try:
                        rows.append(query_disk(d))
                    except Exception as e:
                        rows.append({
                            "device": _device_label(d), "path": d.get("name"),
                            "type": d.get("type"),
                            "error": f"exceção: {e}",
                        })
        else:
            # scan-open não enxergou os discos atrás do controlador —
            # enumera manualmente via -d <type>,0..N
            for ctrl in controllers:
                controllers_used.append(ctrl)
                rows.extend(enumerate_controller_disks(ctrl))

        # 3) Fallback se nada veio: tenta /proc/diskstats com tipo auto
        if not rows and not scanned and not controllers:
            for name in _list_physical_devices():
                try:
                    rows.append(query_disk(name))
                except Exception as e:
                    rows.append({"device": name, "error": f"exceção: {e}"})

    # Filtra: descarta discos sem modelo (lixo de virtio, scan vazio, etc.)
    # mas preserva os FAILED mesmo sem modelo, pra não esconder problema.
    def _keep(r):
        return bool(r.get("model")) or r.get("passed") is False

    raw_count = len(rows)
    rows = [r for r in rows if _keep(r)]
    discarded = raw_count - len(rows)

    summary = {
        "available": True,
        "disks": rows,
        "ok_count": sum(1 for r in rows if r.get("passed") is True),
        "fail_count": sum(1 for r in rows if r.get("passed") is False),
        "unknown_count": sum(1 for r in rows if r.get("passed") is None),
        "controller_count": sum(1 for r in rows if r.get("behind_controller")),
        "controllers_detected": [c["smart_type"] for c in controllers_used],
        "discarded_no_model": discarded,
    }

    if devices is None:
        _CACHE["data"] = summary
        _CACHE["ts"] = now
    return summary
