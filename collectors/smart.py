import json
import shutil
import subprocess
import time

_CACHE = {"data": None, "ts": 0}
_CACHE_TTL = 60


def has_smartctl() -> bool:
    return shutil.which("smartctl") is not None


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


def query_disk(dev: str) -> dict:
    """Coleta SMART de um device. Trata os 3 grupos: NVMe, ATA, falhas."""
    data = _run_json(["smartctl", "-aj", f"/dev/{dev}"], timeout=8)
    if not data:
        return {"device": dev, "error": "smartctl não retornou JSON"}

    sm = data.get("smartctl", {})
    exit_status = sm.get("exit_status")
    messages = sm.get("messages") or []
    # smartctl exit code é um bitfield. Bit 0 (=1) = "Command line did not parse" /
    # "device open failed". Quando isso acontece, normalmente não há dados úteis.
    if exit_status is not None and exit_status & 0x03:
        err_msgs = [m.get("string", "") for m in messages
                    if m.get("severity") == "error"]
        return {
            "device": dev,
            "error": "; ".join(err_msgs) or f"smartctl exit={exit_status}",
        }

    is_nvme = "nvme_smart_health_information_log" in data
    smart_status = data.get("smart_status") or {}

    result = {
        "device": dev,
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
    """Roda smartctl em todos os discos físicos. Resultados cacheados por 60s."""
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

    devs = devices if devices is not None else _list_physical_devices()
    rows = []
    for d in devs:
        try:
            rows.append(query_disk(d))
        except Exception as e:
            rows.append({"device": d, "error": f"exceção inesperada: {e}"})

    summary = {
        "available": True,
        "disks": rows,
        "ok_count": sum(1 for r in rows if r.get("passed") is True),
        "fail_count": sum(1 for r in rows if r.get("passed") is False),
        "unknown_count": sum(1 for r in rows if r.get("passed") is None),
    }

    if devices is None:
        _CACHE["data"] = summary
        _CACHE["ts"] = now
    return summary
