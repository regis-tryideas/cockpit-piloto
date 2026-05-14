import shutil
import subprocess
from pathlib import Path

ARCSTATS_PATH = Path("/proc/spl/kstat/zfs/arcstats")
ARC_MAX_PATH = Path("/sys/module/zfs/parameters/zfs_arc_max")
ARC_MIN_PATH = Path("/sys/module/zfs/parameters/zfs_arc_min")
KERNEL_PARAM_DIR = Path("/sys/module/zfs/parameters")
MODPROBE_CONF = Path("/etc/modprobe.d/zfs.conf")
RAM_SAFETY_MAX_PCT = 0.90  # nunca passar de 90% da RAM total

# Perfis de otimização (key -> (recommended_value, descrição curta))
KERNEL_PROFILE_SSD = {
    "zfs_txg_timeout": ("10",
        "Frequência (s) que o ZFS faz flush de transactions. "
        "Aumentar agrupa mais writes — bom para SSDs com queue depth alta."),
    "zfs_dirty_data_max": (str(32 * 1024**3),
        "Buffer máximo (bytes) de escritas em vôo antes de bloquear apps. "
        "32 GiB ajuda em picos de write — escolha menor se total RAM < 64 GiB."),
}

POOL_PROFILE_SSD = {
    "autotrim": ("on",
        "TRIM contínuo automático. Mantém SSDs performando — sem isso, "
        "performance degrada com o tempo conforme células ficam 'sujas'."),
}

POOL_PROFILE_NVME = dict(POOL_PROFILE_SSD)

# Propriedades base aplicáveis a qualquer dataset que sirva storage de VM
DATASET_PROFILE_BASE = {
    "compression": ("lz4",
        "Compressão rápida com ratio decente. Praticamente grátis em CPU moderna."),
    "atime": ("off",
        "Desativa atualização de access time — reduz writes desnecessários."),
    "xattr": ("sa",
        "Armazena atributos extras inline no dnode em vez de objetos "
        "separados. Mais rápido e usa menos IOPS."),
    "sync": ("standard",
        "Honra fsync da aplicação — seguro. 'always' é forte demais "
        "(degrada writes); 'disabled' é inseguro (perde dados em queda)."),
}

DATASET_PROFILE_VMS = {
    **DATASET_PROFILE_BASE,
    "recordsize": ("16K",
        "Tamanho de bloco. 16K é bom para VMs (compromisso entre random IO "
        "e throughput sequential)."),
    "primarycache": ("all",
        "ARC cacheia dados E metadados. Default ótimo para VMs."),
}

DATASET_PROFILE_VM_DB = {
    **DATASET_PROFILE_BASE,
    "recordsize": ("8K",
        "Bancos relacionais (PostgreSQL/MySQL) usam blocos de 8K. "
        "Match exato evita write amplification."),
    "primarycache": ("metadata",
        "Para DBs que já cacheiam internamente (shared_buffers), "
        "cachear só metadata no ZFS evita duplo-cache."),
}


def kernel_param(key: str) -> str | None:
    p = KERNEL_PARAM_DIR / key
    if not p.exists():
        return None
    try:
        return p.read_text().strip()
    except OSError:
        return None


def kernel_params(keys: list[str] | None = None) -> dict:
    if keys is None:
        keys = list(KERNEL_PROFILE_SSD.keys())
    return {k: kernel_param(k) for k in keys}


def set_kernel_param(key: str, value: str, persist: bool = True) -> tuple[bool, str]:
    """Aplica em /sys/module/zfs/parameters/<key> + persiste em modprobe.d."""
    p = KERNEL_PARAM_DIR / key
    if not p.exists():
        return False, f"parâmetro {key} não existe (módulo zfs carregado?)"
    try:
        p.write_text(str(value))
    except OSError as e:
        return False, f"runtime falhou: {e}"
    if persist:
        ok, msg = _persist_module_options({key: str(value)})
        if not ok:
            return False, f"runtime OK, persistência falhou: {msg}"
        return True, f"aplicado e persistido em {MODPROBE_CONF}"
    return True, "aplicado em runtime (não persistido)"


def _persist_module_options(updates: dict) -> tuple[bool, str]:
    """Adiciona/substitui linhas 'options zfs <k>=<v>' em zfs.conf."""
    new_lines = {}
    for k, v in updates.items():
        new_lines[k] = f"options zfs {k}={v}"
    try:
        existing = []
        if MODPROBE_CONF.exists():
            existing = MODPROBE_CONF.read_text().splitlines()
        out_lines = []
        handled = set()
        for line in existing:
            s = line.strip()
            if not s or s.startswith("#"):
                out_lines.append(line)
                continue
            if s.startswith("options zfs") and "=" in s:
                # tenta detectar qual key tem
                matched_key = None
                for k in updates:
                    if f"{k}=" in s:
                        matched_key = k
                        break
                if matched_key:
                    out_lines.append(new_lines[matched_key])
                    handled.add(matched_key)
                    continue
            out_lines.append(line)
        for k in updates:
            if k not in handled:
                out_lines.append(new_lines[k])
        content = "\n".join(out_lines).rstrip() + "\n"
        MODPROBE_CONF.parent.mkdir(parents=True, exist_ok=True)
        tmp = str(MODPROBE_CONF) + ".cockpit.tmp"
        with open(tmp, "w") as f:
            f.write(content)
        import os as _os
        _os.chmod(tmp, 0o644)
        _os.replace(tmp, str(MODPROBE_CONF))
        return True, str(MODPROBE_CONF)
    except OSError as e:
        return False, str(e)


def pool_properties(name: str, keys: list[str] | None = None) -> dict:
    """zpool get -H -o property,value <props|all> <pool>"""
    if keys is None:
        keys = list(POOL_PROFILE_SSD.keys()) + ["ashift", "size", "capacity", "health"]
    props_arg = ",".join(keys)
    out = _run(["zpool", "get", "-H", "-o", "property,value", props_arg, name])
    if not out:
        return {}
    result = {}
    for line in out.strip().splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            result[parts[0]] = parts[1]
    return result


def set_pool_property(name: str, key: str, value: str) -> tuple[bool, str]:
    try:
        out = subprocess.check_output(
            ["zpool", "set", f"{key}={value}", name],
            stderr=subprocess.STDOUT, timeout=15,
        )
        return True, (out.decode(errors="replace").strip() or f"{key} = {value}")
    except subprocess.CalledProcessError as e:
        return False, e.output.decode(errors="replace").strip() or f"exit={e.returncode}"
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return False, str(e)


def dataset_properties(name: str, keys: list[str] | None = None) -> dict:
    """zfs get -H -o property,value <props> <dataset>"""
    if keys is None:
        keys = list(DATASET_PROFILE_VMS.keys()) + ["used", "available", "type"]
    props_arg = ",".join(keys)
    out = _run(["zfs", "get", "-H", "-o", "property,value", props_arg, name])
    if not out:
        return {}
    result = {}
    for line in out.strip().splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            result[parts[0]] = parts[1]
    return result


def set_dataset_property(name: str, key: str, value: str) -> tuple[bool, str]:
    try:
        out = subprocess.check_output(
            ["zfs", "set", f"{key}={value}", name],
            stderr=subprocess.STDOUT, timeout=15,
        )
        return True, (out.decode(errors="replace").strip() or f"{key} = {value}")
    except subprocess.CalledProcessError as e:
        return False, e.output.decode(errors="replace").strip() or f"exit={e.returncode}"
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return False, str(e)


def create_dataset(name: str, properties: dict | None = None) -> tuple[bool, str]:
    """zfs create <name> + zfs set props"""
    try:
        subprocess.check_output(
            ["zfs", "create", name],
            stderr=subprocess.STDOUT, timeout=20,
        )
    except subprocess.CalledProcessError as e:
        return False, f"create falhou: {e.output.decode(errors='replace').strip()}"
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return False, str(e)
    results = []
    for k, v in (properties or {}).items():
        ok, msg = set_dataset_property(name, k, v)
        results.append(f"{k}={v}: {'ok' if ok else msg}")
    return True, f"dataset {name} criado · " + " · ".join(results)


def apply_profile_kernel_ssd() -> dict:
    """Aplica perfil SSD nos params do módulo."""
    results = {}
    for key, (val, _desc) in KERNEL_PROFILE_SSD.items():
        ok, msg = set_kernel_param(key, val)
        results[key] = {"ok": ok, "msg": msg, "value": val}
    return results


def apply_profile_pool(name: str, profile_name: str = "ssd") -> dict:
    profile = POOL_PROFILE_NVME if profile_name == "nvme" else POOL_PROFILE_SSD
    results = {}
    for key, (val, _) in profile.items():
        ok, msg = set_pool_property(name, key, val)
        results[key] = {"ok": ok, "msg": msg, "value": val}
    return results


def apply_profile_dataset(name: str, profile_name: str = "vms") -> dict:
    profile = DATASET_PROFILE_VM_DB if profile_name == "vm_db" else DATASET_PROFILE_VMS
    results = {}
    for key, (val, _) in profile.items():
        ok, msg = set_dataset_property(name, key, val)
        results[key] = {"ok": ok, "msg": msg, "value": val}
    return results


def evaluate_dataset_profile(props: dict, profile_name: str = "vms") -> dict:
    """Compara props atuais com perfil. Retorna lista de mismatches."""
    profile = DATASET_PROFILE_VM_DB if profile_name == "vm_db" else DATASET_PROFILE_VMS
    mismatches = []
    for k, (expected, desc) in profile.items():
        cur = props.get(k)
        # 'recordsize' aparece como '16K' ou '16384' dependendo da versão
        if cur and k == "recordsize":
            cur_norm = cur.upper().rstrip("B")
        else:
            cur_norm = cur
        if cur and cur_norm != expected:
            mismatches.append({"key": k, "current": cur, "expected": expected, "desc": desc})
    return {
        "compliant": len(mismatches) == 0,
        "mismatches": mismatches,
        "ok_count": len(profile) - len(mismatches),
        "total": len(profile),
    }


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

    # Enriquece cada pool com props (autotrim, ashift...) e compliance
    for p in pool_list:
        props = pool_properties(p["name"])
        p["props"] = props
        p["autotrim"] = props.get("autotrim", "off")
        # Compliance simples: só checa autotrim
        p["needs_tuning"] = (props.get("autotrim", "off") != "on")
    # Datasets enriquecidos com props e compliance heuristica
    ds_list = datasets()
    for d in ds_list:
        props = dataset_properties(d["name"])
        d["props"] = props
        # Heurística: se nome tem 'db', sugere perfil vm_db; senão vms
        suggested = "vm_db" if "db" in d["name"].lower() else "vms"
        d["suggested_profile"] = suggested
        d["compliance"] = evaluate_dataset_profile(props, suggested)

    # Kernel tuners atuais
    kparams = kernel_params()
    kernel_status = {}
    for k, (rec, desc) in KERNEL_PROFILE_SSD.items():
        cur = kparams.get(k)
        # zfs_dirty_data_max é número grande — compara como int
        try:
            matches = (int(cur or 0) == int(rec))
        except (TypeError, ValueError):
            matches = (cur == rec)
        kernel_status[k] = {
            "current": cur,
            "recommended": rec,
            "desc": desc,
            "matches": matches,
        }

    return {
        "available": state,
        "interval": interval,
        "pools": pool_list,
        "statuses": statuses,
        "scrubs": scrubs,
        "datasets": ds_list,
        "arc": arc_stats(),
        "arc_tunable": arc_tunable_info(),
        "io": pool_io(interval),
        "vdev_io": vdev_io(interval),
        "latency": pool_latency(interval),
        "snapshots": snapshot_summary(),
        "kernel_tuners": kernel_status,
        "dataset_profile_vms": {k: v for k, (v, _) in DATASET_PROFILE_VMS.items()},
        "dataset_profile_vm_db": {k: v for k, (v, _) in DATASET_PROFILE_VM_DB.items()},
    }


def arc_max_runtime_bytes() -> int | None:
    raw = _read_sysfs(ARC_MAX_PATH)
    try:
        return int(raw) if raw is not None else None
    except (ValueError, TypeError):
        return None


def arc_min_runtime_bytes() -> int | None:
    raw = _read_sysfs(ARC_MIN_PATH)
    try:
        return int(raw) if raw is not None else None
    except (ValueError, TypeError):
        return None


def _read_sysfs(p: Path) -> str | None:
    try:
        return p.read_text().strip()
    except OSError:
        return None


def total_ram_bytes() -> int:
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    parts = line.split()
                    return int(parts[1]) * 1024
    except OSError:
        pass
    return 0


def arc_tunable_info() -> dict:
    """Estado atual do ARC max, valor persistido e limites de segurança."""
    runtime = arc_max_runtime_bytes()
    arc_min = arc_min_runtime_bytes()
    total_ram = total_ram_bytes()
    persisted = _read_persisted_arc_max()
    return {
        "supported": ARC_MAX_PATH.exists(),
        "runtime_bytes": runtime,
        "runtime_gib": round(runtime / 1024**3, 2) if runtime else 0.0,
        "is_auto": runtime == 0,
        "min_bytes": arc_min,
        "min_gib": round(arc_min / 1024**3, 2) if arc_min else 0.0,
        "total_ram_gib": round(total_ram / 1024**3, 2),
        "max_safe_gib": round(total_ram * RAM_SAFETY_MAX_PCT / 1024**3, 2),
        "persisted_bytes": persisted,
        "persisted_gib": round(persisted / 1024**3, 2) if persisted else None,
        "modprobe_conf": str(MODPROBE_CONF),
    }


def _read_persisted_arc_max() -> int | None:
    """Lê /etc/modprobe.d/zfs.conf procurando 'options zfs zfs_arc_max=...'."""
    if not MODPROBE_CONF.exists():
        return None
    try:
        for line in MODPROBE_CONF.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("options zfs") and "zfs_arc_max" in line:
                for token in line.split():
                    if token.startswith("zfs_arc_max="):
                        try:
                            return int(token.split("=", 1)[1])
                        except ValueError:
                            return None
    except OSError:
        return None
    return None


def set_arc_max(gib: float, persist: bool = True) -> tuple[bool, str]:
    """Define zfs_arc_max em bytes. Retorna (sucesso, mensagem).

    - gib=0 reseta para automático (kernel calcula sozinho).
    - Limite máximo de segurança: 90% da RAM total.
    """
    if not ARC_MAX_PATH.exists():
        return False, "Módulo ZFS não está carregado (parameters/zfs_arc_max ausente)."

    info = arc_tunable_info()

    if gib < 0 or gib > 4096:
        return False, "Valor fora do intervalo aceito."

    if gib == 0:
        target_bytes = 0  # automático
    else:
        if gib < 0.5:
            return False, "Mínimo aceitável: 0.5 GiB."
        if gib > info["max_safe_gib"]:
            return False, (
                f"Valor excede o limite de segurança ({info['max_safe_gib']:.1f} GiB = "
                f"{int(RAM_SAFETY_MAX_PCT*100)}% da RAM total {info['total_ram_gib']:.1f} GiB)."
            )
        target_bytes = int(gib * 1024**3)

    try:
        ARC_MAX_PATH.write_text(str(target_bytes))
    except OSError as e:
        return False, f"Falha ao aplicar em runtime: {e}"

    persisted_msg = ""
    if persist:
        ok, persisted_msg = _persist_arc_max(target_bytes)
        if not ok:
            return False, f"Aplicado em runtime mas falhou ao persistir: {persisted_msg}"

    if target_bytes == 0:
        return True, "ARC max resetado para automático (kernel calcula). " + persisted_msg
    return True, (
        f"ARC max configurado para {gib} GiB em runtime. {persisted_msg}"
    )


def _persist_arc_max(target_bytes: int) -> tuple[bool, str]:
    """Atualiza /etc/modprobe.d/zfs.conf substituindo a linha de zfs_arc_max."""
    new_line = (
        f"options zfs zfs_arc_max={target_bytes}"
        if target_bytes > 0 else
        "# zfs_arc_max removido — kernel calcula automaticamente"
    )
    try:
        if MODPROBE_CONF.exists():
            existing = MODPROBE_CONF.read_text().splitlines()
            replaced = False
            out_lines = []
            for line in existing:
                if line.strip().startswith("options zfs") and "zfs_arc_max" in line:
                    if target_bytes > 0:
                        out_lines.append(new_line)
                    # se reset (target=0), apaga linha existente
                    replaced = True
                else:
                    out_lines.append(line)
            if not replaced and target_bytes > 0:
                out_lines.append(new_line)
            MODPROBE_CONF.write_text("\n".join(out_lines).rstrip() + "\n")
        else:
            if target_bytes > 0:
                MODPROBE_CONF.write_text(new_line + "\n")
        return True, f"persistido em {MODPROBE_CONF}."
    except OSError as e:
        return False, str(e)


def _availability_message(state: dict) -> str:
    missing = []
    if not state["kmod"]:
        missing.append("módulo kernel zfs (instale zfs-dkms ou zfs-modules)")
    if not state["zpool"]:
        missing.append("comando zpool (pacote zfsutils-linux)")
    if not state["zfs"]:
        missing.append("comando zfs (pacote zfsutils-linux)")
    return "ZFS indisponível: " + ", ".join(missing)
