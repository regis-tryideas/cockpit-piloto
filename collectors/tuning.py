"""Recomendações de tuning para hosts PVE com alta carga de VMs.

Cada recomendação tem severity: 'critical' / 'warn' / 'info' / 'ok'.
"""
from pathlib import Path


def _read_sysctl(key: str) -> str | None:
    path = Path("/proc/sys") / key.replace(".", "/")
    try:
        return path.read_text().strip()
    except OSError:
        return None


def _int(v):
    if v is None:
        return None
    try:
        return int(str(v).split()[0])
    except (ValueError, IndexError):
        return None


def _thp_state() -> str | None:
    p = Path("/sys/kernel/mm/transparent_hugepage/enabled")
    if not p.exists():
        return None
    try:
        txt = p.read_text()
    except OSError:
        return None
    # "[always] madvise never" — colchetes marcam o ativo
    for opt in ("always", "madvise", "never"):
        if f"[{opt}]" in txt:
            return opt
    return None


def _arc_max_b() -> int | None:
    p = Path("/sys/module/zfs/parameters/zfs_arc_max")
    if not p.exists():
        return None
    try:
        return int(p.read_text().strip())
    except (OSError, ValueError):
        return None


def collect(total_ram_b: int = 0, cores: int = 0,
            pve_vms: int = 0, has_zfs: bool = False,
            numa_nodes: int = 1) -> dict:
    """Devolve recomendações pra este host. Os contadores vêm dos outros
    coletores (memória, cpu, proxmox, zfs, numa) e moldam as heurísticas."""
    total_ram_gb = total_ram_b / 1024**3 if total_ram_b else 0
    cores = cores or 1
    recs = []

    def add(key, current, recommended, severity, why):
        matches = (str(current) == str(recommended))
        if matches:
            severity = "ok"
        recs.append({
            "key": key,
            "current": str(current) if current is not None else "—",
            "recommended": str(recommended),
            "severity": severity,
            "why": why,
            "matches": matches,
        })

    # ---- vm.swappiness ----
    sw = _int(_read_sysctl("vm.swappiness"))
    if sw is not None:
        target = 10 if pve_vms > 0 or total_ram_gb >= 32 else 60
        sev = "warn" if total_ram_gb >= 32 and sw > 30 else "info"
        add("vm.swappiness", sw, target, sev,
            "VMs já gerenciam o próprio swap; swappiness alto faz o host "
            "swapar páginas que poderiam servir cache. Em hosts PVE recomenda-"
            "se 10 (ou 1 se você nunca quer tocar swap).")

    # ---- vm.dirty_ratio / dirty_background_ratio ----
    dr = _int(_read_sysctl("vm.dirty_ratio"))
    if dr is not None and total_ram_gb >= 32:
        target_dr = 10
        sev = "warn" if dr >= 20 else "info"
        add("vm.dirty_ratio", dr, target_dr, sev,
            f"Com {total_ram_gb:.0f} GB de RAM, dirty_ratio default (20%) deixa "
            "até 6+ GB sujos antes de bloquear escritas — causa stalls quando "
            "finalmente faz flush. Reduzir pra 10% suaviza o fluxo.")
    dbr = _int(_read_sysctl("vm.dirty_background_ratio"))
    if dbr is not None and total_ram_gb >= 32:
        target_dbr = 5
        sev = "info" if dbr <= 10 else "warn"
        add("vm.dirty_background_ratio", dbr, target_dbr, sev,
            "Background flush começa mais cedo (5%) — espalha o I/O em vez "
            "de salvar tudo em pico.")

    # ---- fs.file-max ----
    fm = _int(_read_sysctl("fs.file-max"))
    if fm is not None:
        target_fm = max(2_000_000, pve_vms * 8192)
        sev = "warn" if fm < target_fm * 0.5 else "info"
        add("fs.file-max", fm, target_fm, sev,
            f"Com {pve_vms} VMs ativas, cada uma com milhares de FDs (qemu, "
            "tap, etc.), o teto precisa ser alto. 2M é seguro pra qualquer "
            "host PVE.")

    # ---- kernel.pid_max ----
    pm = _int(_read_sysctl("kernel.pid_max"))
    if pm is not None and pve_vms >= 5:
        target_pm = 4_194_304
        sev = "warn" if pm < 65536 else "info"
        add("kernel.pid_max", pm, target_pm, sev,
            "Default 32768 esgota fácil em hosts com 10+ VMs ativas (cada "
            "qemu + threads + tasks internas). 4M é o máximo seguro do kernel.")

    # ---- net.core.somaxconn ----
    sc = _int(_read_sysctl("net.core.somaxconn"))
    if sc is not None:
        target_sc = 8192
        sev = "info" if sc >= 4096 else "warn"
        add("net.core.somaxconn", sc, target_sc, sev,
            "Tamanho da fila de accept(). VMs com servidor web/DB se "
            "beneficiam de fila maior pra absorver picos de conexão.")

    # ---- net.core.netdev_max_backlog ----
    nmb = _int(_read_sysctl("net.core.netdev_max_backlog"))
    if nmb is not None:
        target_nmb = 30000
        sev = "info" if nmb >= 5000 else "warn"
        add("net.core.netdev_max_backlog", nmb, target_nmb, sev,
            "Fila de pacotes recebidos antes do softirq processar. Em "
            "hosts PVE com vmbr0+ várias VMs trafegando, aumentar evita "
            "drops em picos.")

    # ---- vm.min_free_kbytes ----
    mfk = _int(_read_sysctl("vm.min_free_kbytes"))
    if mfk is not None and total_ram_gb >= 16:
        target_mfk = max(262144, int(total_ram_gb * 1024 * 0.5))  # ~0.5%
        sev = "info" if mfk >= target_mfk * 0.5 else "warn"
        add("vm.min_free_kbytes", mfk, target_mfk, sev,
            f"Reserva mínima de RAM livre. Em hosts com {total_ram_gb:.0f} GB, "
            f"manter ~{target_mfk//1024} MB livre ajuda alocações urgentes "
            "(DMA pra IO, balloon das VMs).")

    # ---- Transparent Hugepages ----
    thp = _thp_state()
    if thp is not None:
        if thp != "madvise":
            sev = "warn" if thp == "always" else "info"
            add("transparent_hugepage", thp, "madvise", sev,
                "THP=always causa khugepaged a compactar páginas em background, "
                "introduzindo stalls em VMs (sintoma: latência aleatória dentro "
                "da VM). 'madvise' deixa o kernel só compactar quando a app "
                "explicitamente pede.")
        else:
            add("transparent_hugepage", thp, "madvise", "ok",
                "Configuração ótima pra PVE.")

    # ---- NUMA balancing ----
    if numa_nodes >= 2:
        nb = _int(_read_sysctl("kernel.numa_balancing"))
        if nb is not None and nb == 1:
            add("kernel.numa_balancing", nb, 0, "info",
                "Em hosts multi-socket, numa_balancing migra páginas entre "
                "nodes — útil em workloads genéricos, ruim quando VMs têm "
                "afinidade NUMA explícita (CPU pinning). Se você usa pinning, "
                "desabilite.")

    # ---- ZFS arc_max ----
    if has_zfs:
        arc_max = _arc_max_b()
        # Ideal: 25% da RAM pro ARC em hosts PVE (deixar RAM pras VMs)
        target_arc_gb = max(4, int(total_ram_gb * 0.25))
        if arc_max == 0 or arc_max is None:
            add("zfs.arc_max",
                "automático (até 50% da RAM)",
                f"{target_arc_gb} GiB ({int(total_ram_gb * 0.25)}% da RAM)",
                "warn",
                "ZFS default usa metade da RAM, agressivo pra PVE — deixa "
                "menos memória pras VMs. Ajuste na aba ZFS ou via "
                "/sys/module/zfs/parameters/zfs_arc_max.")
        elif arc_max > total_ram_b * 0.50:
            add("zfs.arc_max",
                f"{arc_max / 1024**3:.1f} GiB",
                f"{target_arc_gb} GiB",
                "warn",
                "ARC ocupando mais de 50% da RAM pode esgotar memória pra "
                "VMs em picos. Limite a ~25%.")

    # ---- Resumo ----
    by_sev = {"critical": 0, "warn": 0, "info": 0, "ok": 0}
    for r in recs:
        by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1

    return {
        "context": {
            "total_ram_gb": round(total_ram_gb, 1),
            "cores": cores,
            "pve_vms": pve_vms,
            "has_zfs": has_zfs,
            "numa_nodes": numa_nodes,
        },
        "recommendations": recs,
        "by_severity": by_sev,
    }
