"""Recomendações de tuning para hosts PVE com alta carga de VMs.

Cada recomendação tem severity: 'critical' / 'warn' / 'info' / 'ok'.
"""
from pathlib import Path

PVE_NODES_DIR = Path("/etc/pve/nodes")


def _pve_pinning_signals() -> dict:
    """Detecta VMs com sinais de PINNING REAL.

    Diferenciação importante:
    - 'affinity: <cpu_list>' → pinning real (vCPU→core físico). Único sinal
      que justifica desabilitar numa_balancing.
    - 'numa: 1' → apenas expõe topologia NUMA *dentro* da VM (configuração
      interna do guest). NÃO faz pinning ao host — kernel host continua
      livre pra mover vCPUs entre cores. NÃO justifica mexer em
      numa_balancing.
    """
    info = {
        "vms_with_affinity": 0,    # pinning real
        "vms_with_numa_only": 0,   # numa virtual exposto, sem pinning
        "total_pinned": 0,         # = vms_with_affinity
    }
    if not PVE_NODES_DIR.exists():
        return info
    try:
        for node_dir in PVE_NODES_DIR.iterdir():
            qemu_dir = node_dir / "qemu-server"
            if not qemu_dir.exists():
                continue
            for conf in qemu_dir.glob("*.conf"):
                try:
                    text = conf.read_text()
                except OSError:
                    continue
                has_affinity = False
                has_numa = False
                for line in text.splitlines():
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    if s.startswith("[") and s.endswith("]"):
                        break  # entrou em seção [snapshot]
                    if s.startswith("affinity:"):
                        has_affinity = True
                    elif s.startswith("numa:") and "1" in s.split(":", 1)[1]:
                        has_numa = True
                if has_affinity:
                    info["vms_with_affinity"] += 1
                    info["total_pinned"] += 1
                elif has_numa:
                    info["vms_with_numa_only"] += 1
    except OSError:
        pass
    return info


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
            numa_nodes: int = 1, has_iscsi: bool = False) -> dict:
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

    # ---- TCP buffers para redes 10G+ (iSCSI, replicação, backup) ----
    if has_iscsi:
        def _norm_ws(s):
            return " ".join((s or "").split())

        target_rmem = 134217728
        rmem = _int(_read_sysctl("net.core.rmem_max"))
        if rmem is not None:
            sev = "warn" if rmem < target_rmem else "info"
            add("net.core.rmem_max", rmem, target_rmem, sev,
                "Buffer máximo de socket de recebimento. Default ~200 KiB é "
                "insuficiente pra TCP saturar 10G+ (iSCSI). 128 MiB destrava "
                "o auto-tuning de janela em links rápidos.")

        target_wmem = 134217728
        wmem = _int(_read_sysctl("net.core.wmem_max"))
        if wmem is not None:
            sev = "warn" if wmem < target_wmem else "info"
            add("net.core.wmem_max", wmem, target_wmem, sev,
                "Idem para envio. Limita o que tcp_wmem consegue alcançar.")

        target_tcp_rmem = "4096 87380 134217728"
        cur_tcp_rmem = _norm_ws(_read_sysctl("net.ipv4.tcp_rmem"))
        if cur_tcp_rmem:
            sev = "warn" if cur_tcp_rmem != target_tcp_rmem else "info"
            add("net.ipv4.tcp_rmem", cur_tcp_rmem, target_tcp_rmem, sev,
                "Tupla min/default/max do auto-tuning de buffer recv por socket. "
                "O 'max' (último valor) precisa bater com net.core.rmem_max — "
                "senão o auto-tune não cresce além do default.")

        target_tcp_wmem = "4096 65536 134217728"
        cur_tcp_wmem = _norm_ws(_read_sysctl("net.ipv4.tcp_wmem"))
        if cur_tcp_wmem:
            sev = "warn" if cur_tcp_wmem != target_tcp_wmem else "info"
            add("net.ipv4.tcp_wmem", cur_tcp_wmem, target_tcp_wmem, sev,
                "Mesma lógica do tcp_rmem, lado envio.")

        ws = _int(_read_sysctl("net.ipv4.tcp_window_scaling"))
        if ws is not None:
            sev = "warn" if ws == 0 else "info"
            add("net.ipv4.tcp_window_scaling", ws, 1, sev,
                "TCP Window Scaling (RFC 1323). Sem isso, janela trava em "
                "64 KiB e throughput em links de alta latência fica preso. "
                "Default é 1 — só vale verificar.")

        ts = _int(_read_sysctl("net.ipv4.tcp_timestamps"))
        if ts is not None:
            sev = "warn" if ts == 0 else "info"
            add("net.ipv4.tcp_timestamps", ts, 1, sev,
                "Timestamps TCP melhoram estimativa de RTT e proteção PAWS "
                "(retransmissões em janelas reaproveitadas). Default 1.")

        ll = _int(_read_sysctl("net.ipv4.tcp_low_latency"))
        if ll is not None:
            sev = "info"  # em kernels modernos é no-op
            add("net.ipv4.tcp_low_latency", ll, 1, sev,
                "Em kernels antigos prefere latência baixa a throughput; "
                "em kernels modernos (>= 4.5) é no-op, mantido aqui por "
                "compatibilidade com guias de tuning.")

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

    # ---- NUMA balancing — só recomenda se houver PINNING REAL ----
    # numa_balancing=1 (default) é BENÉFICO para workloads dinâmicos. O
    # kernel migra páginas pra ficar perto do CPU que as acessa.
    # Apenas 'affinity:' (CPU pinning físico) justifica desabilitar — o
    # hypervisor já está cuidando do scheduling. 'numa: 1' sozinho só
    # expõe topologia NUMA virtual dentro da VM e não impede o kernel
    # host de migrar — numa_balancing continua útil.
    if numa_nodes >= 2:
        nb = _int(_read_sysctl("kernel.numa_balancing"))
        pinning = _pve_pinning_signals()
        n_pinned = pinning["total_pinned"]
        n_numa_only = pinning["vms_with_numa_only"]
        if nb is not None and nb == 1 and n_pinned > 0:
            add("kernel.numa_balancing", nb, 0, "info",
                f"Detectei <strong>{n_pinned} VM(s) com pinning real "
                "(linha <code>affinity:</code>)</strong>. Como o pinning "
                "fixa vCPU→core físico, o kernel não tem onde migrar — "
                "<code>numa_balancing</code> só adiciona overhead de scan. "
                "Desabilitar é vantajoso. (Detectei também " + str(n_numa_only) +
                " VM(s) só com <code>numa: 1</code> — essas não contam: "
                "numa virtual dentro da VM não restringe o host.)")
        elif nb is not None and nb == 1:
            extra = (f" {n_numa_only} VM(s) usam <code>numa: 1</code>, "
                     "mas isso só expõe topologia NUMA <em>dentro</em> da "
                     "VM — não restringe o scheduler do host." if n_numa_only else "")
            add("kernel.numa_balancing", nb, 1, "ok",
                "Host multi-socket sem pinning real (<code>affinity:</code>) "
                "detectado." + extra +
                " <code>numa_balancing=1</code> (padrão) é o ideal — "
                "o kernel migra páginas dinamicamente para reduzir distância "
                "memória/CPU. <strong>Não desabilite</strong> a menos que "
                "ative pinning <code>affinity:</code> em VMs sensíveis primeiro.")

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
