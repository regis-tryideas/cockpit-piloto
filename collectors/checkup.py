"""Checkup agregado — junta validações de tuning, ZFS, iSCSI, SMART,
processos D-state, PG e replicação em uma lista única com severidades.
"""
import sys as _sys
import time
from pathlib import Path as _Path

# Garante que módulos top-level (db, version) sejam importáveis quando este
# arquivo é carregado como sub-módulo de 'collectors'.
_ROOT = str(_Path(__file__).resolve().parents[1])
if _ROOT not in _sys.path:
    _sys.path.insert(0, _ROOT)

import db
import version


def _add(items, *, category, title, status, current="", expected="",
         why="", fix_link="", fix_label=""):
    items.append({
        "category": category, "title": title, "status": status,
        "current": str(current) if current is not None else "",
        "expected": str(expected) if expected is not None else "",
        "why": why, "fix_link": fix_link, "fix_label": fix_label,
    })


def _hostinfo(items, mem, cpu, numa, distro):
    total_ram_gib = (mem.get("ram_kb") or {}).get("total", 0) / 1024 / 1024
    cores = cpu.get("cpu_count") or 0
    nodes = numa.get("node_count") if not numa.get("error") else 1
    _add(items, category="Hardware", title="RAM total",
         status="info", current=f"{total_ram_gib:.1f} GiB",
         why="memória física disponível ao host (excluindo reservada)")
    _add(items, category="Hardware", title="Cores",
         status="info", current=str(cores),
         why="cores lógicos vistos pelo kernel")
    _add(items, category="Hardware", title="NUMA",
         status="info", current=f"{nodes} nó(s)",
         why=("UMA — sem afinidade entre cores e RAM" if nodes <= 1
              else f"NUMA real, considere CPU pinning para VMs críticas"))
    if distro.get("pretty_name"):
        _add(items, category="Hardware", title="Distribuição",
             status="info", current=distro["pretty_name"])


def collect() -> dict:
    """Executa todas as checagens e devolve lista plana de items."""
    items: list[dict] = []

    # Imports tardios para não pagar custo quando algum coletor falhar
    from collectors import cpu as cpu_col
    from collectors import iscsi as iscsi_col
    from collectors import memory as mem_col
    from collectors import numa as numa_col
    from collectors import proxmox as pve_col
    from collectors import smart as smart_col
    from collectors import system as system_col
    from collectors import tuning as tuning_col
    from collectors import zfs as zfs_col

    # ----- coleta dos dados base -----
    mem = mem_col.collect()
    cpu_data = cpu_col.collect(interval=1)
    numa = numa_col.collect()
    sysinfo = system_col.info()
    distro = sysinfo.get("distro") or {}
    total_ram_b = (mem.get("ram_kb") or {}).get("total", 0) * 1024
    cores = sysinfo.get("logical_cpus") or 1
    pve_state = pve_col.detect()
    pve_vms = 0
    if pve_state.get("ok"):
        try:
            pve_data = pve_col.collect()
            if not pve_data.get("error"):
                pve_vms = pve_data.get("impact", {}).get("running_count", 0)
        except Exception:
            pass
    zfs_state = zfs_col.available()

    _hostinfo(items, mem, cpu_data, numa, distro)

    # ----- 1. Sysctl tuning -----
    try:
        tuning_data = tuning_col.collect(
            total_ram_b=total_ram_b, cores=cores, pve_vms=pve_vms,
            has_zfs=zfs_state.get("ok", False),
            numa_nodes=numa.get("node_count", 1) if not numa.get("error") else 1,
        )
        for r in tuning_data.get("recommendations", []):
            _add(items, category="Kernel / Sysctl", title=r["key"],
                 status=r["severity"], current=r["current"],
                 expected=r["recommended"], why=r["why"],
                 fix_link="/system#tuning", fix_label="Aplicar em Sistema")
    except Exception:
        pass

    # ----- 2. ZFS -----
    if zfs_state.get("ok"):
        try:
            zd = zfs_col.collect()
            # 2a. ARC max
            t = zd.get("arc_tunable") or {}
            if t.get("supported") and t.get("is_auto"):
                target_gib = max(4, int(t.get("total_ram_gib", 0) * 0.25))
                _add(items, category="ZFS / ARC",
                     title="zfs_arc_max não definido",
                     status="warn", current="automático (50% RAM)",
                     expected=f"~{target_gib} GiB (25% RAM)",
                     why="ZFS default consome metade da RAM, agressivo demais para PVE com muitas VMs",
                     fix_link="/zfs", fix_label="Ajustar em ZFS")
            # 2b. Kernel tuners ZFS
            for k, info in (zd.get("kernel_tuners") or {}).items():
                if not info.get("matches"):
                    _add(items, category="ZFS / Kernel",
                         title=k, status="info",
                         current=info.get("current") or "—",
                         expected=info.get("recommended"),
                         why=info.get("desc"),
                         fix_link="/zfs",
                         fix_label="Aplicar em ZFS → Tuners")
            # 2c. Pools perfil
            for p in zd.get("pools", []):
                if p.get("needs_tuning"):
                    n_div = len(p.get("profile_mismatches") or [])
                    _add(items, category="ZFS / Pool",
                         title=p["name"],
                         status="warn",
                         current=f"{n_div} divergência(s)",
                         expected=f"perfil {p.get('suggested_profile') or 'auto'}",
                         why="zpool/zfs props não batem com o perfil sugerido pelo tipo de disco",
                         fix_link="/zfs", fix_label="Aplicar perfil em ZFS")
                if p.get("health") and p["health"] != "ONLINE":
                    _add(items, category="ZFS / Pool",
                         title=f"{p['name']} saúde",
                         status="critical",
                         current=p["health"],
                         expected="ONLINE",
                         why="pool degradado ou faltando dispositivos",
                         fix_link="/zfs")
            # 2d. Datasets
            for d in zd.get("datasets", []):
                c = d.get("compliance") or {}
                if c and not c.get("compliant"):
                    _add(items, category="ZFS / Dataset",
                         title=d["name"],
                         status="info",
                         current=f"{c.get('ok_count', 0)}/{c.get('total', 0)} props ok",
                         expected=f"perfil {d.get('suggested_profile', 'vms')}",
                         why="propriedades não batem com o perfil sugerido",
                         fix_link="/zfs")
        except Exception:
            pass

    # ----- 3. iSCSI -----
    try:
        ic = iscsi_col.collect()
        if ic.get("available"):
            # 3a. iscsid.conf global
            cc = ic.get("iscsid_conf_compliance")
            if cc and not cc.get("compliant"):
                _add(items, category="iSCSI / Global",
                     title="/etc/iscsi/iscsid.conf",
                     status="warn",
                     current=f"{len(cc.get('mismatches', []))} param(s) fora do perfil",
                     expected="perfil PVE (replacement_timeout=15s, noop=5s)",
                     why="defaults do open-iscsi causam D-state irrecuperável quando target cai",
                     fix_link="/iscsi", fix_label="Aplicar perfil PVE")
            # 3b. Por target
            for n in ic.get("nodes", []):
                if not n.get("compliance", {}).get("compliant"):
                    miss = len(n["compliance"].get("mismatches", []))
                    _add(items, category="iSCSI / Target",
                         title=n["target"][:80] + ("..." if len(n["target"]) > 80 else ""),
                         status="warn",
                         current=f"{miss} timeout(s) fora do perfil",
                         expected="perfil PVE",
                         why="timeouts altos travam IO e podem forçar reboot do host",
                         fix_link="/iscsi", fix_label="Aplicar perfil")
    except Exception:
        pass

    # ----- 4. D-state processes -----
    try:
        d_state = system_col.d_state_processes(limit=30)
        import re as _re
        iscsi_re = _re.compile(r"iscsi|sbsm|scsi_eh|target_", _re.IGNORECASE)
        iscsi_stuck = [p for p in d_state if p.get("wchan") and iscsi_re.search(p["wchan"])]
        if iscsi_stuck:
            _add(items, category="Processos",
                 title=f"{len(iscsi_stuck)} processo(s) presos em wchan SCSI/iSCSI",
                 status="critical",
                 why="indica gargalo ou target iSCSI/SCSI travado",
                 fix_link="/iscsi", fix_label="Verificar iSCSI")
        kthread_stuck = [p for p in d_state if p.get("is_kthread")]
        if kthread_stuck:
            names = ", ".join(p["comm"] for p in kthread_stuck[:5])
            _add(items, category="Processos",
                 title=f"{len(kthread_stuck)} kthread(s) em D-state",
                 status="warn",
                 current=names,
                 why="kernel thread travado pode indicar driver ou hardware com problema",
                 fix_link="/system", fix_label="Ver Sistema → D-state")
    except Exception:
        pass

    # ----- 5. SMART -----
    try:
        sm = smart_col.collect()
        for s in sm.get("disks", []):
            if s.get("passed") is False:
                _add(items, category="Hardware / SMART",
                     title=f"{s['device']} reportou FAILED",
                     status="critical",
                     current=f"{s.get('model')} · {s.get('serial')}",
                     why="firmware do disco indica falha iminente — substitua",
                     fix_link="/disk", fix_label="Ver Disco")
            for w in (s.get("warnings") or []):
                _add(items, category="Hardware / SMART",
                     title=f"{s['device']}: {w}",
                     status="warn", why=w,
                     fix_link="/disk")
            poh = s.get("power_on_hours") or 0
            if poh >= 43800 and not s.get("is_ssd") and not s.get("is_nvme"):
                _add(items, category="Hardware / SMART",
                     title=f"{s['device']} com vida estendida",
                     status="info",
                     current=f"{poh:,} h (~{poh/8760:.1f} anos)",
                     why="disco rotativo passou expectativa típica de 5 anos — planeje substituição",
                     fix_link="/disk")
            wear = s.get("wear_pct_used")
            if wear and wear >= 80:
                _add(items, category="Hardware / SMART",
                     title=f"{s['device']} wear-out alto",
                     status="warn",
                     current=f"{wear}%",
                     why="NVMe próximo do fim da vida útil estimada",
                     fix_link="/disk")
    except Exception:
        pass

    # ----- 6. PostgreSQL config -----
    try:
        pg = db.pg_get_config()
        if pg.get("enabled"):
            if pg.get("last_test_ok") == 0:
                _add(items, category="Banco / PostgreSQL",
                     title="Última conexão PG falhou",
                     status="warn",
                     current=pg.get("last_test_msg", "—"),
                     why="dual-write para PG não está funcionando — histórico de longo prazo offline",
                     fix_link="/system/pg", fix_label="Verificar config PG")
    except Exception:
        pass

    # ----- 7. Replicação -----
    try:
        with db.connect() as conn:
            bad = conn.execute(
                "SELECT name, last_error FROM replication_jobs "
                "WHERE last_run_status='error' AND enabled=1"
            ).fetchall()
        for j in bad:
            _add(items, category="Replicação",
                 title=f"job {j['name']} com erro",
                 status="warn",
                 current=(j["last_error"] or "")[:120],
                 why="último run terminou em erro — investigue rede, permissões SSH ou tooling",
                 fix_link="/replication")
    except Exception:
        pass

    # ----- 8. Update do Cockpit -----
    try:
        v = version.info()
        if v.get("updates_available"):
            _add(items, category="Cockpit",
                 title="Atualização disponível",
                 status="info",
                 current=v.get("label", "?"),
                 expected=f"{v.get('commits_behind')} commit(s) novos",
                 why="origin/main tem commits não puxados",
                 fix_link="/system#update", fix_label="Verificar / atualizar")
    except Exception:
        pass

    # ----- 9. Filesystems quase cheios -----
    try:
        from collectors import disk as disk_col
        d = disk_col.collect(interval=1)
        for fs in d.get("filesystems", []):
            pct = int((fs.get("use_pct") or "0").rstrip("%") or 0)
            if pct >= 90:
                _add(items, category="Hardware / Filesystems",
                     title=f"{fs.get('mount')} a {pct}%",
                     status="critical",
                     current=f"{pct}%",
                     expected="< 90%",
                     why="filesystem quase cheio — risco de falha em escritas",
                     fix_link="/disk")
            elif pct >= 80:
                _add(items, category="Hardware / Filesystems",
                     title=f"{fs.get('mount')} a {pct}%",
                     status="warn",
                     current=f"{pct}%", expected="< 80%",
                     why="filesystem se aproximando do limite",
                     fix_link="/disk")
    except Exception:
        pass

    # ----- resumo -----
    summary = {"critical": 0, "warn": 0, "info": 0, "ok": 0}
    cat_counts: dict = {}
    for it in items:
        summary[it["status"]] = summary.get(it["status"], 0) + 1
        cat = it["category"]
        cat_counts[cat] = cat_counts.get(cat, 0) + 1

    return {
        "items": items,
        "summary": summary,
        "categories": sorted(cat_counts.keys()),
        "category_counts": cat_counts,
        "generated_at": int(time.time()),
    }
