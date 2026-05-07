import logging
import threading
import time

import db
from collectors import cpu as cpu_col
from collectors import disk as disk_col
from collectors import logical_disk as ldisk_col
from collectors import memory as mem_col
from collectors import network as net_col
from collectors import pressure as psi_col
from collectors import zfs as zfs_col

log = logging.getLogger("cockpit.sampler")

SAMPLE_INTERVAL_SECONDS = 30
PURGE_INTERVAL_SECONDS = 3600

_started = False
_lock = threading.Lock()
_last_purge = 0
_last_arc = {"hits": None, "misses": None}


def _safe(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        log.warning("collector falhou: %s", e)
        return None


def _sample_once(ts: int):
    cpu = _safe(cpu_col.collect, interval=1) or {}
    if not cpu.get("error") and cpu.get("overall"):
        ov = cpu["overall"]
        la = cpu.get("loadavg") or {}
        db.insert_many("metrics_cpu", [{
            "ts": ts,
            "busy": ov.get("busy"),
            "iowait": ov.get("iowait"),
            "sys": ov.get("sys"),
            "usr": ov.get("usr"),
            "load1": la.get("1m"),
            "load5": la.get("5m"),
            "load15": la.get("15m"),
        }])

    mem = _safe(mem_col.collect) or {}
    if not mem.get("error"):
        ram = mem.get("ram_kb", {})
        db.insert_many("metrics_mem", [{
            "ts": ts,
            "used_pct": (mem.get("ram_pct") or {}).get("used"),
            "swap_pct": mem.get("swap_pct"),
            "used_kb": ram.get("used"),
            "available_kb": ram.get("available"),
            "total_kb": ram.get("total"),
            "buffers_kb": ram.get("buffers"),
            "cached_kb": ram.get("cached"),
        }])

    remote = ldisk_col.remote_block_devices()
    disk = _safe(disk_col.collect, interval=1) or {}
    if not disk.get("error"):
        rows = []
        for d in disk.get("devices", []):
            if d["device"] in remote:
                continue
            rows.append({
                "ts": ts, "device": d["device"],
                "util": d.get("util"),
                "r_iops": d.get("r_s"), "w_iops": d.get("w_s"),
                "r_kbs": d.get("rkB_s"), "w_kbs": d.get("wkB_s"),
                "r_await": d.get("r_await"), "w_await": d.get("w_await"),
                "aqu_sz": d.get("aqu_sz"),
            })
        if rows:
            db.insert_many("metrics_disk", rows)

    net = _safe(net_col.collect, interval=1) or {}
    if not net.get("error"):
        rows = []
        for n in net.get("interfaces", []):
            rows.append({
                "ts": ts, "iface": n["iface"],
                "rx_kbps": n.get("rx_kbps"), "tx_kbps": n.get("tx_kbps"),
                "rx_pps": n.get("rx_pps"), "tx_pps": n.get("tx_pps"),
                "rx_errors": n.get("rx_errors"), "tx_errors": n.get("tx_errors"),
            })
        if rows:
            db.insert_many("metrics_net", rows)

    psi = _safe(psi_col.collect) or {}
    if not psi.get("error"):
        def _g(res, kind, key):
            v = (psi.get(res) or {}).get(kind) or {}
            return v.get(key)
        db.insert_many("metrics_psi", [{
            "ts": ts,
            "cpu_some10": _g("cpu", "some", "avg10"),
            "mem_some10": _g("memory", "some", "avg10"),
            "mem_full10": _g("memory", "full", "avg10"),
            "io_some10": _g("io", "some", "avg10"),
            "io_full10": _g("io", "full", "avg10"),
        }])

    zfs = _safe(zfs_col.collect, interval=1) or {}
    if zfs and not zfs.get("error"):
        pool_rows = []
        io_by_pool = {r["name"]: r for r in zfs.get("io", [])}
        for p in zfs.get("pools", []):
            io = io_by_pool.get(p["name"], {})
            cap = (p.get("capacity") or "0").rstrip("%")
            try:
                cap_pct = float(cap)
            except ValueError:
                cap_pct = 0.0
            try:
                frag = float((p.get("fragmentation") or "0").rstrip("%"))
            except ValueError:
                frag = 0.0
            pool_rows.append({
                "ts": ts, "pool": p["name"],
                "capacity_pct": cap_pct,
                "alloc_b": int(p.get("alloc_gib", 0) * 1024**3),
                "free_b": int(p.get("free_gib", 0) * 1024**3),
                "read_iops": io.get("read_iops"),
                "write_iops": io.get("write_iops"),
                "read_bw": io.get("read_bw"),
                "write_bw": io.get("write_bw"),
                "fragmentation_pct": frag,
            })
        if pool_rows:
            db.insert_many("metrics_zfs_pool", pool_rows)

        arc = zfs.get("arc") or {}
        if arc:
            global _last_arc
            hits = arc.get("hits", 0)
            misses = arc.get("misses", 0)
            hits_d = (hits - (_last_arc["hits"] or hits)) if _last_arc["hits"] is not None else 0
            misses_d = (misses - (_last_arc["misses"] or misses)) if _last_arc["misses"] is not None else 0
            total_d = hits_d + misses_d
            interval_hit_ratio = round(100.0 * hits_d / total_d, 2) if total_d > 0 else None
            _last_arc = {"hits": hits, "misses": misses}
            db.insert_many("metrics_zfs_arc", [{
                "ts": ts,
                "size_b": int(arc.get("size_gib", 0) * 1024**3),
                "c_max_b": int(arc.get("c_max_gib", 0) * 1024**3),
                "fill_pct": arc.get("fill_pct"),
                "hit_ratio": interval_hit_ratio if interval_hit_ratio is not None else arc.get("hit_ratio_pct"),
                "hits_delta": hits_d if total_d > 0 else None,
                "misses_delta": misses_d if total_d > 0 else None,
                "mfu_size_b": arc.get("mfu_size_b"),
                "mru_size_b": arc.get("mru_size_b"),
                "l2_hit_ratio": arc.get("l2_hit_ratio_pct"),
            }])


def _loop():
    global _last_purge
    while True:
        ts = int(time.time())
        try:
            _sample_once(ts)
        except Exception as e:
            log.exception("sampling falhou: %s", e)
        if ts - _last_purge >= PURGE_INTERVAL_SECONDS:
            try:
                db.purge_history()
                _last_purge = ts
            except Exception as e:
                log.exception("purge falhou: %s", e)
        # Os coletores já consumiram alguns segundos com seus intervalos
        # internos. Dorme o restante até o próximo ciclo de amostra.
        elapsed = int(time.time()) - ts
        sleep_for = max(1, SAMPLE_INTERVAL_SECONDS - elapsed)
        time.sleep(sleep_for)


def start():
    global _started
    with _lock:
        if _started:
            return
        _started = True
    t = threading.Thread(target=_loop, name="cockpit-sampler", daemon=True)
    t.start()
    log.info("sampler iniciado (intervalo=%ds, retenção=72h)", SAMPLE_INTERVAL_SECONDS)
