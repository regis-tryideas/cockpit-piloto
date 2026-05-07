def _read_meminfo() -> dict:
    info = {}
    with open("/proc/meminfo") as f:
        for line in f:
            key, _, rest = line.partition(":")
            value = rest.strip().split()
            if not value:
                continue
            try:
                info[key] = int(value[0])
            except ValueError:
                continue
    return info


def collect() -> dict:
    try:
        info = _read_meminfo()
    except OSError as e:
        return {"error": f"Não foi possível ler /proc/meminfo: {e}"}

    total = info.get("MemTotal", 0)
    free = info.get("MemFree", 0)
    available = info.get("MemAvailable", free)
    buffers = info.get("Buffers", 0)
    cached = info.get("Cached", 0)
    used = total - available
    swap_total = info.get("SwapTotal", 0)
    swap_free = info.get("SwapFree", 0)
    swap_used = swap_total - swap_free

    def pct(num, denom):
        return round(100.0 * num / denom, 2) if denom else 0.0

    return {
        "ram_kb": {
            "total": total,
            "used": used,
            "available": available,
            "free": free,
            "buffers": buffers,
            "cached": cached,
        },
        "ram_pct": {
            "used": pct(used, total),
            "available": pct(available, total),
            "buffers": pct(buffers, total),
            "cached": pct(cached, total),
        },
        "swap_kb": {
            "total": swap_total,
            "used": swap_used,
            "free": swap_free,
        },
        "swap_pct": pct(swap_used, swap_total),
        "raw": {
            "Dirty": info.get("Dirty", 0),
            "Writeback": info.get("Writeback", 0),
            "Slab": info.get("Slab", 0),
            "Mapped": info.get("Mapped", 0),
            "Shmem": info.get("Shmem", 0),
        },
    }
