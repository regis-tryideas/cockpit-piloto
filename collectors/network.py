import time

# Prefixos de interfaces "barulho" que poluem o painel em hosts PVE:
# fwbr*/fwln*/fwpr* (bridges de firewall por VM), tap* (tap devices das VMs).
IGNORED_PREFIXES = ("fw", "tap")


def _is_ignored(iface: str) -> bool:
    return iface.startswith(IGNORED_PREFIXES)


def _snapshot() -> dict:
    snapshot = {}
    with open("/proc/net/dev") as f:
        lines = f.readlines()[2:]
    for line in lines:
        if ":" not in line:
            continue
        iface, rest = line.split(":", 1)
        iface = iface.strip()
        parts = rest.split()
        if len(parts) < 16:
            continue
        snapshot[iface] = {
            "rx_bytes": int(parts[0]),
            "rx_packets": int(parts[1]),
            "rx_errors": int(parts[2]),
            "rx_drop": int(parts[3]),
            "tx_bytes": int(parts[8]),
            "tx_packets": int(parts[9]),
            "tx_errors": int(parts[10]),
            "tx_drop": int(parts[11]),
        }
    return snapshot


def collect(interval: int = 1) -> dict:
    try:
        a = _snapshot()
        t0 = time.monotonic()
        time.sleep(interval)
        b = _snapshot()
        dt = time.monotonic() - t0 or interval
    except OSError as e:
        return {"error": f"Não foi possível ler /proc/net/dev: {e}"}

    rows = []
    for iface, cur in b.items():
        if _is_ignored(iface):
            continue
        prev = a.get(iface)
        if not prev:
            continue
        rows.append({
            "iface": iface,
            "rx_kbps": round((cur["rx_bytes"] - prev["rx_bytes"]) / 1024 / dt, 2),
            "tx_kbps": round((cur["tx_bytes"] - prev["tx_bytes"]) / 1024 / dt, 2),
            "rx_pps": round((cur["rx_packets"] - prev["rx_packets"]) / dt, 2),
            "tx_pps": round((cur["tx_packets"] - prev["tx_packets"]) / dt, 2),
            "rx_errors": cur["rx_errors"],
            "tx_errors": cur["tx_errors"],
            "rx_drop": cur["rx_drop"],
            "tx_drop": cur["tx_drop"],
            "rx_total_mb": round(cur["rx_bytes"] / 1024 / 1024, 2),
            "tx_total_mb": round(cur["tx_bytes"] / 1024 / 1024, 2),
        })

    rows.sort(key=lambda r: r["rx_kbps"] + r["tx_kbps"], reverse=True)
    return {"interval": interval, "interfaces": rows}
