import json
import os
import subprocess


def collect(interval: int = 1) -> dict:
    try:
        out = subprocess.check_output(
            ["mpstat", "-P", "ALL", "-o", "JSON", str(interval), "2"],
            stderr=subprocess.STDOUT,
            timeout=interval + 5,
        )
    except subprocess.CalledProcessError as e:
        return {"error": f"mpstat falhou: {e.output.decode(errors='replace')}"}
    except FileNotFoundError:
        return {"error": "mpstat não está instalado (pacote sysstat)."}
    except subprocess.TimeoutExpired:
        return {"error": "mpstat excedeu o tempo limite."}

    try:
        data = json.loads(out)
        sample = data["sysstat"]["hosts"][0]["statistics"][1]
        cpus = sample.get("cpu-load", [])
    except (KeyError, IndexError, json.JSONDecodeError) as e:
        return {"error": f"Falha ao interpretar saída do mpstat: {e}"}

    rows = []
    overall = None
    for c in cpus:
        cpu_id = c.get("cpu", "?")
        row = {
            "cpu": cpu_id,
            "usr": c.get("usr", 0.0),
            "sys": c.get("sys", 0.0),
            "iowait": c.get("iowait", 0.0),
            "irq": c.get("irq", 0.0) + c.get("soft", 0.0),
            "steal": c.get("steal", 0.0),
            "idle": c.get("idle", 0.0),
            "busy": round(100.0 - c.get("idle", 0.0), 2),
        }
        if cpu_id == "all":
            overall = row
        else:
            rows.append(row)

    try:
        load_1, load_5, load_15 = os.getloadavg()
    except OSError:
        load_1 = load_5 = load_15 = 0.0

    return {
        "interval": interval,
        "overall": overall,
        "per_cpu": rows,
        "loadavg": {"1m": load_1, "5m": load_5, "15m": load_15},
        "cpu_count": os.cpu_count() or len(rows),
    }
