from pathlib import Path

PSI_DIR = Path("/proc/pressure")


def _parse_psi_file(path: Path) -> dict:
    """Parse a /proc/pressure/* file.

    Cada arquivo PSI tem 1 ou 2 linhas no formato:
        some avg10=0.00 avg60=0.00 avg300=0.00 total=N
        full avg10=0.00 avg60=0.00 avg300=0.00 total=N
    """
    result = {"some": None, "full": None}
    try:
        text = path.read_text()
    except OSError as e:
        return {"error": str(e)}
    for line in text.strip().splitlines():
        parts = line.split()
        if not parts:
            continue
        kind = parts[0]
        kv = {}
        for token in parts[1:]:
            if "=" not in token:
                continue
            k, v = token.split("=", 1)
            try:
                kv[k] = float(v) if "." in v else int(v)
            except ValueError:
                continue
        result[kind] = kv
    return result


def collect() -> dict:
    if not PSI_DIR.exists():
        return {"error": "PSI indisponível (kernel sem CONFIG_PSI?)"}
    out = {}
    for resource in ("cpu", "memory", "io"):
        out[resource] = _parse_psi_file(PSI_DIR / resource)
    return out
