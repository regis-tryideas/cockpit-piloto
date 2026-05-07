import subprocess
import time
from pathlib import Path

PROJECT_NAME = "Cockpit - piloto"
ROOT = Path(__file__).parent
VERSION_FILE = ROOT / "VERSION"

_cached: dict | None = None
_cached_ts: float = 0
_TTL = 60  # recomputa a cada 60s pra refletir git pull sem reinicio


def _git(*args: str) -> str | None:
    try:
        out = subprocess.check_output(
            ["git", "-C", str(ROOT), *args],
            stderr=subprocess.DEVNULL,
            timeout=2,
        )
        return out.decode(errors="replace").strip() or None
    except (subprocess.CalledProcessError, FileNotFoundError,
            subprocess.TimeoutExpired):
        return None


def _compute() -> dict:
    count = _git("rev-list", "--count", "HEAD")
    sha = _git("rev-parse", "--short", "HEAD")
    branch = _git("rev-parse", "--abbrev-ref", "HEAD")
    last_commit_ts = _git("log", "-1", "--format=%ct")
    porcelain = _git("status", "--porcelain")
    dirty = bool(porcelain)

    if count and sha:
        version = f"v0.{count}"
        label = version + ("-dirty" if dirty else "")
        try:
            ts = int(last_commit_ts) if last_commit_ts else None
        except ValueError:
            ts = None
        return {
            "name": PROJECT_NAME,
            "version": version,
            "label": label,
            "sha": sha,
            "branch": branch,
            "dirty": dirty,
            "commit_ts": ts,
        }

    if VERSION_FILE.exists():
        v = VERSION_FILE.read_text().strip()
        return {
            "name": PROJECT_NAME, "version": v, "label": v,
            "sha": None, "branch": None, "dirty": False, "commit_ts": None,
        }

    return {
        "name": PROJECT_NAME, "version": "dev", "label": "dev",
        "sha": None, "branch": None, "dirty": False, "commit_ts": None,
    }


def info() -> dict:
    """Devolve info de versão (cacheada por 60s)."""
    global _cached, _cached_ts
    now = time.time()
    if _cached is None or now - _cached_ts > _TTL:
        _cached = _compute()
        _cached_ts = now
    return _cached
