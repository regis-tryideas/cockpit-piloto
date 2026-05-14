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
    # Anexa estado do update cache se houver (sem fazer fetch novo)
    result = dict(_cached)
    upd = _UPDATE_CACHE.get("result")
    result["updates_checked_at"] = _UPDATE_CACHE.get("last_check") or None
    result["updates_available"] = bool(upd and upd.get("commits_behind", 0) > 0)
    result["commits_behind"] = upd.get("commits_behind") if upd else None
    return result


# =========================================================================
# Update checker (git fetch + git pull)
# =========================================================================
_UPDATE_CACHE: dict = {"last_check": 0, "result": None}
_UPDATE_TTL = 300  # 5 min


def _git_capture(*args, timeout: int = 30) -> tuple[bool, str]:
    """Roda git capturando stdout+stderr. Retorna (ok, output)."""
    try:
        p = subprocess.run(
            ["git", "-C", str(ROOT), *args],
            capture_output=True, text=True, timeout=timeout,
        )
        out = (p.stdout or "") + (p.stderr or "")
        return p.returncode == 0, out.strip()
    except (subprocess.CalledProcessError, FileNotFoundError,
            subprocess.TimeoutExpired) as e:
        return False, str(e)


def check_updates(force: bool = False) -> dict:
    """git fetch + compara HEAD com origin/<branch>. Cache de 5 min."""
    now = time.time()
    if not force and _UPDATE_CACHE["result"] and \
       (now - _UPDATE_CACHE["last_check"] < _UPDATE_TTL):
        return _UPDATE_CACHE["result"]

    branch = _git("rev-parse", "--abbrev-ref", "HEAD") or "main"
    fetch_ok, fetch_out = _git_capture("fetch", "--quiet", "origin", branch)
    if not fetch_ok:
        result = {"ok": False, "error": f"git fetch falhou: {fetch_out[:300]}"}
        _UPDATE_CACHE.update(last_check=now, result=result)
        return result

    count_str = _git("rev-list", "--count", f"HEAD..origin/{branch}")
    try:
        commits_behind = int(count_str) if count_str else 0
    except ValueError:
        commits_behind = 0

    log_out = _git(
        "log", f"HEAD..origin/{branch}",
        "--pretty=%h %ad %s", "--date=short", "--max-count=20",
    ) or ""

    result = {
        "ok": True,
        "branch": branch,
        "commits_behind": commits_behind,
        "log": log_out,
        "checked_at": int(now),
    }
    _UPDATE_CACHE.update(last_check=now, result=result)
    return result


def apply_update() -> tuple[bool, str]:
    """git pull --ff-only."""
    branch = _git("rev-parse", "--abbrev-ref", "HEAD") or "main"
    ok, out = _git_capture("pull", "--ff-only", "origin", branch, timeout=60)
    # Limpa cache pra próxima check refletir HEAD novo
    _UPDATE_CACHE.update(last_check=0, result=None)
    return ok, out or ("OK" if ok else "falhou")


def restart_service() -> tuple[bool, str]:
    """systemctl restart cockpit-piloto, com delay pra resposta voltar."""
    import shutil as _sh
    if not _sh.which("systemctl"):
        return False, "systemctl não disponível"
    try:
        p = subprocess.run(
            ["systemctl", "is-active", "cockpit-piloto"],
            capture_output=True, text=True, timeout=5,
        )
        if p.stdout.strip() != "active":
            return False, ("serviço cockpit-piloto não está active "
                           "(rodando manualmente? use pkill+./run.sh)")
    except Exception as e:
        return False, f"systemctl is-active falhou: {e}"
    try:
        subprocess.Popen(
            ["bash", "-c", "sleep 1 && systemctl restart cockpit-piloto"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True,
        )
        return True, "restart agendado em 1s (cockpit-piloto.service)"
    except Exception as e:
        return False, str(e)
