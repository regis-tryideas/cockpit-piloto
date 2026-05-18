"""Gerenciamento de serviços do sistema (snmpd, zabbix-agent2 etc).

Lifecycle systemd + edição de config com backup + rollback. Tudo via
argv (sem shell), backup automático antes de qualquer escrita, validação
pela própria reinicialização do serviço (se subir, config é boa).
"""
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

# === Catálogo de serviços conhecidos ==================================

SERVICES: dict[str, dict] = {
    "snmpd": {
        "label": "SNMP daemon",
        "unit": "snmpd.service",
        "packages": ["snmpd", "snmp"],
        "config_path": "/etc/snmp/snmpd.conf",
        "binary": "/usr/sbin/snmpd",
    },
    "zabbix-agent2": {
        "label": "Zabbix agent 2",
        "unit": "zabbix-agent2.service",
        "packages": ["zabbix-agent2"],
        "config_path": "/etc/zabbix/zabbix_agent2.conf",
        "binary": "/usr/sbin/zabbix_agent2",
    },
}

BACKUP_SUFFIX = ".cockpit.bak."
MAX_BACKUPS_KEPT = 10
JOURNAL_LINES = 50


# === systemd helpers ==================================================

def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except FileNotFoundError:
        return 127, "", "command not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def _has_systemctl() -> bool:
    return shutil.which("systemctl") is not None


def unit_status(unit: str) -> dict:
    if not _has_systemctl():
        return {"available": False, "error": "systemctl não disponível"}
    rc_active, active, _ = _run(["systemctl", "is-active", unit], timeout=5)
    rc_enabled, enabled, _ = _run(["systemctl", "is-enabled", unit], timeout=5)
    show_keys = (
        "LoadState", "ActiveState", "SubState", "UnitFileState",
        "MainPID", "MemoryCurrent", "NRestarts", "ActiveEnterTimestamp",
        "FragmentPath", "Description",
    )
    rc, out, _ = _run(
        ["systemctl", "show", unit, "--property=" + ",".join(show_keys)],
        timeout=5,
    )
    props: dict[str, str] = {}
    for line in out.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            props[k.strip()] = v.strip()
    mem_b = None
    try:
        v = props.get("MemoryCurrent", "")
        mem_b = int(v) if v and v != "[not set]" else None
    except ValueError:
        pass
    try:
        n_restarts = int(props.get("NRestarts", "0") or 0)
    except ValueError:
        n_restarts = 0
    return {
        "available": True,
        "unit": unit,
        "active": active,
        "enabled": enabled,
        "load_state": props.get("LoadState"),
        "active_state": props.get("ActiveState"),
        "sub_state": props.get("SubState"),
        "unit_file_state": props.get("UnitFileState"),
        "main_pid": props.get("MainPID"),
        "memory_b": mem_b,
        "n_restarts": n_restarts,
        "active_since": props.get("ActiveEnterTimestamp") or None,
        "fragment_path": props.get("FragmentPath"),
        "description": props.get("Description"),
        "loaded": props.get("LoadState") == "loaded",
    }


def unit_action(unit: str, action: str) -> tuple[bool, str]:
    """start/stop/restart/reload/enable/disable."""
    if action not in {"start", "stop", "restart", "reload",
                      "enable", "disable", "reload-or-restart"}:
        return False, f"ação inválida: {action}"
    if not _has_systemctl():
        return False, "systemctl não disponível"
    rc, out, err = _run(["systemctl", action, unit], timeout=30)
    if rc != 0:
        return False, (err or out or f"exit={rc}")
    return True, f"{action} {unit}: OK"


def unit_journal(unit: str, lines: int = JOURNAL_LINES,
                 since: str = "1h") -> list[dict]:
    if not shutil.which("journalctl"):
        return []
    rc, out, _ = _run([
        "journalctl", "-u", unit, "-n", str(lines), "--since", since,
        "-o", "short-iso", "--no-pager",
    ], timeout=10)
    if rc != 0:
        return []
    rows = []
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("-- "):
            continue
        rows.append({"line": line})
    return rows


# === Pacotes via apt ===================================================

def apt_install(packages: list[str]) -> tuple[bool, str]:
    if not shutil.which("apt-get"):
        return False, "apt-get não disponível"
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    rc, out, err = _run(
        ["apt-get", "install", "-y", "--no-install-recommends", *packages],
        timeout=300,
    )
    if rc != 0:
        tail = (err or out).splitlines()[-5:]
        return False, " | ".join(tail) or f"exit={rc}"
    return True, f"instalado: {', '.join(packages)}"


def package_installed(binary: str) -> bool:
    return Path(binary).exists()


# === Backup / rollback ================================================

def _safe_config_path(path: str) -> Path | None:
    p = Path(path).resolve()
    allowed_roots = (Path("/etc"),)
    if not any(str(p).startswith(str(r) + os.sep) for r in allowed_roots):
        return None
    return p


def backup_file(path: str) -> tuple[bool, str]:
    p = _safe_config_path(path)
    if p is None:
        return False, f"path fora de /etc: {path}"
    if not p.exists():
        return False, f"{p} não existe"
    bk = p.with_name(p.name + BACKUP_SUFFIX + str(int(time.time())))
    try:
        shutil.copy2(p, bk)
        _prune_backups(p)
        return True, str(bk)
    except OSError as e:
        return False, str(e)


def list_backups(path: str) -> list[dict]:
    p = _safe_config_path(path)
    if p is None or not p.parent.exists():
        return []
    prefix = p.name + BACKUP_SUFFIX
    out = []
    for f in sorted(p.parent.iterdir(), reverse=True):
        if not f.name.startswith(prefix):
            continue
        try:
            ts = int(f.name[len(prefix):])
        except ValueError:
            continue
        try:
            stat = f.stat()
        except OSError:
            continue
        out.append({
            "name": f.name,
            "ts": ts,
            "size": stat.st_size,
        })
    return out


def _prune_backups(p: Path) -> None:
    backups = list_backups(str(p))
    for old in backups[MAX_BACKUPS_KEPT:]:
        try:
            (p.parent / old["name"]).unlink()
        except OSError:
            pass


def rollback_backup(path: str, backup_name: str) -> tuple[bool, str]:
    p = _safe_config_path(path)
    if p is None:
        return False, "path inválido"
    if not re.fullmatch(rf"{re.escape(p.name)}{re.escape(BACKUP_SUFFIX)}\d+",
                        backup_name):
        return False, "nome de backup inválido"
    src = p.parent / backup_name
    if not src.exists():
        return False, f"backup não encontrado: {backup_name}"
    cur_bk = backup_file(str(p))
    try:
        shutil.copy2(src, p)
        return True, f"restaurado de {backup_name} (config atual salva como {cur_bk[1] if cur_bk[0] else '?'})"
    except OSError as e:
        return False, str(e)


def write_atomic(path: str, content: str, mode: int = 0o644) -> tuple[bool, str]:
    p = _safe_config_path(path)
    if p is None:
        return False, f"path fora de /etc: {path}"
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = str(p) + ".cockpit.tmp"
    try:
        with open(tmp, "w") as f:
            f.write(content)
        os.chmod(tmp, mode)
        os.replace(tmp, str(p))
        return True, str(p)
    except OSError as e:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except OSError:
            pass
        return False, str(e)


def read_text(path: str) -> str:
    p = _safe_config_path(path)
    if p is None or not p.exists():
        return ""
    try:
        return p.read_text()
    except OSError:
        return ""


# === SNMP =============================================================

SNMPD_DEFAULTS = {
    "agentAddress": "udp:161",
    "community": "public",
    "sysLocation": "",
    "sysContact": "",
    "sysServices": "72",
    "restrict_ip": "",
    "view_systemonly": True,
}


def snmpd_read_form() -> dict:
    raw = read_text(SERVICES["snmpd"]["config_path"])
    form = dict(SNMPD_DEFAULTS)
    for line in raw.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split()
        if not parts:
            continue
        key = parts[0]
        if key == "agentAddress" and len(parts) >= 2:
            form["agentAddress"] = parts[1]
        elif key == "rocommunity" and len(parts) >= 2:
            form["community"] = parts[1]
            if len(parts) >= 3 and parts[2] != "default":
                form["restrict_ip"] = parts[2]
        elif key == "sysLocation" and len(parts) >= 2:
            form["sysLocation"] = " ".join(parts[1:])
        elif key == "sysContact" and len(parts) >= 2:
            form["sysContact"] = " ".join(parts[1:])
        elif key == "sysServices" and len(parts) >= 2:
            form["sysServices"] = parts[1]
    return form


def _sanitize_oneliner(s: str) -> str:
    return s.replace("\n", " ").replace("\r", " ").strip()


def snmpd_render_form(form: dict) -> str:
    agent = _sanitize_oneliner(form.get("agentAddress") or "udp:161")
    community = _sanitize_oneliner(form.get("community") or "public")
    location = _sanitize_oneliner(form.get("sysLocation") or "")
    contact = _sanitize_oneliner(form.get("sysContact") or "")
    services = _sanitize_oneliner(form.get("sysServices") or "72")
    restrict_ip = _sanitize_oneliner(form.get("restrict_ip") or "")
    source = restrict_ip if restrict_ip else "default"
    return (
        "# Gerado por cockpit-piloto\n"
        f"agentAddress {agent}\n"
        "\n"
        "view   systemonly  included   .1.3.6.1.2.1\n"
        "view   systemonly  included   .1.3.6.1.4.1\n"
        "\n"
        f"rocommunity {community} {source} -V systemonly\n"
        "\n"
        f"sysLocation    {location}\n"
        f"sysContact     {contact}\n"
        f"sysServices    {services}\n"
        "\n"
        "master agentx\n"
    )


# === Zabbix-agent =====================================================

ZABBIX_DEFAULTS = {
    "Server": "127.0.0.1",
    "ServerActive": "127.0.0.1",
    "Hostname": "",
    "ListenPort": "10050",
    "LogFile": "/var/log/zabbix/zabbix_agent2.log",
}

_ZABBIX_KEYS = list(ZABBIX_DEFAULTS.keys())


def zabbix_read_form() -> dict:
    raw = read_text(SERVICES["zabbix-agent2"]["config_path"])
    form = dict(ZABBIX_DEFAULTS)
    for line in raw.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "=" not in s:
            continue
        k, _, v = s.partition("=")
        k = k.strip()
        if k in _ZABBIX_KEYS:
            form[k] = v.strip()
    return form


def zabbix_apply_form(form: dict) -> str:
    """Edita o zabbix_agent2.conf preservando comentários e linhas extras."""
    raw = read_text(SERVICES["zabbix-agent2"]["config_path"])
    if not raw:
        lines = [
            "# Gerado por cockpit-piloto",
            "PidFile=/run/zabbix/zabbix_agent2.pid",
            f"LogFile={form.get('LogFile', ZABBIX_DEFAULTS['LogFile'])}",
            f"Server={_sanitize_oneliner(form.get('Server') or '')}",
            f"ServerActive={_sanitize_oneliner(form.get('ServerActive') or '')}",
            f"Hostname={_sanitize_oneliner(form.get('Hostname') or '')}",
            f"ListenPort={_sanitize_oneliner(form.get('ListenPort') or '10050')}",
        ]
        return "\n".join(lines) + "\n"

    handled: set[str] = set()
    out_lines: list[str] = []
    for line in raw.splitlines():
        m = re.match(r"^\s*#?\s*([A-Za-z][A-Za-z0-9_]*)\s*=", line)
        if m:
            key = m.group(1)
            if key in _ZABBIX_KEYS and key not in handled:
                val = _sanitize_oneliner(form.get(key, ZABBIX_DEFAULTS.get(key, "")))
                out_lines.append(f"{key}={val}")
                handled.add(key)
                continue
        out_lines.append(line)
    missing = [k for k in _ZABBIX_KEYS if k not in handled]
    if missing:
        out_lines.append("")
        out_lines.append("# Adicionado por cockpit-piloto")
        for k in missing:
            val = _sanitize_oneliner(form.get(k, ZABBIX_DEFAULTS.get(k, "")))
            out_lines.append(f"{k}={val}")
    return "\n".join(out_lines) + "\n"


# === Dispatcher: aplica config + reinicia, com rollback automático ====

def apply_and_restart(svc_key: str, content: str) -> tuple[bool, str]:
    """Backup + write + restart + verifica. Se falhar, faz rollback."""
    svc = SERVICES.get(svc_key)
    if not svc:
        return False, f"serviço desconhecido: {svc_key}"
    cfg = svc["config_path"]
    ok_bk, bk_msg = backup_file(cfg) if Path(cfg).exists() else (True, "(sem config prévia)")
    if not ok_bk:
        return False, f"backup falhou: {bk_msg}"

    ok_w, msg_w = write_atomic(cfg, content)
    if not ok_w:
        return False, f"escrita falhou: {msg_w}"

    ok_r, msg_r = unit_action(svc["unit"], "restart")
    if not ok_r:
        # Tenta rollback do backup recém-criado
        if bk_msg and bk_msg != "(sem config prévia)":
            bk_name = Path(bk_msg).name
            rb_ok, rb_msg = rollback_backup(cfg, bk_name)
            unit_action(svc["unit"], "restart")
            return False, (f"restart falhou ({msg_r}); rollback "
                           f"{'OK' if rb_ok else 'FALHOU: ' + rb_msg}")
        return False, f"restart falhou: {msg_r}"

    time.sleep(1.5)
    st = unit_status(svc["unit"])
    if st.get("active") != "active":
        if bk_msg and bk_msg != "(sem config prévia)":
            bk_name = Path(bk_msg).name
            rollback_backup(cfg, bk_name)
            unit_action(svc["unit"], "restart")
            return False, (f"{svc['unit']} não ficou active após restart "
                           f"(state={st.get('active_state')}/{st.get('sub_state')}); "
                           "rollback automático aplicado")
        return False, (f"{svc['unit']} não ficou active "
                       f"({st.get('active_state')}/{st.get('sub_state')})")
    return True, f"aplicado · backup: {Path(bk_msg).name if bk_msg.startswith('/') else bk_msg}"


# === Coleta agregada ==================================================

def collect_service(svc_key: str) -> dict:
    svc = SERVICES[svc_key]
    installed = package_installed(svc["binary"])
    status = unit_status(svc["unit"]) if installed else {"available": False}
    raw = read_text(svc["config_path"]) if installed else ""
    if svc_key == "snmpd":
        form = snmpd_read_form() if installed else dict(SNMPD_DEFAULTS)
    elif svc_key == "zabbix-agent2":
        form = zabbix_read_form() if installed else dict(ZABBIX_DEFAULTS)
    else:
        form = {}
    return {
        "key": svc_key,
        "label": svc["label"],
        "unit": svc["unit"],
        "config_path": svc["config_path"],
        "installed": installed,
        "status": status,
        "form": form,
        "raw": raw,
        "backups": list_backups(svc["config_path"]) if installed else [],
        "journal": unit_journal(svc["unit"]) if installed else [],
    }


def collect() -> dict:
    return {
        "systemctl_available": _has_systemctl(),
        "services": [collect_service(k) for k in SERVICES.keys()],
    }
