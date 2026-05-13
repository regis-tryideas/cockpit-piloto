"""Gerenciamento de iSCSI initiator (open-iscsi) para hosts PVE.

Resolve dores típicas: target indisponível travando o host com D-state
irrecuperável. As recomendações abaixo reduzem o replacement_timeout
default de 120s para 15s, e habilitam noop-out mais agressivo pra detectar
queda de path rápido.
"""
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

ISCSID_CONF = Path("/etc/iscsi/iscsid.conf")
ISCSI_NODES_DIR = Path("/etc/iscsi/nodes")

# Perfil recomendado para hosts PVE com VMs em iSCSI.
# Aplicado em cada node (target+portal) via 'iscsiadm -m node -o update'.
PVE_RECOMMENDED = {
    "node.session.timeo.replacement_timeout": "15",
    "node.conn[0].timeo.noop_out_interval": "5",
    "node.conn[0].timeo.noop_out_timeout": "5",
    "node.session.err_timeo.abort_timeout": "15",
    "node.session.err_timeo.lu_reset_timeout": "20",
    "node.session.err_timeo.tgt_reset_timeout": "30",
}

# Parâmetros que vamos coletar pra exibir (subconjunto relevante)
INSPECTED_KEYS = list(PVE_RECOMMENDED.keys()) + [
    "node.startup",
    "node.session.queue_depth",
    "node.conn[0].timeo.login_timeout",
    "node.conn[0].timeo.logout_timeout",
]


def has_iscsiadm() -> bool:
    return shutil.which("iscsiadm") is not None


def _run(cmd: list[str], timeout: int = 10) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "command not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


_SESSION_RE = re.compile(
    r"^(?P<transport>\S+):\s+\[(?P<sid>\d+)\]\s+"
    r"(?P<portal>\S+),(?P<tpgt>\d+)\s+"
    r"(?P<target>\S+)"
)


def sessions() -> list[dict]:
    """iscsiadm -m session — lista sessões ativas."""
    if not has_iscsiadm():
        return []
    rc, out, _ = _run(["iscsiadm", "-m", "session"], timeout=8)
    if rc != 0:
        return []
    rows = []
    for line in out.strip().splitlines():
        m = _SESSION_RE.match(line.strip())
        if not m:
            continue
        rows.append({
            "transport": m.group("transport"),
            "sid": int(m.group("sid")),
            "portal": m.group("portal"),
            "tpgt": int(m.group("tpgt")),
            "target": m.group("target"),
        })
    return rows


_NODE_RE = re.compile(r"^(?P<portal>\S+),(?P<tpgt>\d+)\s+(?P<target>\S+)")


def nodes() -> list[dict]:
    """iscsiadm -m node — lista nodes configurados (logados ou não)."""
    if not has_iscsiadm():
        return []
    rc, out, _ = _run(["iscsiadm", "-m", "node"], timeout=8)
    if rc != 0:
        return []
    rows = []
    for line in out.strip().splitlines():
        m = _NODE_RE.match(line.strip())
        if not m:
            continue
        rows.append({
            "portal": m.group("portal"),
            "tpgt": int(m.group("tpgt")),
            "target": m.group("target"),
        })
    return rows


def node_params(target: str, portal: str) -> dict:
    """iscsiadm -m node -T <iqn> -p <portal> -o show — só keys relevantes."""
    if not has_iscsiadm():
        return {}
    rc, out, _ = _run([
        "iscsiadm", "-m", "node", "-T", target, "-p", portal, "-o", "show",
    ], timeout=8)
    if rc != 0:
        return {}
    params = {}
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        if k in INSPECTED_KEYS:
            params[k] = v.strip()
    return params


def session_state(sid: int) -> dict:
    """Estado interno da sessão via /sys/class/iscsi_session/sessionN/."""
    base = Path(f"/sys/class/iscsi_session/session{sid}")
    if not base.exists():
        return {}
    out = {}
    for attr in ("state", "recovery_tmo", "connection0/iscsi_connection",
                 "targetname", "tpgt"):
        p = base / attr
        try:
            out[attr.split("/")[-1]] = p.read_text().strip() if p.is_file() else None
        except OSError:
            pass
    return out


def evaluate_compliance(params: dict) -> dict:
    """Compara params atuais vs PVE_RECOMMENDED. Retorna {ok_count, mismatches}."""
    mismatches = []
    for k, expected in PVE_RECOMMENDED.items():
        actual = params.get(k)
        if actual is None:
            continue  # param não retornado — driver mais novo/antigo
        if actual.strip() != expected:
            mismatches.append({
                "key": k, "actual": actual, "expected": expected,
            })
    return {
        "ok_count": len(PVE_RECOMMENDED) - len(mismatches),
        "total": len(PVE_RECOMMENDED),
        "mismatches": mismatches,
        "compliant": len(mismatches) == 0,
    }


def set_param(target: str, portal: str, key: str, value: str) -> tuple[bool, str]:
    """iscsiadm -m node -T <t> -p <p> -o update -n <k> -v <v>"""
    if not has_iscsiadm():
        return False, "iscsiadm não disponível"
    rc, out, err = _run([
        "iscsiadm", "-m", "node", "-T", target, "-p", portal,
        "-o", "update", "-n", key, "-v", value,
    ], timeout=10)
    if rc != 0:
        return False, (err.strip() or out.strip() or f"exit={rc}")
    return True, f"{key} = {value}"


def apply_pve_profile(target: str, portal: str) -> dict:
    """Aplica todos os parâmetros do PVE_RECOMMENDED em um node."""
    results = []
    for k, v in PVE_RECOMMENDED.items():
        ok, msg = set_param(target, portal, k, v)
        results.append({"key": k, "value": v, "ok": ok, "message": msg})
    return {
        "all_ok": all(r["ok"] for r in results),
        "results": results,
        "note": ("Para sessões já ativas, faça logout/login para que os novos "
                 "timeouts entrem em vigor."),
    }


def logout(target: str, portal: str) -> tuple[bool, str]:
    rc, out, err = _run([
        "iscsiadm", "-m", "node", "-T", target, "-p", portal, "--logout",
    ], timeout=30)
    if rc != 0:
        return False, (err.strip() or out.strip() or f"exit={rc}")
    return True, "logout OK"


def login(target: str, portal: str) -> tuple[bool, str]:
    rc, out, err = _run([
        "iscsiadm", "-m", "node", "-T", target, "-p", portal, "--login",
    ], timeout=30)
    if rc != 0:
        return False, (err.strip() or out.strip() or f"exit={rc}")
    return True, "login OK"


def iscsid_conf() -> dict:
    """Lê /etc/iscsi/iscsid.conf, devolve dict (chaves não-comentadas)."""
    if not ISCSID_CONF.exists():
        return {"exists": False, "params": {}, "raw": ""}
    try:
        raw = ISCSID_CONF.read_text()
    except OSError as e:
        return {"exists": True, "error": str(e), "raw": ""}
    params = {}
    for line in raw.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if "=" not in s:
            continue
        k, _, v = s.partition("=")
        params[k.strip()] = v.strip()
    return {"exists": True, "params": params, "raw": raw}


def update_iscsid_conf(updates: dict) -> tuple[bool, str]:
    """Edita /etc/iscsi/iscsid.conf atomicamente, preservando comentários.

    Para cada key em `updates`, se já existir (mesmo comentada), descomenta
    e substitui o valor; se não existir, adiciona no final.
    """
    if not ISCSID_CONF.exists():
        return False, f"{ISCSID_CONF} não existe"
    bk = f"{ISCSID_CONF}.cockpit.bak.{int(time.time())}"
    try:
        shutil.copy2(ISCSID_CONF, bk)
    except OSError as e:
        return False, f"backup falhou: {e}"

    try:
        lines = ISCSID_CONF.read_text().splitlines()
    except OSError as e:
        return False, f"leitura falhou: {e}"

    handled = set()
    out_lines = []
    for line in lines:
        matched = False
        for k, v in updates.items():
            # Casa 'key = value' ou '#key = value' (comentado)
            pat = re.compile(rf"^\s*#?\s*{re.escape(k)}\s*=")
            if pat.match(line):
                out_lines.append(f"{k} = {v}")
                handled.add(k)
                matched = True
                break
        if not matched:
            out_lines.append(line)

    # Append das chaves que ainda não apareceram
    missing = [k for k in updates.keys() if k not in handled]
    if missing:
        out_lines.append("")
        out_lines.append("# Adicionado por cockpit-piloto")
        for k in missing:
            out_lines.append(f"{k} = {updates[k]}")

    content = "\n".join(out_lines) + "\n"
    try:
        tmp = str(ISCSID_CONF) + ".cockpit.tmp"
        with open(tmp, "w") as f:
            f.write(content)
        os.chmod(tmp, 0o600)
        os.replace(tmp, str(ISCSID_CONF))
        return True, f"{ISCSID_CONF} atualizado · backup: {bk}"
    except OSError as e:
        return False, f"escrita falhou: {e}"


def apply_pve_profile_global() -> tuple[bool, str]:
    """Aplica PVE_RECOMMENDED no /etc/iscsi/iscsid.conf global."""
    return update_iscsid_conf(PVE_RECOMMENDED)


def session_devices(sid: int) -> list[dict]:
    """Lista block devices /dev/sd* atrás de uma sessão iSCSI."""
    base = Path(f"/sys/class/iscsi_session/session{sid}/device")
    if not base.exists():
        return []
    out = []
    # Estrutura: device/target<H>:<C>:<I>/<H>:<C>:<I>:<LUN>/block/<sd*>
    try:
        for target_dir in base.glob("target*"):
            for lun_dir in target_dir.iterdir():
                if not lun_dir.is_dir():
                    continue
                block_dir = lun_dir / "block"
                if not block_dir.exists():
                    continue
                for dev in block_dir.iterdir():
                    state_file = dev / "device" / "state"
                    state = (state_file.read_text().strip()
                             if state_file.exists() else "?")
                    size_file = dev / "size"
                    sectors = (int(size_file.read_text().strip())
                               if size_file.exists() else 0)
                    out.append({
                        "name": dev.name,
                        "lun": lun_dir.name,
                        "state": state,
                        "size_b": sectors * 512,
                    })
    except OSError:
        pass
    return out


def session_stats(sid: int) -> dict:
    """Lê estatísticas da sessão em /sys/class/iscsi_session/."""
    base = Path(f"/sys/class/iscsi_session/session{sid}")
    if not base.exists():
        return {}
    out = {}
    for attr in (
        "state", "recovery_tmo", "targetname", "tpgt",
        "initial_r2t", "immediate_data", "data_pdu_in_order",
        "data_seq_in_order", "first_burst_len", "max_burst_len",
        "max_outstanding_r2t",
    ):
        p = base / attr
        try:
            if p.is_file():
                out[attr] = p.read_text().strip()
        except OSError:
            continue

    # Connection state (sessionN tem connectionN:0 dentro)
    conn_base = Path(f"/sys/class/iscsi_connection")
    if conn_base.exists():
        for conn in conn_base.glob(f"connection{sid}:*"):
            try:
                out["connection_state"] = (
                    (conn / "state").read_text().strip()
                    if (conn / "state").exists() else None
                )
                out["connection_address"] = (
                    (conn / "address").read_text().strip()
                    if (conn / "address").exists() else None
                )
                out["connection_port"] = (
                    (conn / "port").read_text().strip()
                    if (conn / "port").exists() else None
                )
            except OSError:
                pass
            break
    return out


def journal_errors(lines: int = 50, since: str = "1h") -> dict:
    """Busca no journal entradas de erro relacionadas a iSCSI/SCSI."""
    try:
        from . import logs as logs_col
    except ImportError:
        return {"rows": [], "error": "logs collector indisponível"}

    # Filtra por unit iscsid + kernel; depois grep manual por keywords
    result = logs_col.journal(
        priority=4, unit=None, since=since, search="iscsi|scsi|sd ", lines=lines,
    )
    if result.get("error"):
        return {"rows": [], "error": result["error"]}
    rows = []
    for r in result.get("rows", []):
        msg = r.get("message") or ""
        if any(k in msg.lower() for k in (
            "iscsi", "scsi", "abort", "i/o error", "sense key",
            "session", "ping timeout", "connect failed",
        )):
            rows.append(r)
    return {"rows": rows[:lines]}


def discover(portal: str) -> tuple[bool, list[str] | str]:
    """iscsiadm -m discovery -t st -p <portal>"""
    if not has_iscsiadm():
        return False, "iscsiadm não disponível"
    rc, out, err = _run([
        "iscsiadm", "-m", "discovery", "-t", "st", "-p", portal,
    ], timeout=15)
    if rc != 0:
        return False, (err.strip() or out.strip() or f"exit={rc}")
    targets = []
    for line in out.strip().splitlines():
        m = _NODE_RE.match(line.strip())
        if m:
            targets.append({
                "portal": m.group("portal"),
                "tpgt": int(m.group("tpgt")),
                "target": m.group("target"),
            })
    return True, targets


def collect() -> dict:
    if not has_iscsiadm():
        return {
            "available": False,
            "error": "iscsiadm não encontrado (instale open-iscsi).",
            "sessions": [], "nodes": [],
        }
    sess = sessions()
    sess_set = {(s["target"], s["portal"]) for s in sess}

    node_list = []
    for n in nodes():
        params = node_params(n["target"], n["portal"])
        compliance = evaluate_compliance(params)
        node_list.append({
            **n,
            "logged_in": (n["target"], n["portal"]) in sess_set,
            "params": params,
            "compliance": compliance,
        })

    # Enriquece sessões com estado do sysfs, devices e stats
    for s in sess:
        st = session_stats(s["sid"])
        s["state"] = st.get("state")
        s["recovery_tmo"] = st.get("recovery_tmo")
        s["connection_state"] = st.get("connection_state")
        s["connection_address"] = st.get("connection_address")
        s["connection_port"] = st.get("connection_port")
        s["devices"] = session_devices(s["sid"])

    # Config global iscsid.conf — checa conformidade contra PVE_RECOMMENDED
    conf = iscsid_conf()
    conf_compliance = evaluate_compliance(conf.get("params", {})) if conf.get("exists") else None

    # Erros recentes no journal
    errors = journal_errors(lines=30, since="1h")

    return {
        "available": True,
        "sessions": sess,
        "nodes": node_list,
        "iscsid_conf": conf,
        "iscsid_conf_compliance": conf_compliance,
        "pve_recommended": PVE_RECOMMENDED,
        "errors_recent": errors,
    }
