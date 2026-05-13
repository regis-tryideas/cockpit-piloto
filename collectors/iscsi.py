"""Gerenciamento de iSCSI initiator (open-iscsi) para hosts PVE.

Resolve dores típicas: target indisponível travando o host com D-state
irrecuperável. As recomendações abaixo reduzem o replacement_timeout
default de 120s para 15s, e habilitam noop-out mais agressivo pra detectar
queda de path rápido.
"""
import re
import shutil
import subprocess
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

    # Enriquece sessões com estado do sysfs
    for s in sess:
        st = session_state(s["sid"])
        s["state"] = st.get("state")
        s["recovery_tmo"] = st.get("recovery_tmo")

    return {
        "available": True,
        "sessions": sess,
        "nodes": node_list,
        "iscsid_conf_exists": ISCSID_CONF.exists(),
        "pve_recommended": PVE_RECOMMENDED,
    }
