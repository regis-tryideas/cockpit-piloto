import json
import os
import secrets
import subprocess
import time
from functools import wraps

from flask import (
    Flask, abort, flash, g, get_flashed_messages, jsonify, make_response,
    redirect, render_template, request, url_for,
)

from auth import authenticate
import replication
import sampler
import version
from collectors import cpu as cpu_col
from collectors import disk as disk_col
from collectors import iscsi as iscsi_col
from collectors import kernel as kernel_col
from collectors import logical_disk as ldisk_col
from collectors import logs as logs_col
from collectors import lvm as lvm_col
from collectors import memory as mem_col
from collectors import network as net_col
from collectors import numa as numa_col
from collectors import pressure as psi_col
from collectors import proxmox as pve_col
from collectors import smart as smart_col
from collectors import system as system_col
from collectors import tuning as tuning_col
from collectors import zfs as zfs_col
import db

SESSION_COOKIE = "cockpit_session"
MAX_FAILED_ATTEMPTS = 10
FAILED_WINDOW_SECONDS = 300

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get(
    "COCKPIT_SECRET", secrets.token_hex(32)
)


PVE_DETECTED = pve_col.detect()["ok"]


@app.template_filter("format_ts")
def _format_ts(ts):
    if not ts:
        return "—"
    import datetime
    return datetime.datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M:%S")


@app.template_filter("format_bytes")
def _format_bytes(b):
    if b is None:
        return "—"
    try:
        b = float(b)
    except (TypeError, ValueError):
        return "—"
    if b == 0:
        return "0 B"
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if abs(b) < 1024:
            return f"{b:.2f} {unit}" if unit != "B" else f"{int(b)} B"
        b /= 1024
    return f"{b:.2f} EiB"


@app.template_filter("format_hours")
def _format_hours(h):
    if h is None:
        return "—"
    try:
        h = int(h)
    except (TypeError, ValueError):
        return "—"
    days = h // 24
    years = days / 365.25
    if years >= 1:
        return f"{h:,} h ({years:.1f} anos · {days} dias)"
    return f"{h:,} h ({days} dias)"


@app.template_filter("format_latency_ns")
def _format_latency_ns(ns):
    """Formata nanosegundos escolhendo a unidade mais legível: ns/µs/ms/s."""
    if ns is None:
        return "—"
    try:
        ns = int(ns)
    except (TypeError, ValueError):
        return "—"
    if ns == 0:
        return "0"
    sign = "-" if ns < 0 else ""
    n = abs(ns)
    if n >= 1_000_000_000:
        return f"{sign}{n/1_000_000_000:.2f} s"
    if n >= 1_000_000:
        return f"{sign}{n/1_000_000:.2f} ms"
    if n >= 1_000:
        return f"{sign}{n/1_000:.2f} µs"
    return f"{sign}{n} ns"


@app.before_request
def load_session():
    token = request.cookies.get(SESSION_COOKIE)
    g.session = db.get_session(token)
    g.session_token = token


@app.context_processor
def inject_globals():
    return {
        "pve_detected": PVE_DETECTED,
        "version_info": version.info(),
    }


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not g.get("session"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapper


def _client_addr() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "?")


@app.get("/login")
def login_form():
    if g.get("session"):
        return redirect(url_for("view_dashboard"))
    return render_template("login.html", error=None)


@app.post("/login")
def login():
    addr = _client_addr()
    if db.recent_failed_attempts(addr, FAILED_WINDOW_SECONDS) >= MAX_FAILED_ATTEMPTS:
        return render_template(
            "login.html",
            error="Muitas tentativas falhas. Aguarde alguns minutos.",
        ), 429

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    ok, error = authenticate(username, password)
    db.record_login_attempt(username, ok, addr)
    if not ok:
        return render_template("login.html", error=error), 401

    token = db.create_session(username, addr)
    nxt = request.form.get("next") or url_for("view_dashboard")
    if not nxt.startswith("/"):
        nxt = url_for("view_dashboard")
    resp = make_response(redirect(nxt))
    resp.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=db.SESSION_TTL_SECONDS,
        httponly=True,
        samesite="Lax",
        secure=False,
    )
    return resp


@app.get("/logout")
def logout():
    db.destroy_session(g.get("session_token"))
    resp = make_response(redirect(url_for("login_form")))
    resp.delete_cookie(SESSION_COOKIE)
    return resp


@app.get("/")
@login_required
def index():
    return redirect(url_for("view_dashboard"))


@app.get("/dashboard")
@login_required
def view_dashboard():
    interval = _interval()
    top = system_col.top_processes(limit=5)
    disk_data = disk_col.collect(interval=interval)
    fs_sorted = sorted(
        disk_data.get("filesystems", []),
        key=lambda fs: int((fs.get("use_pct") or "0").rstrip("%") or 0),
        reverse=True,
    )[:5]
    data = {
        "cpu": cpu_col.collect(interval=interval),
        "memory": mem_col.collect(),
        "disk": disk_data,
        "network": net_col.collect(interval=interval),
        "pressure": psi_col.collect(),
        "system_info": system_col.info(),
        "proc_states": system_col.process_states(),
        "fds": system_col.fd_stats(),
        "top_cpu": top["by_cpu"],
        "top_mem": top["by_mem"],
        "top_filesystems": fs_sorted,
    }
    return render_template(
        "_panel_dashboard.html",
        tab="dashboard",
        heading="Visão geral",
        username=g.session["username"],
        data=data,
    )


@app.get("/disk")
@login_required
def view_disk():
    interval = _interval()
    devices = request.args.getlist("device")
    devices = [d for d in devices if d]
    data = disk_col.collect(interval=interval, devices=devices or None)
    data["smart"] = smart_col.collect()
    return render_template(
        "_panel_disk.html",
        tab="disk",
        heading="Atividade de disco",
        username=g.session["username"],
        data=data,
    )


@app.get("/logical-disk")
@login_required
def view_logical_disk():
    interval = _interval()
    data = ldisk_col.collect(interval=interval)
    return render_template(
        "_panel_logical_disk.html",
        tab="logical-disk",
        heading="Logical Disk",
        username=g.session["username"],
        data=data,
    )


@app.get("/system")
@login_required
def view_system():
    data = system_col.collect(top_limit=20)
    data["kernel"] = kernel_col.collect()
    data["d_state"] = system_col.d_state_processes(limit=30)

    # Contexto pro tuning: RAM, cores, nº de VMs PVE, ZFS, NUMA
    mem = mem_col.collect()
    total_ram_b = (mem.get("ram_kb") or {}).get("total", 0) * 1024
    cores = data["info"].get("logical_cpus") or 1
    pve_vms = 0
    if PVE_DETECTED:
        try:
            pve_info = pve_col.collect()
            if not pve_info.get("error"):
                pve_vms = pve_info.get("impact", {}).get("running_count", 0)
        except Exception:
            pass
    from collectors import numa as numa_col_local
    numa_info = numa_col_local.collect()
    numa_nodes = numa_info.get("node_count", 1) if not numa_info.get("error") else 1
    zfs_avail = zfs_col.available().get("ok", False)

    data["tuning"] = tuning_col.collect(
        total_ram_b=total_ram_b, cores=cores, pve_vms=pve_vms,
        has_zfs=zfs_avail, numa_nodes=numa_nodes,
    )

    return render_template(
        "_panel_system.html",
        tab="system",
        heading="Sistema",
        username=g.session["username"],
        data=data,
    )


SYSCTL_DROPIN = "/etc/sysctl.d/99-pve-cockpit.conf"
THP_TMPFILES = "/etc/tmpfiles.d/cockpit-thp.conf"
THP_RUNTIME = "/sys/kernel/mm/transparent_hugepage/enabled"


def _persist_sysctl(key: str, value: str) -> tuple[bool, str]:
    """Adiciona/substitui linha 'key = value' em /etc/sysctl.d/99-pve-cockpit.conf"""
    new_line = f"{key} = {value}"
    try:
        existing = ""
        if os.path.exists(SYSCTL_DROPIN):
            with open(SYSCTL_DROPIN) as f:
                existing = f.read()
        out_lines = []
        replaced = False
        for line in existing.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                out_lines.append(line)
                continue
            # Match 'key = value' ou 'key=value'
            parts = stripped.split("=", 1)
            if len(parts) == 2 and parts[0].strip() == key:
                out_lines.append(new_line)
                replaced = True
            else:
                out_lines.append(line)
        if not replaced:
            if out_lines and out_lines[-1] != "":
                out_lines.append("")
            out_lines.append(f"# Set by cockpit-piloto")
            out_lines.append(new_line)
        content = "\n".join(out_lines) + "\n"
        # Escrita atômica
        tmp = SYSCTL_DROPIN + ".cockpit.tmp"
        with open(tmp, "w") as f:
            f.write(content)
        os.chmod(tmp, 0o644)
        os.replace(tmp, SYSCTL_DROPIN)
        return True, f"persistido em {SYSCTL_DROPIN}"
    except OSError as e:
        return False, str(e)


def _apply_sysctl_runtime(key: str, value: str) -> tuple[bool, str]:
    path = "/proc/sys/" + key.replace(".", "/")
    if not os.path.exists(path):
        return False, f"sysctl não existe em runtime: {path}"
    try:
        with open(path, "w") as f:
            f.write(str(value))
        return True, "aplicado em runtime"
    except OSError as e:
        return False, f"falha runtime: {e}"


def _apply_thp(value: str) -> tuple[bool, str]:
    """Aplica transparent_hugepage e persiste via tmpfiles.d."""
    if value not in ("always", "madvise", "never"):
        return False, f"valor inválido para THP: {value}"
    if not os.path.exists(THP_RUNTIME):
        return False, "THP não suportado neste kernel"
    try:
        with open(THP_RUNTIME, "w") as f:
            f.write(value)
    except OSError as e:
        return False, f"runtime falhou: {e}"
    try:
        with open(THP_TMPFILES, "w") as f:
            f.write(
                "# Set by cockpit-piloto - reaplica THP a cada boot\n"
                f"w /sys/kernel/mm/transparent_hugepage/enabled - - - - {value}\n"
                f"w /sys/kernel/mm/transparent_hugepage/defrag - - - - {value}\n"
            )
        os.chmod(THP_TMPFILES, 0o644)
    except OSError as e:
        return False, f"runtime aplicado, mas persistência falhou: {e}"
    return True, f"THP={value} aplicado · persistido em {THP_TMPFILES}"


@app.post("/system/tuning/apply")
@login_required
def apply_tuning():
    key = (request.form.get("key") or "").strip()
    value = (request.form.get("value") or "").strip()
    if not key or not value:
        flash(("error", "Parâmetros key e value são obrigatórios."))
        return redirect(url_for("view_system") + "#tuning")

    # Caso especial: THP
    if key == "transparent_hugepage":
        ok, msg = _apply_thp(value)
        flash(("ok" if ok else "error", f"{key}: {msg}"))
        return redirect(url_for("view_system") + "#tuning")

    # Caso especial: zfs.arc_max — redireciona pro fluxo dedicado
    if key == "zfs.arc_max":
        flash(("info",
               "Para alterar zfs_arc_max, use a aba ZFS → 'Ajustar ARC max' (interface dedicada)."))
        return redirect(url_for("view_zfs"))

    # Caso geral: sysctl
    if not key.split(".", 1)[0] in ("vm", "kernel", "fs", "net"):
        flash(("error", f"Chave não suportada: {key}"))
        return redirect(url_for("view_system") + "#tuning")

    ok1, msg1 = _apply_sysctl_runtime(key, value)
    if not ok1:
        flash(("error", f"{key}: {msg1}"))
        return redirect(url_for("view_system") + "#tuning")

    ok2, msg2 = _persist_sysctl(key, value)
    if not ok2:
        flash(("error",
               f"{key} aplicado em runtime mas falhou ao persistir: {msg2}"))
        return redirect(url_for("view_system") + "#tuning")

    flash(("ok", f"{key} = {value} · {msg1} · {msg2}"))
    return redirect(url_for("view_system") + "#tuning")


@app.get("/iscsi")
@login_required
def view_iscsi():
    data = iscsi_col.collect()
    return render_template(
        "_panel_iscsi.html",
        tab="proxmox",
        heading="iSCSI",
        username=g.session["username"],
        data=data,
    )


@app.post("/iscsi/apply-pve-profile")
@login_required
def iscsi_apply_profile():
    target = request.form.get("target", "").strip()
    portal = request.form.get("portal", "").strip()
    if not target or not portal:
        flash(("error", "target e portal são obrigatórios"))
        return redirect(url_for("view_iscsi"))
    r = iscsi_col.apply_pve_profile(target, portal)
    if r["all_ok"]:
        flash(("ok", f"Perfil PVE aplicado em {target} ({portal}). "
                     "Faça logout/login para sessões ativas pegarem os novos timeouts."))
    else:
        errs = [x for x in r["results"] if not x["ok"]]
        flash(("error", f"Falhas em {len(errs)} parâmetros: " +
                       "; ".join(f"{e['key']}={e['message']}" for e in errs[:3])))
    return redirect(url_for("view_iscsi"))


@app.post("/iscsi/logout")
@login_required
def iscsi_logout_route():
    target = request.form.get("target", "").strip()
    portal = request.form.get("portal", "").strip()
    if not target or not portal:
        flash(("error", "target e portal são obrigatórios"))
        return redirect(url_for("view_iscsi"))
    ok, msg = iscsi_col.logout(target, portal)
    flash(("ok" if ok else "error", f"Logout {target}: {msg}"))
    return redirect(url_for("view_iscsi"))


@app.post("/iscsi/apply-global-pve")
@login_required
def iscsi_apply_global_pve():
    ok, msg = iscsi_col.apply_pve_profile_global()
    flash(("ok" if ok else "error", msg))
    return redirect(url_for("view_iscsi"))


@app.post("/iscsi/discover")
@login_required
def iscsi_discover():
    portal = request.form.get("portal", "").strip()
    if not portal:
        flash(("error", "Informe o portal (ip:port)"))
        return redirect(url_for("view_iscsi"))
    ok, result = iscsi_col.discover(portal)
    if not ok:
        flash(("error", f"Discovery falhou: {result}"))
    elif not result:
        flash(("info", f"Discovery em {portal} retornou 0 targets"))
    else:
        flash(("ok", f"Discovery em {portal}: {len(result)} target(s) descoberto(s). "
                     "Use 'login' nos cards abaixo para conectar."))
    return redirect(url_for("view_iscsi"))


@app.post("/iscsi/login")
@login_required
def iscsi_login_route():
    target = request.form.get("target", "").strip()
    portal = request.form.get("portal", "").strip()
    if not target or not portal:
        flash(("error", "target e portal são obrigatórios"))
        return redirect(url_for("view_iscsi"))
    ok, msg = iscsi_col.login(target, portal)
    flash(("ok" if ok else "error", f"Login {target}: {msg}"))
    return redirect(url_for("view_iscsi"))


@app.get("/logs")
@login_required
def view_logs():
    source = request.args.get("source", "journal")
    priority = int(request.args.get("priority", "7"))
    since = request.args.get("since", "1h")
    unit = request.args.get("unit", "").strip() or None
    search = request.args.get("search", "").strip()
    lines = int(request.args.get("lines", "200"))

    if source == "kernel":
        result = logs_col.kernel_buffer(lines=lines, search=search)
    else:
        result = logs_col.journal(
            priority=priority, unit=unit, since=since,
            search=search, lines=lines,
        )

    return render_template(
        "_panel_logs.html",
        tab="logs",
        heading="Logs",
        username=g.session["username"],
        data={
            "source": source,
            "priority": priority,
            "since": since,
            "unit": unit or "",
            "search": search,
            "lines": lines,
            "result": result,
            "windows": logs_col.WINDOW_PRESETS,
            "priority_labels": logs_col.PRIORITY_LABELS,
        },
    )


HOSTS_PATH = "/etc/hosts"
HOSTS_BACKUP_PREFIX = "/etc/hosts.cockpit.bak."
HOSTS_MAX_SIZE = 256 * 1024  # 256 KiB
HOSTS_KEEP_BACKUPS = 10


def _list_hosts_backups():
    import glob
    paths = sorted(glob.glob(HOSTS_BACKUP_PREFIX + "*"), reverse=True)
    out = []
    for p in paths[:HOSTS_KEEP_BACKUPS]:
        try:
            st = os.stat(p)
            out.append({
                "path": p,
                "ts": int(p.rsplit(".", 1)[-1]),
                "size": st.st_size,
            })
        except (OSError, ValueError):
            continue
    return out


@app.get("/system/hosts")
@login_required
def view_hosts_editor():
    try:
        with open(HOSTS_PATH) as f:
            content = f.read()
    except OSError as e:
        content = f"# erro ao ler {HOSTS_PATH}: {e}"
    return render_template(
        "_panel_hosts.html",
        tab="system",
        heading="Editor /etc/hosts",
        username=g.session["username"],
        data={
            "path": HOSTS_PATH,
            "content": content,
            "size": len(content),
            "max_size": HOSTS_MAX_SIZE,
            "backups": _list_hosts_backups(),
        },
    )


@app.post("/system/hosts")
@login_required
def save_hosts():
    new_content = request.form.get("content", "")
    if len(new_content) > HOSTS_MAX_SIZE:
        flash(("error", f"Conteúdo > {HOSTS_MAX_SIZE} bytes (limite)."))
        return redirect(url_for("view_hosts_editor"))
    if "\x00" in new_content:
        flash(("error", "Conteúdo contém bytes nulos — recusado."))
        return redirect(url_for("view_hosts_editor"))
    # Validação mínima: cada linha não-comentário deve ter pelo menos
    # IP + 1 hostname (mas não vou bloquear, só avisar)
    invalid_lines = []
    for n, line in enumerate(new_content.splitlines(), start=1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split()
        if len(parts) < 2:
            invalid_lines.append(n)

    # Backup
    ts = int(time.time())
    backup_path = f"{HOSTS_BACKUP_PREFIX}{ts}"
    try:
        with open(HOSTS_PATH) as f:
            current = f.read()
        with open(backup_path, "w") as f:
            f.write(current)
        os.chmod(backup_path, 0o600)
    except OSError as e:
        flash(("error", f"Falha ao criar backup: {e}"))
        return redirect(url_for("view_hosts_editor"))

    # Escrita atômica via tmpfile + rename
    try:
        tmp = HOSTS_PATH + ".cockpit.tmp"
        with open(tmp, "w") as f:
            f.write(new_content)
        os.chmod(tmp, 0o644)
        os.replace(tmp, HOSTS_PATH)
    except OSError as e:
        flash(("error", f"Falha ao gravar: {e}"))
        return redirect(url_for("view_hosts_editor"))

    msg = f"/etc/hosts salvo · backup: {backup_path}"
    if invalid_lines:
        msg += f" · linhas suspeitas (1 token só): {invalid_lines[:5]}"
    flash(("ok", msg))

    # Rotação: mantém só os últimos N
    backups = _list_hosts_backups()
    import glob
    all_paths = sorted(glob.glob(HOSTS_BACKUP_PREFIX + "*"), reverse=True)
    for old in all_paths[HOSTS_KEEP_BACKUPS:]:
        try:
            os.remove(old)
        except OSError:
            pass

    return redirect(url_for("view_hosts_editor"))


@app.post("/system/hosts/restore")
@login_required
def restore_hosts():
    backup = request.form.get("backup", "")
    if not backup.startswith(HOSTS_BACKUP_PREFIX):
        flash(("error", "Caminho inválido."))
        return redirect(url_for("view_hosts_editor"))
    if not os.path.isfile(backup):
        flash(("error", "Backup não existe."))
        return redirect(url_for("view_hosts_editor"))
    try:
        with open(backup) as f:
            content = f.read()
        # Backup do estado atual antes de restaurar
        ts = int(time.time())
        with open(HOSTS_PATH) as f:
            current = f.read()
        with open(f"{HOSTS_BACKUP_PREFIX}{ts}", "w") as f:
            f.write(current)
        with open(HOSTS_PATH, "w") as f:
            f.write(content)
        flash(("ok", f"Restaurado de {backup}. Estado anterior salvo em backup."))
    except OSError as e:
        flash(("error", f"Falha ao restaurar: {e}"))
    return redirect(url_for("view_hosts_editor"))


@app.get("/numa")
@login_required
def view_numa():
    data = numa_col.collect()
    return render_template(
        "_panel_numa.html",
        tab="numa",
        heading="NUMA",
        username=g.session["username"],
        data=data,
    )


@app.get("/proxmox")
@login_required
def view_proxmox():
    data = pve_col.collect()
    return render_template(
        "_panel_proxmox.html",
        tab="proxmox",
        heading="Proxmox VE",
        username=g.session["username"],
        data=data,
    )


@app.post("/zfs/arc-max")
@login_required
def set_arc_max():
    raw = request.form.get("gib", "").strip().replace(",", ".")
    try:
        gib = float(raw)
    except ValueError:
        flash(("error", f"Valor inválido: {raw!r}"))
        return redirect(url_for("view_zfs"))
    ok, msg = zfs_col.set_arc_max(gib)
    flash(("ok" if ok else "error", msg))
    return redirect(url_for("view_zfs"))


@app.get("/replication")
@login_required
def view_replication():
    lvm_info = lvm_col.collect()
    with db.connect() as conn:
        jobs = [dict(r) for r in conn.execute(
            "SELECT * FROM replication_jobs ORDER BY name").fetchall()]
        # últimos 5 runs por job
        runs_by_job = {}
        for j in jobs:
            runs = conn.execute(
                "SELECT * FROM replication_runs WHERE job_id=? "
                "ORDER BY started_at DESC LIMIT 5", (j["id"],)
            ).fetchall()
            runs_by_job[j["id"]] = [dict(r) for r in runs]
    return render_template(
        "_panel_replication.html",
        tab="proxmox",
        heading="Replicação LVM",
        username=g.session["username"],
        data={
            "lvm": lvm_info,
            "jobs": jobs,
            "runs_by_job": runs_by_job,
        },
    )


@app.post("/replication/jobs")
@login_required
def create_replication_job():
    f = request.form
    name = f.get("name", "").strip()
    if not name:
        flash(("error", "Nome é obrigatório"))
        return redirect(url_for("view_replication"))
    now = int(time.time())
    try:
        with db.connect() as conn:
            conn.execute(
                "INSERT INTO replication_jobs "
                "(name, source_vg, source_thin_pool, source_lv, "
                " dest_kind, dest_host, dest_user, dest_vg, dest_thin_pool, dest_lv, "
                " schedule, enabled, keep_snapshots, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    name,
                    f.get("source_vg", "").strip(),
                    f.get("source_thin_pool", "").strip(),
                    f.get("source_lv", "").strip(),
                    f.get("dest_kind", "ssh").strip(),
                    f.get("dest_host", "").strip(),
                    f.get("dest_user", "root").strip() or "root",
                    f.get("dest_vg", "").strip(),
                    f.get("dest_thin_pool", "").strip(),
                    f.get("dest_lv", "").strip(),
                    (f.get("schedule") or "").strip() or None,
                    1 if f.get("enabled") else 0,
                    int(f.get("keep_snapshots", 3) or 3),
                    now, now,
                )
            )
        flash(("ok", f"Job '{name}' criado."))
    except Exception as e:
        flash(("error", f"Falha ao criar job: {e}"))
    return redirect(url_for("view_replication"))


@app.post("/replication/jobs/<int:job_id>/delete")
@login_required
def delete_replication_job(job_id):
    with db.connect() as conn:
        conn.execute("DELETE FROM replication_runs WHERE job_id=?", (job_id,))
        conn.execute("DELETE FROM replication_jobs WHERE id=?", (job_id,))
    flash(("ok", f"Job {job_id} removido."))
    return redirect(url_for("view_replication"))


@app.post("/replication/jobs/<int:job_id>/run")
@login_required
def run_replication_job(job_id):
    result = replication.run_job(job_id)
    flash(("ok" if result["ok"] else "error", result["message"]))
    return redirect(url_for("view_replication"))


@app.get("/api/replication/source-volumes")
@login_required
def api_repl_source_volumes():
    info = lvm_col.collect()
    if not info.get("available"):
        return jsonify({"available": False, "error": info.get("error")})
    vols = [
        v for v in info.get("thin_volumes", [])
        if not v.get("is_snapshot")
        and not v.get("name", "").startswith("cockpitrepl_")
    ]
    return jsonify({
        "available": True,
        "thin_pools": info.get("thin_pools", []),
        "volumes": vols,
    })


@app.get("/api/proxmox/nodes")
@login_required
def api_pve_nodes():
    if not pve_col.detect().get("ok"):
        return jsonify({"available": False, "nodes": []})
    data = pve_col._run_json([
        "pvesh", "get", "/nodes", "--output-format=json",
    ], timeout=10) or []
    nodes = [{
        "name": n.get("node"),
        "status": n.get("status"),
        "uptime": n.get("uptime", 0),
        "level": n.get("level"),
    } for n in data if n.get("node")]
    return jsonify({"available": True, "nodes": nodes})


@app.get("/api/replication/remote-volumes")
@login_required
def api_repl_remote_volumes():
    import shlex
    user = request.args.get("user", "root").strip() or "root"
    host = request.args.get("host", "").strip()
    if not host:
        return jsonify({"error": "host required"}), 400
    cmd = [
        "ssh", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=8",
        f"{user}@{host}",
        "lvs --reportformat=json --units=b "
        "-o vg_name,lv_name,pool_lv,lv_size,data_percent,lv_attr",
    ]
    try:
        out = subprocess.check_output(
            cmd, stderr=subprocess.STDOUT, timeout=15,
        )
    except subprocess.CalledProcessError as e:
        return jsonify({"error": e.output.decode(errors="replace")[:300]}), 500
    except subprocess.TimeoutExpired:
        return jsonify({"error": "SSH timeout"}), 504
    except FileNotFoundError:
        return jsonify({"error": "ssh não encontrado"}), 500
    try:
        data = json.loads(out)
    except json.JSONDecodeError as e:
        return jsonify({"error": f"JSON inválido: {e}"}), 500
    pools, volumes = [], []
    for r in (data.get("report") or [{}])[0].get("lv", []):
        attr = r.get("lv_attr", "")
        try:
            size_b = int(r["lv_size"].rstrip("B"))
        except (KeyError, ValueError):
            size_b = 0
        row = {
            "vg": r.get("vg_name"),
            "name": r.get("lv_name"),
            "pool": r.get("pool_lv") or "",
            "size_b": size_b,
            "data_pct": float(r.get("data_percent") or 0),
        }
        if attr.startswith("t"):
            pools.append(row)
        elif attr.startswith("V"):
            volumes.append(row)
    return jsonify({
        "host": host, "user": user,
        "thin_pools": pools, "volumes": volumes,
    })


@app.post("/replication/jobs/<int:job_id>/test")
@login_required
def test_replication_job(job_id):
    with db.connect() as conn:
        row = conn.execute(
            "SELECT dest_user, dest_host FROM replication_jobs WHERE id=?",
            (job_id,)
        ).fetchone()
    if not row:
        flash(("error", "Job não encontrado"))
    else:
        ok, msg = replication.test_connection(row["dest_user"], row["dest_host"])
        flash(("ok" if ok else "error", f"Conexão: {msg}"))
    return redirect(url_for("view_replication"))


@app.get("/zfs")
@login_required
def view_zfs():
    interval = _interval()
    data = zfs_col.collect(interval=interval)
    return render_template(
        "_panel_zfs.html",
        tab="zfs",
        heading="ZFS",
        username=g.session["username"],
        data=data,
    )


@app.get("/cpu")
@login_required
def view_cpu():
    interval = _interval()
    data = cpu_col.collect(interval=interval)
    return render_template(
        "_panel_cpu.html",
        tab="cpu",
        heading="CPU",
        username=g.session["username"],
        data=data,
    )


@app.get("/memory")
@login_required
def view_memory():
    data = mem_col.collect()
    return render_template(
        "_panel_memory.html",
        tab="memory",
        heading="Memória",
        username=g.session["username"],
        data=data,
    )


@app.get("/network")
@login_required
def view_network():
    interval = _interval()
    data = net_col.collect(interval=interval)
    return render_template(
        "_panel_network.html",
        tab="network",
        heading="Rede",
        username=g.session["username"],
        data=data,
    )


def _interval() -> int:
    raw = request.args.get("interval", "1")
    try:
        v = int(raw)
    except ValueError:
        return 1
    return max(1, min(v, 5))


VALID_HISTORY_RESOURCES = {
    "cpu": "metrics_cpu",
    "mem": "metrics_mem",
    "disk": "metrics_disk",
    "net": "metrics_net",
    "psi": "metrics_psi",
    "zfs_pool": "metrics_zfs_pool",
    "zfs_arc": "metrics_zfs_arc",
    "pve_vm": "metrics_pve_vm",
    "procs": "metrics_procs",
}

WINDOW_PRESETS = {
    "1h":  3600,
    "6h":  6 * 3600,
    "24h": 24 * 3600,
    "72h": 72 * 3600,
}


@app.get("/api/history/<resource>")
@login_required
def api_history(resource):
    table = VALID_HISTORY_RESOURCES.get(resource)
    if not table:
        abort(404)
    window = request.args.get("window", "6h")
    seconds = WINDOW_PRESETS.get(window, 6 * 3600)
    rows = db.fetch_history(table, seconds)
    if resource == "disk":
        for r in rows:
            ri = r.get("r_iops") or 0
            wi = r.get("w_iops") or 0
            total = ri + wi
            r["total_iops"] = round(total, 2)
            ra = r.get("r_await") or 0
            wa = r.get("w_await") or 0
            r["avg_latency"] = (
                round((ra * ri + wa * wi) / total, 2) if total > 0 else 0.0
            )

    if resource == "pve_vm":
        vmid = request.args.get("vmid")
        if vmid:
            try:
                vmid_int = int(vmid)
                rows = [r for r in rows if r.get("vmid") == vmid_int]
            except ValueError:
                pass
        # Calcula deltas de IO/rede entre amostras (campos cumulativos no PVE)
        prev = {}
        for r in rows:
            key = r.get("vmid")
            p = prev.get(key)
            if p:
                dt = max(1, (r["ts"] or 0) - (p["ts"] or 0))
                for src, dest in (
                    ("diskread_b", "diskread_bps"),
                    ("diskwrite_b", "diskwrite_bps"),
                    ("netin_b",   "netin_bps"),
                    ("netout_b",  "netout_bps"),
                ):
                    cur_v = r.get(src) or 0
                    prev_v = p.get(src) or 0
                    delta = max(0, cur_v - prev_v)  # ignora reset (start de VM)
                    r[dest] = round(delta / dt, 2)
            prev[key] = r

    return jsonify({"resource": resource, "window": window, "rows": rows})


@app.get("/api/proxmox/vm/<int:vmid>/logs")
@login_required
def api_proxmox_vm_logs(vmid):
    vm_type = request.args.get("type", "qemu")
    since = request.args.get("since", "1h")
    lines = int(request.args.get("lines", "200"))
    tasks = pve_col.vm_tasks(vmid, limit=20)
    logs = pve_col.vm_logs(vmid, vm_type=vm_type, since=since, lines=lines)
    return jsonify({"vmid": vmid, "tasks": tasks, "logs": logs})


@app.get("/api/proxmox/vm/<int:vmid>/snapshots")
@login_required
def api_proxmox_vm_snapshots(vmid):
    vm_type = request.args.get("type", "qemu")
    snaps = pve_col.vm_snapshots(vmid, vm_type=vm_type)
    return jsonify({"vmid": vmid, "snapshots": snaps})


@app.errorhandler(404)
def not_found(_):
    return ("Página não encontrada", 404)


def main():
    db.init()
    db.purge_expired_sessions()
    db.purge_history()
    db.purge_non_physical_disks()
    sampler.start()
    host = os.environ.get("COCKPIT_HOST", "0.0.0.0")
    port = int(os.environ.get("COCKPIT_PORT", "6969"))
    app.run(host=host, port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
