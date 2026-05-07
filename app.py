import os
import secrets
from functools import wraps

from flask import (
    Flask, abort, g, jsonify, make_response, redirect, render_template,
    request, url_for,
)

from auth import authenticate
import sampler
from collectors import cpu as cpu_col
from collectors import disk as disk_col
from collectors import logical_disk as ldisk_col
from collectors import memory as mem_col
from collectors import network as net_col
from collectors import numa as numa_col
from collectors import pressure as psi_col
from collectors import proxmox as pve_col
from collectors import system as system_col
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


@app.before_request
def load_session():
    token = request.cookies.get(SESSION_COOKIE)
    g.session = db.get_session(token)
    g.session_token = token


@app.context_processor
def inject_globals():
    return {"pve_detected": PVE_DETECTED}


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
        return redirect(url_for("view_disk"))
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
    nxt = request.form.get("next") or url_for("view_disk")
    if not nxt.startswith("/"):
        nxt = url_for("view_disk")
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
    data = {
        "cpu": cpu_col.collect(interval=interval),
        "memory": mem_col.collect(),
        "disk": disk_col.collect(interval=interval),
        "network": net_col.collect(interval=interval),
        "pressure": psi_col.collect(),
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
    return render_template(
        "_panel_system.html",
        tab="system",
        heading="Sistema",
        username=g.session["username"],
        data=data,
    )


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
    return jsonify({"resource": resource, "window": window, "rows": rows})


@app.errorhandler(404)
def not_found(_):
    return ("Página não encontrada", 404)


def main():
    db.init()
    db.purge_expired_sessions()
    db.purge_history()
    sampler.start()
    host = os.environ.get("COCKPIT_HOST", "0.0.0.0")
    port = int(os.environ.get("COCKPIT_PORT", "6969"))
    app.run(host=host, port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
