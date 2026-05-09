"""Replicação LVM thin → LVM thin (snapshot incremental).

Para cada job:
1. Cria snapshot thin atomic da origem (`lvcreate --snapshot --type thin`)
2. Se há `last_snapshot` válido, calcula delta com `thin_delta` e envia só a
   diferença com `thin_send`. Caso contrário, envia full pela primeira vez.
3. No destino (via SSH), recebe o stream com `thin_recv` num LV equivalente.
4. Mantém os últimos N snapshots na origem (rotação) para próximas rep.

Requer no host fonte E destino:
- lvm2 (lvcreate, lvremove, vgs, lvs)
- thin-provisioning-tools (thin_send, thin_recv, thin_delta)
- SSH com chave configurada para acesso passwordless ao destino
"""
import logging
import shlex
import shutil
import subprocess
import time
from datetime import datetime

import db
from collectors import lvm

log = logging.getLogger("cockpit.replication")

SNAPSHOT_PREFIX = "cockpitrepl"
SSH_OPTS = [
    "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", "ConnectTimeout=10",
]


def _now() -> int:
    return int(time.time())


def _snapshot_name(lv: str) -> str:
    ts = datetime.now().strftime("%Y%m%dT%H%M%S")
    return f"{SNAPSHOT_PREFIX}_{lv}_{ts}"


def _run(cmd: list[str], **kwargs) -> tuple[int, str, str]:
    """Roda comando local, retorna (rc, stdout, stderr)."""
    log.debug("run: %s", " ".join(shlex.quote(p) for p in cmd))
    p = subprocess.run(
        cmd, capture_output=True, text=True, **kwargs,
    )
    return p.returncode, p.stdout, p.stderr


def _ssh_cmd(user: str, host: str, remote_cmd: str) -> list[str]:
    return ["ssh", *SSH_OPTS, f"{user}@{host}", remote_cmd]


def test_connection(user: str, host: str) -> tuple[bool, str]:
    """Verifica que SSH funciona e que ferramentas existem no destino."""
    rc, out, err = _run(_ssh_cmd(
        user, host,
        "command -v lvcreate >/dev/null && command -v thin_recv >/dev/null && echo OK",
    ), timeout=15)
    if rc != 0:
        return False, f"SSH falhou: {err.strip() or out.strip() or rc}"
    if "OK" not in out:
        return False, "Destino não tem lvm2 + thin-provisioning-tools"
    return True, "OK"


def _create_thin_snapshot(vg: str, lv: str, snap_name: str) -> tuple[bool, str]:
    rc, out, err = _run([
        "lvcreate", "--snapshot",
        "--name", snap_name,
        f"{vg}/{lv}",
    ], timeout=30)
    if rc != 0:
        return False, f"lvcreate falhou: {err.strip() or out.strip()}"
    # Snapshots de volumes thin são read-write por padrão, mas vamos
    # garantir que está montável read-only durante a transferência
    _run(["lvchange", "--permission", "r", f"{vg}/{snap_name}"], timeout=10)
    return True, snap_name


def _remove_lv(vg: str, lv: str) -> None:
    _run(["lvremove", "-f", f"{vg}/{lv}"], timeout=30)


def _list_repl_snapshots(vg: str, base_lv: str) -> list[str]:
    """Lista snapshots criados pelo cockpit, ordenados do mais antigo
    para o mais novo (por nome — embute timestamp ISO)."""
    snaps = lvm.list_thin_volumes(vg=vg)
    prefix = f"{SNAPSHOT_PREFIX}_{base_lv}_"
    names = [s["name"] for s in snaps if s["name"].startswith(prefix)]
    return sorted(names)


def _rotate_snapshots(vg: str, base_lv: str, keep: int) -> None:
    """Mantém só os últimos N snapshots. Os mais antigos são removidos."""
    all_snaps = _list_repl_snapshots(vg, base_lv)
    # Mantém os últimos `keep`
    to_remove = all_snaps[:-keep] if keep > 0 else all_snaps
    for snap in to_remove:
        _remove_lv(vg, snap)


def _ensure_dest_lv(job: dict, src_size_b: int) -> tuple[bool, str]:
    """Garante que o LV destino existe e tem tamanho >= origem.

    Em primeira execução, cria o LV com `lvcreate -V <size> --thin -n <lv> -T <pool>`.
    """
    user = job["dest_user"]
    host = job["dest_host"]
    vg = job["dest_vg"]
    pool = job["dest_thin_pool"]
    lv = job["dest_lv"]

    # Verifica se existe
    rc, out, err = _run(_ssh_cmd(
        user, host,
        f"lvs --noheadings -o lv_name {shlex.quote(vg)}/{shlex.quote(lv)}",
    ), timeout=15)
    if rc == 0 and lv in out:
        return True, "destino já existe"

    # Cria
    size_str = f"{src_size_b}b"
    cmd = (
        f"lvcreate -V {shlex.quote(size_str)} "
        f"--thin -n {shlex.quote(lv)} {shlex.quote(vg)}/{shlex.quote(pool)}"
    )
    rc, out, err = _run(_ssh_cmd(user, host, cmd), timeout=60)
    if rc != 0:
        return False, f"lvcreate destino falhou: {err.strip() or out.strip()}"
    return True, f"LV criado: {vg}/{lv}"


def run_job(job_id: int) -> dict:
    """Executa um job de replicação. Retorna {ok, message, run_id}."""
    if not lvm.has_lvm():
        return {"ok": False, "message": "LVM não disponível neste host."}
    if not lvm.has_thin_tools():
        return {"ok": False, "message": "thin-provisioning-tools ausente."}

    with db.connect() as conn:
        row = conn.execute(
            "SELECT * FROM replication_jobs WHERE id = ?", (job_id,),
        ).fetchone()
    if not row:
        return {"ok": False, "message": f"job {job_id} não encontrado"}

    job = dict(row)
    started_at = _now()
    new_snap = _snapshot_name(job["source_lv"])
    prev_snap = job["last_snapshot"]
    mode = "incremental" if prev_snap else "full"

    # Registra início do run
    with db.connect() as conn:
        cur = conn.execute(
            "INSERT INTO replication_runs "
            "(job_id, started_at, status, snapshot_name, mode) "
            "VALUES (?, ?, 'running', ?, ?)",
            (job_id, started_at, new_snap, mode),
        )
        run_id = cur.lastrowid

    def _finish(ok: bool, msg: str, bytes_sent: int = 0):
        finished = _now()
        status = "ok" if ok else "error"
        with db.connect() as conn:
            conn.execute(
                "UPDATE replication_runs SET finished_at=?, status=?, "
                "bytes_sent=?, error_message=? WHERE id=?",
                (finished, status, bytes_sent, msg if not ok else None, run_id),
            )
            updates = "last_run_at=?, last_run_status=?, last_error=?"
            params = [finished, status, msg if not ok else None]
            if ok:
                updates += ", last_snapshot=?"
                params.append(new_snap)
            updates += ", updated_at=?"
            params.append(finished)
            params.append(job_id)
            conn.execute(
                f"UPDATE replication_jobs SET {updates} WHERE id=?", params,
            )
        return {"ok": ok, "message": msg, "run_id": run_id}

    # 1) Cria snapshot fonte
    ok, snap_or_err = _create_thin_snapshot(
        job["source_vg"], job["source_lv"], new_snap,
    )
    if not ok:
        return _finish(False, snap_or_err)

    try:
        # 2) Garante LV destino
        # Pega tamanho do volume fonte
        src_volumes = lvm.list_thin_volumes(
            vg=job["source_vg"], pool=job["source_thin_pool"],
        )
        src_info = next(
            (v for v in src_volumes if v["name"] == job["source_lv"]), None,
        )
        if not src_info:
            return _finish(False, "volume fonte sumiu durante a operação")

        ok, msg = _ensure_dest_lv(job, src_info["size_b"])
        if not ok:
            return _finish(False, msg)

        # 3) Pipe: thin_send local | ssh dest "thin_recv"
        # Usa o block device dos snapshots
        src_dev = f"/dev/{job['source_vg']}/{new_snap}"
        dest_dev = f"/dev/{job['dest_vg']}/{job['dest_lv']}"

        if mode == "incremental" and prev_snap:
            # thin_send com 2 snapshots = só o delta
            local = ["thin_send", f"/dev/{job['source_vg']}/{prev_snap}", src_dev]
        else:
            local = ["thin_send", src_dev]

        remote = (
            f"thin_recv {shlex.quote(dest_dev)}"
        )
        ssh = _ssh_cmd(job["dest_user"], job["dest_host"], remote)

        # Pipe thin_send | ssh ... thin_recv
        proc_send = subprocess.Popen(
            local, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        proc_recv = subprocess.Popen(
            ssh, stdin=proc_send.stdout, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if proc_send.stdout:
            proc_send.stdout.close()  # permite ao send receber SIGPIPE
        recv_out, recv_err = proc_recv.communicate(timeout=3600)
        send_err = proc_send.stderr.read().decode(errors="replace") if proc_send.stderr else ""
        proc_send.wait(timeout=10)

        if proc_send.returncode != 0:
            return _finish(False, f"thin_send falhou: {send_err.strip()}")
        if proc_recv.returncode != 0:
            return _finish(
                False,
                f"thin_recv (remoto) falhou: {recv_err.decode(errors='replace').strip()}",
            )

        bytes_sent = src_info["size_b"]  # aproximação; tracking real em fase 2

        # 4) Rotaciona snapshots na origem
        try:
            _rotate_snapshots(
                job["source_vg"], job["source_lv"], job["keep_snapshots"],
            )
        except Exception as e:
            log.warning("rotação de snapshots falhou: %s", e)

        return _finish(
            True,
            f"replicado {mode} ({job['source_vg']}/{new_snap} → "
            f"{job['dest_host']}:{job['dest_vg']}/{job['dest_lv']})",
            bytes_sent=bytes_sent,
        )

    except subprocess.TimeoutExpired:
        return _finish(False, "timeout (>1h) na transferência")
    except Exception as e:
        log.exception("run_job %s falhou", job_id)
        return _finish(False, f"erro inesperado: {e}")
