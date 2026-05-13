"""Utilitários de mount/fstab. Usado por /iscsi e /nvmeof.

Princípios:
- mkfs NÃO é coberto aqui (destrutivo demais — exige fluxo separado).
- Para iSCSI/NVMe-oF, options default incluem `_netdev,nofail`:
    _netdev  — espera rede subir antes de tentar montar (systemd).
    nofail   — boot não falha se montagem falhar.
"""
import os
import shutil
import subprocess
import time
from pathlib import Path

FSTAB = Path("/etc/fstab")
FSTAB_BAK_PREFIX = "/etc/fstab.cockpit.bak."
DEFAULT_NETDEV_OPTS = "_netdev,nofail,x-systemd.device-timeout=30s"


def _run(cmd: list[str], timeout: int = 15) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "command not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def blkid(device: str) -> dict:
    """blkid -o export <device>"""
    if not device:
        return {}
    rc, out, _ = _run(["blkid", "-o", "export", device], timeout=5)
    if rc != 0:
        return {}
    info = {}
    for line in out.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            info[k.strip().lower()] = v.strip()
    return info


def is_mounted(dev_or_mp: str) -> bool:
    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 2:
                    continue
                if parts[0] == dev_or_mp or parts[1] == dev_or_mp:
                    return True
    except OSError:
        pass
    return False


def current_mounts() -> list[dict]:
    rows = []
    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 4:
                    continue
                rows.append({
                    "device": parts[0],
                    "mountpoint": parts[1],
                    "fstype": parts[2],
                    "options": parts[3],
                })
    except OSError:
        pass
    return rows


def mountpoint_of(device: str) -> str | None:
    for m in current_mounts():
        if m["device"] == device:
            return m["mountpoint"]
    return None


def fstab_lines() -> list[dict]:
    """Parseia /etc/fstab em lista de dicts."""
    rows = []
    try:
        text = FSTAB.read_text()
    except OSError:
        return rows
    for n, line in enumerate(text.splitlines(), start=1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split()
        if len(parts) < 4:
            continue
        rows.append({
            "lineno": n,
            "device": parts[0],
            "mountpoint": parts[1],
            "fstype": parts[2],
            "options": parts[3],
            "dump": parts[4] if len(parts) > 4 else "0",
            "fsck": parts[5] if len(parts) > 5 else "0",
        })
    return rows


def _backup_fstab() -> str | None:
    if not FSTAB.exists():
        return None
    bk = f"{FSTAB_BAK_PREFIX}{int(time.time())}"
    try:
        shutil.copy2(FSTAB, bk)
        os.chmod(bk, 0o600)
        return bk
    except OSError:
        return None


def fstab_add(device: str, mountpoint: str, fstype: str,
              options: str = DEFAULT_NETDEV_OPTS,
              dump: str = "0", fsck: str = "0",
              tag: str = "cockpit") -> tuple[bool, str]:
    """Adiciona linha no /etc/fstab. Faz backup antes."""
    bk = _backup_fstab()
    if not bk:
        return False, "falha ao criar backup de /etc/fstab"
    try:
        existing = FSTAB.read_text() if FSTAB.exists() else ""
    except OSError as e:
        return False, f"leitura falhou: {e}"

    # Remove qualquer linha pré-existente do mesmo device/mp para evitar
    # duplicata.
    out_lines = []
    for line in existing.splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            parts = s.split()
            if len(parts) >= 2 and (parts[0] == device or parts[1] == mountpoint):
                continue  # remove duplicata
        out_lines.append(line)
    if out_lines and out_lines[-1].strip() != "":
        out_lines.append("")
    out_lines.append(f"# Added by {tag}")
    out_lines.append(f"{device} {mountpoint} {fstype} {options} {dump} {fsck}")
    content = "\n".join(out_lines) + "\n"

    try:
        tmp = str(FSTAB) + ".cockpit.tmp"
        with open(tmp, "w") as f:
            f.write(content)
        os.chmod(tmp, 0o644)
        os.replace(tmp, str(FSTAB))
    except OSError as e:
        return False, f"escrita falhou: {e}"
    return True, f"/etc/fstab atualizado · backup: {bk}"


def fstab_remove(device_or_mp: str) -> tuple[bool, str]:
    """Remove linhas que casam com o device ou mountpoint."""
    bk = _backup_fstab()
    if not bk:
        return False, "falha ao criar backup de /etc/fstab"
    try:
        text = FSTAB.read_text()
    except OSError as e:
        return False, f"leitura falhou: {e}"
    out_lines = []
    removed = 0
    for line in text.splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            parts = s.split()
            if len(parts) >= 2 and (parts[0] == device_or_mp
                                     or parts[1] == device_or_mp):
                removed += 1
                continue
        out_lines.append(line)
    if removed == 0:
        return False, "nenhuma linha casou — nada removido"
    try:
        tmp = str(FSTAB) + ".cockpit.tmp"
        with open(tmp, "w") as f:
            f.write("\n".join(out_lines) + "\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, str(FSTAB))
    except OSError as e:
        return False, f"escrita falhou: {e}"
    return True, f"{removed} linha(s) removida(s) · backup: {bk}"


def mount_device(device: str, mountpoint: str, fstype: str | None = None,
                 options: str = DEFAULT_NETDEV_OPTS,
                 persist: bool = True) -> tuple[bool, str]:
    """Cria mountpoint, monta o device e opcionalmente adiciona ao fstab."""
    if not os.path.exists(device):
        return False, f"device {device} não existe"
    if is_mounted(device):
        return False, f"{device} já está montado em {mountpoint_of(device)}"
    try:
        os.makedirs(mountpoint, exist_ok=True)
    except OSError as e:
        return False, f"falha ao criar {mountpoint}: {e}"

    # Auto-detecta filesystem se não informado
    if not fstype:
        info = blkid(device)
        fstype = info.get("type")
        if not fstype:
            return False, ("não consegui detectar filesystem em "
                           f"{device}. Use 'blkid {device}' ou formate "
                           "antes de montar.")

    cmd = ["mount", "-t", fstype, "-o", options, device, mountpoint]
    rc, out, err = _run(cmd, timeout=30)
    if rc != 0:
        return False, f"mount falhou: {err.strip() or out.strip()}"

    if persist:
        ok, msg = fstab_add(device, mountpoint, fstype, options=options)
        return ok, f"montado em {mountpoint} · {msg}"
    return True, f"montado em {mountpoint} (não persistido)"


def umount_target(target: str, remove_fstab: bool = False) -> tuple[bool, str]:
    """Desmonta target (device ou mountpoint). Opcionalmente remove do fstab."""
    rc, out, err = _run(["umount", target], timeout=30)
    if rc != 0:
        return False, f"umount falhou: {err.strip() or out.strip()}"
    msg = f"desmontado: {target}"
    if remove_fstab:
        ok, m2 = fstab_remove(target)
        msg += f" · fstab: {m2}"
    return True, msg
