import pam

ALLOWED_USERS = {"root"}
PAM_SERVICE = "login"


def authenticate(username: str, password: str) -> tuple[bool, str]:
    if username not in ALLOWED_USERS:
        return False, "Usuário não autorizado. Apenas root pode acessar."
    if not password:
        return False, "Senha obrigatória."
    p = pam.pam()
    ok = p.authenticate(username, password, service=PAM_SERVICE)
    if not ok:
        return False, "Credenciais inválidas."
    return True, ""
