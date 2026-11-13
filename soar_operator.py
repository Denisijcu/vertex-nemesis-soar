"""Consola del operador de Vertex Nemesis SOAR.

Uso, desde la carpeta del proyecto y con el venv activado:
    python soar_operator.py pendientes
    python soar_operator.py aprobar PND-...   "motivo opcional"
    python soar_operator.py rechazar PND-...  "motivo opcional"
    python soar_operator.py bloqueos
    python soar_operator.py desbloquear VTX_...

Lee el token de %USERPROFILE%\\.vertex\\soar_operator.token (lo crea el gateway al arrancar).
"""
import json
import sys

import requests

from core.config import OPERATOR_TOKEN_PATH

BASE_URL = "http://127.0.0.1:8000/api/v1"


def _headers() -> dict:
    if not OPERATOR_TOKEN_PATH.exists():
        sys.exit(f"❌ No existe {OPERATOR_TOKEN_PATH}. Arranca el gateway una vez para que lo cree.")
    return {"X-Operator-Token": OPERATOR_TOKEN_PATH.read_text(encoding="utf-8").strip()}


def _show(r: requests.Response) -> int:
    try:
        body = r.json()
    except ValueError:
        body = r.text
    print(json.dumps(body, indent=2, ensure_ascii=False))
    return 0 if r.ok else 1


def pendientes() -> int:
    items = requests.get(f"{BASE_URL}/pending", timeout=10).json()["pending"]
    if not items:
        print("✅ No hay acciones pendientes.")
        return 0
    print(f"{len(items)} acción(es) esperando decisión:\n")
    for p in items:
        print(f"  {p['action_id']}  [{p['severity']}]  {p['tool']} {json.dumps(p['arguments'], ensure_ascii=False)}")
        print(f"      evidencia : {p['evidence']}")
        print(f"      caduca    : {p['expires_at']}   dry_run={p['dry_run']}\n")
    return 0


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 1
    cmd, rest = argv[0].lower(), argv[1:]
    try:
        if cmd == "pendientes":
            return pendientes()
        if cmd in ("aprobar", "rechazar") and rest:
            accion = "approve" if cmd == "aprobar" else "reject"
            note = rest[1] if len(rest) > 1 else ""
            return _show(requests.post(f"{BASE_URL}/pending/{rest[0]}/{accion}",
                                       headers=_headers(), json={"note": note}, timeout=60))
        if cmd == "bloqueos":
            return _show(requests.get(f"{BASE_URL}/blocks", timeout=10))
        if cmd == "desbloquear" and rest:
            return _show(requests.delete(f"{BASE_URL}/blocks/{rest[0]}", headers=_headers(), timeout=30))
    except requests.exceptions.ConnectionError:
        print("❌ El gateway no está corriendo en 127.0.0.1:8000.")
        return 1
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
