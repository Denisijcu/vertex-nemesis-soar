"""Aprobación humana (fase 2.1).

Regla por severidad, solo para herramientas que CAMBIAN algo (hoy: block_firewall_ip):
  ROJO     -> se ejecuta en el momento (con todas las verificaciones de la v1.1).
  AMARILLO -> queda PENDIENTE; no se ejecuta hasta que el operador la apruebe.
  VERDE    -> no se ejecuta; una alerta informativa no justifica tocar el firewall.
Las herramientas de solo lectura (check_listening_ports) corren con cualquier severidad.

Aprobar o rechazar exige el token del operador (cabecera X-Operator-Token). Así ni el
modelo, ni otro programa local, ni una página web abierta en el navegador pueden aprobar
nada: el token vive en %USERPROFILE%\\.vertex\\soar_operator.token.

Al aprobar se vuelven a pasar las verificaciones (grounding sobre el contexto guardado,
IPs protegidas, bloqueo duplicado): entre la alerta y el clic puede haber cambiado algo.
"""
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from core import defense_ops, vault
from core.config import OPERATOR_TOKEN_PATH, PENDING_TTL_MINUTES
from core.grounding import verify_tool_call

SEVERITIES = {"ROJO": "ROJO", "RED": "ROJO",
              "AMARILLO": "AMARILLO", "YELLOW": "AMARILLO",
              "VERDE": "VERDE", "GREEN": "VERDE"}
MUTATING_TOOLS = {"block_firewall_ip"}


def normalize_severity(raw: str | None) -> str | None:
    return SEVERITIES.get(str(raw or "").strip().upper())


def load_operator_token() -> str:
    if not OPERATOR_TOKEN_PATH.exists():
        OPERATOR_TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
        OPERATOR_TOKEN_PATH.write_text(secrets.token_urlsafe(32), encoding="utf-8")
    return OPERATOR_TOKEN_PATH.read_text(encoding="utf-8").strip()


def token_ok(given: str | None) -> bool:
    return bool(given) and hmac.compare_digest(given.strip(), load_operator_token())


def gate(tool: str, severity: str) -> str:
    """Devuelve EXECUTE, PENDING o BLOCK_LOW_SEVERITY."""
    if tool not in MUTATING_TOOLS:
        return "EXECUTE"
    return {"ROJO": "EXECUTE", "AMARILLO": "PENDING"}.get(severity, "BLOCK_LOW_SEVERITY")


def create_pending(severity: str, tool: str, args: dict, context: str, evidence: str,
                   dry_run: bool) -> dict:
    now = datetime.now(timezone.utc)
    action_id = f"PND-{now.strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(3).upper()}"
    expires = now + timedelta(minutes=PENDING_TTL_MINUTES)
    vault.add_pending(action_id, now.isoformat(), expires.isoformat(), severity, tool, args,
                      context, evidence, dry_run)
    return {"result": "PENDING_APPROVAL", "action_id": action_id, "tool": tool,
            "arguments": args, "expires_at": expires.isoformat()}


def expire_pending() -> list[str]:
    now = datetime.now(timezone.utc)
    expired = []
    for p in vault.list_pending(only_open=True):
        if datetime.fromisoformat(p["expires_at"]) <= now:
            if vault.claim_pending(p["action_id"], "EXPIRED", now.isoformat(), "caducó sin decisión"):
                receipt = vault.log_forensic_event(
                    "CYBER_MCP", "PENDING_EXPIRED", p["tool"], p["arguments"], p["evidence"],
                    {"action_id": p["action_id"], "detail": "caducó sin decisión del operador"})
                vault.finish_pending(p["action_id"], receipt["event_id"], None)
                expired.append(p["action_id"])
    return expired


def decide(action_id: str, approve: bool, note: str = "") -> tuple[int, dict]:
    """Aprueba o rechaza. Devuelve (código HTTP, cuerpo)."""
    expire_pending()
    p = vault.get_pending(action_id)
    if not p:
        return 404, {"error": f"no existe la acción {action_id}"}
    if p["state"] != "PENDING":
        return 409, {"error": f"la acción {action_id} ya está {p['state']}", "state": p["state"]}

    now = datetime.now(timezone.utc).isoformat()
    new_state = "APPROVED" if approve else "REJECTED"
    if not vault.claim_pending(action_id, new_state, now, note):
        return 409, {"error": "otra decisión llegó primero"}

    if not approve:
        result = {"result": "HUMAN_REJECTED", "action_id": action_id}
        status = "HUMAN_REJECTED"
    else:
        grounding = verify_tool_call(p["tool"], p["arguments"], p["context"], None)
        if not grounding["grounded"]:
            result = {"result": "REJECTED_UNGROUNDED", "detail": grounding["reason"]}
        else:
            result = defense_ops.execute_mcp_action(p["tool"], p["arguments"], dry_run=p["dry_run"])
        status = "HUMAN_APPROVED"

    receipt = vault.log_forensic_event(
        "CYBER_MCP", status, p["tool"], p["arguments"], p["evidence"],
        {"action_id": action_id, "note": note, "execution": result, "dry_run": p["dry_run"],
         "request_event": p["request_event"]})
    vault.finish_pending(action_id, receipt["event_id"], result)
    if result.get("result") == "NETSH_RULE_APPLIED":
        vault.link_block_event(result["rule_name"], receipt["event_id"])
    return 200, {"action_id": action_id, "state": new_state, "soar_execution": result,
                 "forensic_receipt": receipt}
