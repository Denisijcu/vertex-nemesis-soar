"""Vertex Nemesis SOAR v1.2 — gateway de contención con grounding verificado
y aprobación humana para las alertas AMARILLO.

Flujo de cada alerta:
  1. El modelo (LM Studio) propone una herramienta o se abstiene.
  2. Si el modelo dice ABSTENTION, se respeta SIEMPRE, traiga lo que traiga.
  3. La herramienta tiene que estar en la lista blanca del servidor.
  4. El código verifica que los argumentos salgan del [CONTEXTO] (grounding).
  5. Si la acción apunta a una IP protegida, se rechaza ahí mismo.
  6. Severidad: ROJO se ejecuta, AMARILLO queda pendiente del operador, VERDE no toca nada.
  7. defense_ops aplica la red de seguridad (expiración, solo reglas VTX_).
  8. Todo, incluidos los fallos y las decisiones humanas, queda en el ledger encadenado.
"""
import json
import re
from contextlib import asynccontextmanager

from fastapi import Body, FastAPI, Header, HTTPException
from openai import OpenAI
from pydantic import BaseModel

from core import approvals, defense_ops, vault
from core.config import FORCE_DRY_RUN, LM_STUDIO_URL, VERTEX_MODEL
from core.grounding import verify_tool_call

VERSION = "1.2.0"

client = OpenAI(base_url=LM_STUDIO_URL, api_key="not-needed")

# System prompt de la v1.0, sin tocar: es el que se probó en vivo con el modelo.
# En esta fase solo se cambia el código alrededor (una cosa a la vez).
VERTEX_SYSTEM_PROMPT = (
    "Eres Vertex-Core-Grounded, motor de inteligencia ofensiva, MCP y análisis RAG/SQL de Vertex Coders LLC. "
    "Analiza exclusivamente los datos dentro de [CONTEXTO] y [ESQUEMA_MCP_O_SQL]. "
    "Si todos los datos requeridos están presentes, devuelve el JSON de llamada a la herramienta. "
    "Si falta un dato crítico (como la IP o CVE que no aparece en el contexto), abstente devolviendo: "
    '{"status": "ABSTENTION_INSUFFICIENT_DATA", "missing_info": "Dato faltante en el contexto"}. '
    "Responde EXCLUSIVAMENTE con un objeto JSON válido, sin texto adicional."
)

DEFAULT_SCHEMA = "Herramientas disponibles: " + "; ".join(defense_ops.MODEL_TOOLS.values())


class TelemetryAlert(BaseModel):
    context: str
    question: str
    schema_def: str | None = None  # si no viene, el servidor pone su propio esquema
    dry_run: bool = True           # por defecto NO toca el firewall
    severity: str = "AMARILLO"     # ROJO | AMARILLO | VERDE; por defecto pide aprobación


class Decision(BaseModel):
    note: str = ""


def _require_operator(token: str | None) -> None:
    if not approvals.token_ok(token):
        raise HTTPException(status_code=403, detail="falta o es incorrecto X-Operator-Token")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    vault.init_vault()
    approvals.load_operator_token()
    defense_ops.protected_ips(refresh=True)
    defense_ops.expire_blocks()
    approvals.expire_pending()
    yield


app = FastAPI(
    title="Vertex Nemesis SOAR Engine",
    description="Contención autónoma con grounding verificado, impulsada por Vertex-Core-Grounded",
    version=VERSION,
    lifespan=lifespan,
)


# ---------------------------------------------------------------- modelo

def get_active_model_id() -> str:
    """VERTEX_MODEL si está puesto; si no, el primer modelo cargado que diga 'vertex'."""
    if VERTEX_MODEL:
        return VERTEX_MODEL
    try:
        ids = [m.id for m in client.models.list().data]
        for mid in ids:
            if "vertex" in mid.lower() and "embed" not in mid.lower():
                return mid
        for mid in ids:
            if "embed" not in mid.lower():
                return mid
    except Exception:
        pass
    return "vertex-qwen35-4b-grounded"


def call_model(system_prompt: str, user_payload: str) -> tuple[str, str]:
    model_id = get_active_model_id()
    response = client.chat.completions.create(
        model=model_id,
        messages=[{"role": "system", "content": system_prompt},
                  {"role": "user", "content": user_payload}],
        temperature=0.0,
        max_tokens=300,
    )
    return model_id, response.choices[0].message.content or ""


def extract_json_safely(raw_text: str) -> dict:
    """Primer objeto JSON válido; entiende <think>, <tool_call> (Hermes/Qwen3) y Markdown."""
    if not raw_text or not raw_text.strip():
        raise ValueError("respuesta vacía del modelo (¿está cargado en LM Studio?)")
    cleaned = re.sub(r"<think>.*?</think>", "", raw_text, flags=re.DOTALL)
    tool_tag = re.search(r"<tool_call>(.*?)</tool_call>", cleaned, flags=re.DOTALL)
    if tool_tag:
        cleaned = tool_tag.group(1)
    decoder = json.JSONDecoder()
    for pos, ch in enumerate(cleaned):
        if ch == "{":
            try:
                obj, _ = decoder.raw_decode(cleaned[pos:])
                if isinstance(obj, dict):
                    return obj
            except json.JSONDecodeError:
                continue
    raise ValueError(f"no hay JSON válido en la salida del modelo: {raw_text[:200]!r}")


def parse_decision(parsed: dict) -> dict:
    """Traduce los formatos que suelta el modelo a {abstained, tool, args, evidence, domain}."""
    model_status = str(parsed.get("status", "")).upper()
    decision = {
        "model_status": model_status or None,
        "abstained": model_status.startswith("ABSTENTION"),
        "tool": None,
        "args": {},
        "evidence": parsed.get("evidence_quote"),
        "domain": parsed.get("domain", "CYBER_MCP"),
    }
    if decision["abstained"]:
        return decision  # la abstención manda: no se busca ninguna herramienta

    nested = parsed.get("mcp_tool_call") or parsed.get("tool_call")
    if isinstance(nested, dict):
        decision["tool"] = nested.get("tool") or nested.get("name")
        decision["args"] = nested.get("arguments") or nested.get("parameters") or {}
    elif "tool" in parsed:
        decision["tool"] = parsed.get("tool")
        decision["args"] = parsed.get("arguments") or parsed.get("parameters") or {}
    elif "action" in parsed:
        decision["tool"] = parsed.get("action")
        decision["args"] = parsed.get("parameters") or parsed.get("arguments") or {}
    elif "name" in parsed and ("arguments" in parsed or "parameters" in parsed):
        decision["tool"] = parsed.get("name")  # formato Hermes de Qwen3
        decision["args"] = parsed.get("arguments") or parsed.get("parameters") or {}

    if isinstance(decision["args"], str):  # algunos modelos mandan los argumentos como texto JSON
        try:
            decision["args"] = json.loads(decision["args"])
        except json.JSONDecodeError:
            decision["args"] = {}
    if not decision["tool"]:
        decision["abstained"] = True  # sin herramienta clara no se ejecuta nada
    return decision


# ---------------------------------------------------------------- endpoints

@app.post("/api/v1/analyze-and-contain")
def analyze_and_contain(alert: TelemetryAlert):
    severity = approvals.normalize_severity(alert.severity)
    if not severity:
        raise HTTPException(status_code=422, detail="severity debe ser ROJO, AMARILLO o VERDE")
    defense_ops.expire_blocks()
    approvals.expire_pending()
    dry_run = alert.dry_run or FORCE_DRY_RUN
    user_payload = (
        f"[CONTEXTO] {alert.context}\n"
        f"[ESQUEMA_MCP_O_SQL] {alert.schema_def or DEFAULT_SCHEMA}\n\n"
        f"[PREGUNTA]: {alert.question}"
    )

    try:
        model_id, raw_output = call_model(VERTEX_SYSTEM_PROMPT, user_payload)
        print(f"\n📥 [LM STUDIO RAW ({model_id})]: {raw_output}")
        parsed = extract_json_safely(raw_output)
    except Exception as e:
        receipt = vault.log_forensic_event("CYBER_MCP", "ERROR_MODEL_OUTPUT", "NONE", {},
                                           alert.context[:300], {"error": str(e)})
        raise HTTPException(status_code=502, detail={"error": str(e), "forensic_receipt": receipt})

    d = parse_decision(parsed)
    grounding = None
    execution = {"result": "ABSTAINED_NO_EXECUTION"}

    if d["abstained"]:
        status = "ABSTENTION_INSUFFICIENT_DATA"
    elif d["tool"] not in defense_ops.MODEL_TOOLS:
        status = "REJECTED_UNAUTHORIZED_TOOL"
        execution = {"result": "REJECTED_UNAUTHORIZED_TOOL", "tool": d["tool"]}
    else:
        grounding = verify_tool_call(d["tool"], d["args"], alert.context, d["evidence"])
        if not grounding["grounded"]:
            status = "REJECTED_UNGROUNDED"
            execution = {"result": "REJECTED_UNGROUNDED", "detail": grounding["reason"]}
        else:
            protected = None
            if d["tool"] == "block_firewall_ip":
                protected = defense_ops.protection_reason(str(d["args"].get("ip_address", "")).strip())
            decision = approvals.gate(d["tool"], severity)
            if protected:
                status = "REJECTED_PROTECTED_IP"
                execution = {"result": "REJECTED_PROTECTED_IP",
                             "ip": d["args"].get("ip_address"), "detail": protected}
            elif decision == "BLOCK_LOW_SEVERITY":
                status = "REJECTED_LOW_SEVERITY"
                execution = {"result": "REJECTED_LOW_SEVERITY",
                             "detail": f"una alerta {severity} no autoriza {d['tool']}"}
            elif decision == "PENDING":
                status = "PENDING_APPROVAL"
                execution = approvals.create_pending(severity, d["tool"], d["args"], alert.context,
                                                     grounding["evidence"], dry_run)
            else:
                execution = defense_ops.execute_mcp_action(d["tool"], d["args"], dry_run=dry_run)
                status = ("REJECTED_PROTECTED_IP" if execution["result"] == "REJECTED_PROTECTED_IP"
                          else "VERIFIED_OK")

    evidence = (grounding or {}).get("evidence") or d["evidence"] or ""
    receipt = vault.log_forensic_event(
        domain=d["domain"], status=status, tool=d["tool"] or "NONE", args=d["args"],
        evidence=evidence, exec_result={"execution": execution, "dry_run": dry_run,
                                        "severity": severity, "model": model_id,
                                        "grounding": grounding},
    )
    if execution.get("result") == "NETSH_RULE_APPLIED":
        vault.link_block_event(execution["rule_name"], receipt["event_id"])
    if status == "PENDING_APPROVAL":
        vault.link_pending_request(execution["action_id"], receipt["event_id"])

    return {
        "status": status,
        "severity": severity,
        "forensic_receipt": receipt,
        "model_decision": parsed,
        "grounding": grounding,
        "soar_execution": execution,
        "dry_run": dry_run,
    }


@app.get("/api/v1/ledger")
def get_audit_ledger(limit: int = 25):
    events = vault.read_ledger(limit=max(1, min(limit, 500)))
    return {"returned": len(events), "events": events}


@app.get("/api/v1/ledger/verify")
def verify_ledger():
    return vault.verify_chain()


@app.get("/api/v1/ledger/anchor")
def anchor_ledger():
    return vault.anchor_head()


@app.get("/api/v1/blocks")
def get_blocks(all: bool = False):
    return {"blocks": vault.list_blocks(only_active=not all)}


@app.delete("/api/v1/blocks/{rule_name}")
def human_unblock(rule_name: str, dry_run: bool = False,
                  x_operator_token: str | None = Header(default=None)):
    """Desbloqueo manual del operador. El modelo no tiene esta herramienta a propósito."""
    _require_operator(x_operator_token)
    result = defense_ops.unblock_rule(rule_name, dry_run=dry_run)
    receipt = vault.log_forensic_event("CYBER_MCP", "HUMAN_UNBLOCK", "unblock_firewall_ip",
                                       {"rule_name": rule_name}, "Acción manual del operador", result)
    return {"soar_execution": result, "forensic_receipt": receipt}


@app.get("/api/v1/pending")
def get_pending(all: bool = False):
    approvals.expire_pending()
    return {"pending": vault.list_pending(only_open=not all)}


def _decide(action_id: str, approve: bool, decision: Decision | None, token: str | None):
    _require_operator(token)
    code, body = approvals.decide(action_id, approve, (decision.note if decision else ""))
    if code != 200:
        raise HTTPException(status_code=code, detail=body)
    return body


@app.post("/api/v1/pending/{action_id}/approve")
def approve_pending(action_id: str, decision: Decision | None = Body(default=None),
                    x_operator_token: str | None = Header(default=None)):
    return _decide(action_id, True, decision, x_operator_token)


@app.post("/api/v1/pending/{action_id}/reject")
def reject_pending(action_id: str, decision: Decision | None = Body(default=None),
                   x_operator_token: str | None = Header(default=None)):
    return _decide(action_id, False, decision, x_operator_token)


@app.post("/api/v1/blocks/expire")
def run_expiry():
    return {"expired": defense_ops.expire_blocks()}


@app.get("/api/v1/health")
def health():
    return {"version": VERSION, "force_dry_run": FORCE_DRY_RUN,
            "pending_open": len(vault.list_pending(only_open=True)),
            "severity_rules": {"ROJO": "ejecuta", "AMARILLO": "pide aprobación",
                               "VERDE": "no toca el firewall"},
            "protected_ips": defense_ops.protected_ips(),
            "model_tools": list(defense_ops.MODEL_TOOLS)}
