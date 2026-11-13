"""Verificación de grounding: el modelo propone, el código verifica.

El prompt le pide al modelo que use solo lo que está en [CONTEXTO], pero eso
es una promesa. Aquí se comprueba: cada IP que el modelo quiera bloquear tiene
que aparecer literalmente en el contexto de la alerta. La [PREGUNTA] no cuenta
como fuente: es justo por donde entraría una orden inyectada.
"""
import ipaddress
import re

# Ojo: una IP al final de una frase lleva un punto detrás ("desde 10.0.0.5.").
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
_IPV6 = re.compile(r"(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![0-9a-fA-F:])")
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?;\n])\s+")


def _norm(text: str) -> str:
    return " ".join((text or "").split()).casefold()


def extract_ips(text: str) -> set[str]:
    found = set()
    for m in list(_IPV4.finditer(text or "")) + list(_IPV6.finditer(text or "")):
        try:
            found.add(str(ipaddress.ip_address(m.group(0))))
        except ValueError:
            pass
    return found


def sentence_with(text: str, needle: str) -> str:
    """Frase del contexto que contiene el dato, como evidencia calculada por el código."""
    for sentence in _SENTENCE_SPLIT.split(text or ""):
        if needle in sentence:
            return sentence.strip()
    return ""


def quote_in_context(quote: str, context: str) -> bool:
    return bool(quote) and _norm(quote) in _norm(context)


def verify_tool_call(tool: str, args: dict, context: str, model_evidence: str | None) -> dict:
    """Devuelve {"grounded": bool, "reason": str, "evidence": str, "model_evidence_verified": bool}."""
    model_ev_ok = quote_in_context(model_evidence or "", context)

    if tool == "check_listening_ports":
        return {"grounded": True, "reason": "herramienta de solo lectura, sin argumentos",
                "evidence": sentence_with(context, "") or context[:200],
                "model_evidence_verified": model_ev_ok}

    if tool == "block_firewall_ip":
        raw_ip = str((args or {}).get("ip_address", "")).strip()
        try:
            ip = str(ipaddress.ip_address(raw_ip))
        except ValueError:
            return {"grounded": False, "reason": f"IP inválida propuesta por el modelo: {raw_ip!r}",
                    "evidence": "", "model_evidence_verified": model_ev_ok}
        if ip not in extract_ips(context):
            return {"grounded": False,
                    "reason": f"la IP {ip} no aparece en el [CONTEXTO] de la alerta",
                    "evidence": "", "model_evidence_verified": model_ev_ok}
        return {"grounded": True, "reason": f"IP {ip} presente en el contexto",
                "evidence": sentence_with(context, raw_ip) or sentence_with(context, ip),
                "model_evidence_verified": model_ev_ok}

    return {"grounded": False, "reason": f"herramienta sin regla de grounding: {tool}",
            "evidence": "", "model_evidence_verified": model_ev_ok}
