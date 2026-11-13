"""Contención activa en Windows 11 (netsh) con red de seguridad.

- El modelo solo puede usar MODEL_TOOLS. Desbloquear es cosa de humanos
  (endpoint DELETE /api/v1/blocks/{rule}), para que un log envenenado no
  pueda pedirle al modelo que quite un bloqueo.
- IPs protegidas: loopback, 0.0.0.0, multicast, broadcast, link-local, las IPs
  de esta máquina, la puerta de enlace y las de VERTEX_PROTECTED_IPS.
- Cada bloqueo lleva expiración (VERTEX_BLOCK_TTL_MINUTES) y queda registrado
  en active_blocks para poder deshacerlo.
- El SOAR solo crea y borra reglas con el prefijo VTX_.
"""
import ipaddress
import re
import socket
import subprocess
from datetime import datetime, timedelta, timezone

from core import vault
from core.config import (BLOCK_TTL_MINUTES, EXTRA_PROTECTED_IPS, FORCE_DRY_RUN,
                         IS_WINDOWS, RULE_PREFIX)

MODEL_TOOLS = {
    "block_firewall_ip": "block_firewall_ip(ip_address: str, rule_name: str) — aísla una IP hostil "
                         "(entrada y salida) en Windows Firewall, con expiración automática.",
    "check_listening_ports": "check_listening_ports() — lista los puertos locales en escucha.",
}

_protected_cache: dict[str, str] | None = None


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, shell=False, timeout=30)


def _local_ips() -> set[str]:
    ips = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ips.add(str(ipaddress.ip_address(info[4][0].split("%")[0])))
    except (OSError, ValueError):
        pass
    return ips


def _default_gateways() -> set[str]:
    """Lee la ruta por defecto de 'route print' (no depende del idioma de Windows)."""
    if not IS_WINDOWS:
        return set()
    gateways = set()
    try:
        out = _run(["route", "print", "-4"]).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                try:
                    gateways.add(str(ipaddress.ip_address(parts[2])))
                except ValueError:
                    pass  # "On-link" / "En vínculo"
    except (OSError, subprocess.TimeoutExpired):
        pass
    return gateways


def protected_ips(refresh: bool = False) -> dict[str, str]:
    global _protected_cache
    if _protected_cache is None or refresh:
        table = {}
        for ip in _local_ips():
            table[ip] = "IP de esta máquina"
        for ip in _default_gateways():
            table[ip] = "puerta de enlace por defecto"
        for raw in EXTRA_PROTECTED_IPS:
            try:
                table[str(ipaddress.ip_address(raw))] = "VERTEX_PROTECTED_IPS"
            except ValueError:
                pass
        _protected_cache = table
    return _protected_cache


def protection_reason(ip: str) -> str | None:
    addr = ipaddress.ip_address(ip)
    if addr.is_loopback:
        return "loopback"
    if addr.is_unspecified:
        return "dirección no especificada (bloquearía todo)"
    if addr.is_multicast:
        return "multicast"
    if addr.is_link_local:
        return "link-local"
    if addr.version == 4 and ip == "255.255.255.255":
        return "broadcast"
    if addr.is_reserved:
        return "rango reservado"
    return protected_ips().get(ip)


def _clean_rule_name(raw: str, ip: str) -> str:
    base = "".join(c for c in str(raw or "") if c.isalnum() or c in ("_", "-"))[:40] or "BLOCK"
    if base.upper().startswith(RULE_PREFIX):
        base = base[len(RULE_PREFIX):]
    ip_tag = re.sub(r"[^0-9a-fA-F]", "-", ip)
    return f"{RULE_PREFIX}{base}_{ip_tag}"


def block_ip(ip: str, rule_hint: str, dry_run: bool, event_ref: str = "") -> dict:
    ip = str(ipaddress.ip_address(ip))
    reason = protection_reason(ip)
    if reason:
        return {"result": "REJECTED_PROTECTED_IP", "ip": ip, "detail": reason}

    existing = vault.find_active_block(ip)
    if existing:
        return {"result": "ALREADY_BLOCKED", "ip": ip, "rule_name": existing[0],
                "expires_at": existing[1]}

    rule = _clean_rule_name(rule_hint, ip)
    cmds = [
        ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule}",
         "dir=in", "action=block", f"remoteip={ip}"],
        ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule}",
         "dir=out", "action=block", f"remoteip={ip}"],
    ]
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=BLOCK_TTL_MINUTES)

    if dry_run or FORCE_DRY_RUN:
        return {"result": "DRY_RUN_OK", "ip": ip, "rule_name": rule,
                "would_expire_at": expires.isoformat(),
                "commands": [" ".join(c) for c in cmds]}

    errors = []
    for cmd in cmds:
        res = _run(cmd)
        if res.returncode != 0:
            errors.append(res.stdout.strip() or res.stderr.strip())
    if errors:
        _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule}"])  # sin reglas a medias
        return {"result": "NETSH_FAILED", "ip": ip, "rule_name": rule,
                "detail": " | ".join(errors) + " (¿PowerShell como administrador?)"}

    vault.add_block(rule, ip, now.isoformat(), expires.isoformat(), event_ref)
    return {"result": "NETSH_RULE_APPLIED", "ip": ip, "rule_name": rule,
            "expires_at": expires.isoformat()}


def unblock_rule(rule_name: str, dry_run: bool = False) -> dict:
    if not rule_name.startswith(RULE_PREFIX):
        return {"result": "REJECTED_FOREIGN_RULE",
                "detail": f"solo se borran reglas creadas por el SOAR ({RULE_PREFIX}*)"}
    row = vault.get_block(rule_name)
    if not row or row[4] != "ACTIVE":
        return {"result": "NOT_FOUND", "detail": f"no hay bloqueo activo llamado {rule_name}"}
    cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
    if dry_run or FORCE_DRY_RUN:
        return {"result": "DRY_RUN_OK", "rule_name": rule_name, "commands": [" ".join(cmd)]}
    res = _run(cmd)
    if res.returncode != 0:
        return {"result": "NETSH_FAILED", "rule_name": rule_name,
                "detail": res.stdout.strip() or res.stderr.strip()}
    vault.set_block_state(rule_name, "REMOVED")
    return {"result": "NETSH_RULE_REMOVED", "rule_name": rule_name, "ip": row[1]}


def expire_blocks() -> list[dict]:
    """Quita los bloqueos vencidos. Se llama al arrancar, en cada alerta y a mano."""
    now = datetime.now(timezone.utc)
    done = []
    for block in vault.list_blocks(only_active=True):
        if datetime.fromisoformat(block["expires_at"]) <= now:
            result = unblock_rule(block["rule_name"])
            if result["result"] == "NETSH_RULE_REMOVED":
                vault.set_block_state(block["rule_name"], "EXPIRED")
                vault.log_forensic_event("CYBER_MCP", "AUTO_EXPIRE", "unblock_firewall_ip",
                                         {"rule_name": block["rule_name"], "ip": block["ip"]},
                                         f"Expiración del bloqueo creado en {block['created_at']}",
                                         result)
            done.append(result)
    return done


def check_listening_ports() -> dict:
    res = _run(["netstat", "-ano"])
    ports = []
    for line in res.stdout.splitlines():
        # Windows en inglés dice LISTENING; en español, ESCUCHANDO
        if "LISTENING" in line or "ESCUCHANDO" in line:
            parts = line.split()
            if len(parts) >= 5:
                ports.append({"proto": parts[0], "local": parts[1], "pid": parts[-1]})
    exposed = [p for p in ports if p["local"].startswith(("0.0.0.0:", "[::]:"))]
    return {"result": "PORTS_AUDITED", "listening": len(ports),
            "exposed_all_interfaces": exposed[:25], "sample": ports[:25]}


def execute_mcp_action(tool_name: str, args: dict, dry_run: bool = False) -> dict:
    if tool_name not in MODEL_TOOLS:
        return {"result": "REJECTED_UNAUTHORIZED_TOOL", "tool": tool_name}
    if tool_name == "block_firewall_ip":
        return block_ip(args.get("ip_address", ""), args.get("rule_name", ""), dry_run)
    if tool_name == "check_listening_ports":
        return check_listening_ports()
    return {"result": "NO_OP"}
