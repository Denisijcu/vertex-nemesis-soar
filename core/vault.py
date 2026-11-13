"""Bóveda forense de Vertex Nemesis SOAR — ledger encadenado y sellado.

Cada evento guarda el hash del evento anterior (cadena tipo blockchain) y un
HMAC-SHA256 con una clave que no vive en la base de datos. Si alguien cambia,
borra o reordena una fila, verify_chain() lo detecta.

Límite honesto: un atacante que tenga a la vez el .duckdb Y la clave puede
reescribir la cadena entera. Para eso está anchor_head(): publicar el último
hash en un sitio externo (un commit, un correo) fija el estado del ledger.
"""
import hashlib
import hmac
import json
import secrets
import threading
from datetime import datetime, timezone

import duckdb

from core.config import DB_PATH, KEY_PATH

GENESIS_HASH = "0" * 64
_lock = threading.Lock()  # FastAPI atiende en varios hilos: una escritura a la vez


def _connect():
    return duckdb.connect(str(DB_PATH))


def _load_key() -> bytes:
    if not KEY_PATH.exists():
        KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
        KEY_PATH.write_text(secrets.token_hex(32), encoding="utf-8")
    return bytes.fromhex(KEY_PATH.read_text(encoding="utf-8").strip())


def _canonical(record: dict) -> str:
    return json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _seal(prev_hash: str, record: dict, key: bytes) -> tuple[str, str]:
    sha = hashlib.sha256((prev_hash + _canonical(record)).encode("utf-8")).hexdigest().upper()
    mac = hmac.new(key, sha.encode("utf-8"), hashlib.sha256).hexdigest().upper()
    return sha, mac


def init_vault() -> None:
    _load_key()
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS soar_ledger (
                seq              INTEGER PRIMARY KEY,
                event_id         VARCHAR,
                ts               VARCHAR,
                domain           VARCHAR,
                status           VARCHAR,
                tool_executed    VARCHAR,
                arguments_json   VARCHAR,
                evidence_quote   VARCHAR,
                execution_result VARCHAR,
                prev_hash        VARCHAR,
                sha256_seal      VARCHAR,
                hmac_seal        VARCHAR
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS active_blocks (
                rule_name  VARCHAR PRIMARY KEY,
                ip         VARCHAR,
                created_at VARCHAR,
                expires_at VARCHAR,
                state      VARCHAR,
                event_id   VARCHAR
            )
        """)


def log_forensic_event(domain: str, status: str, tool: str, args: dict,
                       evidence: str, exec_result) -> dict:
    """Agrega un evento al final de la cadena y devuelve el recibo."""
    key = _load_key()
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "domain": domain,
        "status": status,
        "tool": tool,
        "arguments": args or {},
        "evidence": evidence or "",
        "result": exec_result if isinstance(exec_result, str) else _canonical(exec_result),
    }
    with _lock, _connect() as conn:
        last = conn.execute(
            "SELECT seq, sha256_seal FROM soar_ledger ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        seq = (last[0] + 1) if last else 1
        prev_hash = last[1] if last else GENESIS_HASH
        record["seq"] = seq
        sha, mac = _seal(prev_hash, record, key)
        event_id = f"VTX-{seq:06d}-{sha[:8]}"
        conn.execute(
            "INSERT INTO soar_ledger VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (seq, event_id, record["ts"], domain, status, tool,
             _canonical(record["arguments"]), record["evidence"], record["result"],
             prev_hash, sha, mac),
        )
    return {"event_id": event_id, "seq": seq, "sha256_seal": sha, "prev_hash": prev_hash,
            "timestamp": record["ts"]}


def verify_chain() -> dict:
    """Recorre el ledger completo y dice si alguien lo tocó."""
    key = _load_key()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT seq, event_id, ts, domain, status, tool_executed, arguments_json, "
            "evidence_quote, execution_result, prev_hash, sha256_seal, hmac_seal "
            "FROM soar_ledger ORDER BY seq"
        ).fetchall()

    expected_prev = GENESIS_HASH
    for i, r in enumerate(rows, start=1):
        seq, event_id, ts, domain, status, tool, args_json, evidence, result, prev, sha, mac = r
        problem = None
        if seq != i:
            problem = f"secuencia rota: se esperaba {i} y hay {seq} (fila borrada o insertada)"
        elif prev != expected_prev:
            problem = "prev_hash no coincide con el evento anterior (cadena cortada)"
        else:
            record = {"ts": ts, "domain": domain, "status": status, "tool": tool,
                      "arguments": json.loads(args_json), "evidence": evidence,
                      "result": result, "seq": seq}
            calc_sha, calc_mac = _seal(prev, record, key)
            if calc_sha != sha:
                problem = "el contenido de la fila fue modificado (SHA-256 no coincide)"
            elif not hmac.compare_digest(calc_mac, mac):
                problem = "sello HMAC inválido (resellado sin la clave)"
        if problem:
            return {"intact": False, "events_checked": i, "broken_at_seq": seq,
                    "event_id": event_id, "reason": problem}
        expected_prev = sha

    return {"intact": True, "events_checked": len(rows), "head_hash": expected_prev}


def anchor_head() -> dict:
    """Último hash de la cadena, para anclarlo fuera de la máquina."""
    result = verify_chain()
    return {"intact": result["intact"], "events": result["events_checked"],
            "head_hash": result.get("head_hash"),
            "anchored_at": datetime.now(timezone.utc).isoformat()}


def read_ledger(limit: int = 25) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT seq, event_id, ts, domain, status, tool_executed, arguments_json, "
            "execution_result, sha256_seal FROM soar_ledger ORDER BY seq DESC LIMIT ?",
            (limit,),
        ).fetchall()
    keys = ["seq", "event_id", "timestamp", "domain", "status", "tool",
            "arguments", "execution_result", "sha256_seal"]
    return [dict(zip(keys, r)) for r in rows]


# ---------- bloqueos activos (para expiración y rollback) ----------

def add_block(rule_name: str, ip: str, created_at: str, expires_at: str, event_id: str) -> None:
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO active_blocks VALUES (?, ?, ?, ?, 'ACTIVE', ?)",
            (rule_name, ip, created_at, expires_at, event_id),
        )


def set_block_state(rule_name: str, state: str) -> None:
    with _lock, _connect() as conn:
        conn.execute("UPDATE active_blocks SET state = ? WHERE rule_name = ?", (state, rule_name))


def link_block_event(rule_name: str, event_id: str) -> None:
    with _lock, _connect() as conn:
        conn.execute("UPDATE active_blocks SET event_id = ? WHERE rule_name = ?", (event_id, rule_name))


def find_active_block(ip: str):
    with _connect() as conn:
        return conn.execute(
            "SELECT rule_name, expires_at FROM active_blocks WHERE ip = ? AND state = 'ACTIVE'",
            (ip,),
        ).fetchone()


def get_block(rule_name: str):
    with _connect() as conn:
        return conn.execute(
            "SELECT rule_name, ip, created_at, expires_at, state FROM active_blocks WHERE rule_name = ?",
            (rule_name,),
        ).fetchone()


def list_blocks(only_active: bool = True) -> list[dict]:
    sql = "SELECT rule_name, ip, created_at, expires_at, state, event_id FROM active_blocks"
    if only_active:
        sql += " WHERE state = 'ACTIVE'"
    with _connect() as conn:
        rows = conn.execute(sql + " ORDER BY created_at DESC").fetchall()
    keys = ["rule_name", "ip", "created_at", "expires_at", "state", "event_id"]
    return [dict(zip(keys, r)) for r in rows]
