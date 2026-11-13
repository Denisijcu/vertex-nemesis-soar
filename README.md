# 🛡️ Vertex Nemesis SOAR v1.1 — Contención autónoma con grounding verificado

**Desarrollado por:** [Vertex Coders LLC](https://vertex-services.org) (Miami, FL)
**Fundador:** Denis Sanchez Leyva (`@Denisijcu`)
**Modelo local:** [`Denisijcu/vertex-qwen35-4b-grounded-gguf`](https://huggingface.co/Denisijcu/vertex-qwen35-4b-grounded-gguf) (`Q4_K_M`, base `Qwen/Qwen3-4B-Instruct-2507`, servido en LM Studio)

---

## La idea en una línea

**El modelo propone, el código verifica.** El modelo decide qué hacer con una alerta, pero
nada se ejecuta si el código no comprueba primero que los datos salen de la alerta, que la
herramienta está permitida y que el objetivo no es una IP protegida. Todo queda en un ledger
encadenado que delata cualquier manipulación.

## Flujo de una alerta

```
alerta ──► modelo (LM Studio, T=0) ──► ¿abstención? ── sí ──► se respeta, no se ejecuta nada
                                           │ no
                                           ▼
                              ¿herramienta en la lista blanca? ── no ──► REJECTED_UNAUTHORIZED_TOOL
                                           │ sí
                                           ▼
                        ¿la IP aparece en el [CONTEXTO]? ── no ──► REJECTED_UNGROUNDED
                                           │ sí
                                           ▼
                             ¿IP protegida? ── sí ──► REJECTED_PROTECTED_IP
                                           │ no
                                           ▼
                    netsh: regla de entrada + salida, con expiración ──► VERIFIED_OK
                                           │
                                           ▼
                         ledger encadenado (SHA-256 + HMAC) en DuckDB
```

## Componentes

| Archivo | Qué hace |
| :--- | :--- |
| `app.py` | Gateway FastAPI. Llama al modelo, interpreta su decisión y aplica las reglas en orden. |
| `core/grounding.py` | Comprueba que cada IP propuesta aparezca en el `[CONTEXTO]`. La `[PREGUNTA]` no cuenta como fuente, porque por ahí entraría una orden inyectada. |
| `core/defense_ops.py` | `netsh` con `shell=False`, IPs protegidas, expiración, rollback y solo reglas `VTX_*`. |
| `core/vault.py` | Ledger encadenado: cada evento lleva el hash del anterior y un HMAC con una clave que no vive en la base de datos. |
| `core/config.py` | Rutas y ajustes, todos cambiables por variables de entorno. |
| `tests/test_offline.py` | 28 pruebas sin LM Studio ni firewall (modelo y netsh simulados). |
| `client_test.py` | Examen en vivo contra el modelo real, todo en `dry_run`. |

## Herramientas del modelo

| Herramienta | Efecto |
| :--- | :--- |
| `block_firewall_ip(ip_address, rule_name)` | Bloquea la IP en entrada y salida durante `VERTEX_BLOCK_TTL_MINUTES` (60 por defecto). |
| `check_listening_ports()` | Lista los puertos en escucha y marca los expuestos en `0.0.0.0`. Entiende `LISTENING` y `ESCUCHANDO`. |

**Desbloquear no es una herramienta del modelo, a propósito.** Lo hace el operador con
`DELETE /api/v1/blocks/{rule_name}`. Así un log envenenado no puede pedirle al modelo que
quite un bloqueo.

## IPs que nunca se bloquean

Loopback, `0.0.0.0`, multicast, broadcast, link-local, rangos reservados, las IPs de esta
máquina, la puerta de enlace por defecto (leída de `route print`) y las que pongas en
`VERTEX_PROTECTED_IPS` (separadas por comas, por ejemplo tu DNS).

## Endpoints

| Método | Ruta | Uso |
| :--- | :--- | :--- |
| POST | `/api/v1/analyze-and-contain` | Analiza una alerta. `dry_run` es `true` por defecto. |
| GET | `/api/v1/ledger?limit=25` | Últimos eventos. |
| GET | `/api/v1/ledger/verify` | Recorre la cadena y dice si alguien la tocó. |
| GET | `/api/v1/ledger/anchor` | Último hash, para anclarlo fuera de la máquina. |
| GET | `/api/v1/blocks` | Bloqueos activos (`?all=true` para el histórico). |
| DELETE | `/api/v1/blocks/{rule_name}` | Desbloqueo manual del operador. |
| POST | `/api/v1/blocks/expire` | Quita ya los bloqueos vencidos. |
| GET | `/api/v1/health` | Versión, IPs protegidas y herramientas. |

## Puesta en marcha (Windows 11)

Todos los comandos se corren desde la carpeta del proyecto, en PowerShell.

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 1. Pruebas offline (no hace falta LM Studio)
python tests\test_offline.py

# 2. Gateway (deja esta terminal abierta)
uvicorn app:app --host 127.0.0.1 --port 8000

# 3. En otra terminal, con LM Studio y el modelo cargados en 127.0.0.1:1234
.\venv\Scripts\Activate.ps1
python client_test.py
```

Para que `dry_run: false` aplique reglas de verdad, el gateway tiene que correr en un
PowerShell **como administrador**. Para forzar el modo seguro siempre:
`$env:VERTEX_SOAR_DRY_RUN = "1"`.

## Variables de entorno

| Variable | Por defecto |
| :--- | :--- |
| `VERTEX_LM_URL` | `http://127.0.0.1:1234/v1` |
| `VERTEX_MODEL` | vacío: autodetecta el primer modelo cargado que diga `vertex` |
| `VERTEX_SOAR_DB` | `vertex_soar_vault.duckdb` en la carpeta del proyecto |
| `VERTEX_VAULT_KEY_FILE` | `%USERPROFILE%\.vertex\soar_vault.key` (se crea sola la primera vez) |
| `VERTEX_BLOCK_TTL_MINUTES` | `60` |
| `VERTEX_PROTECTED_IPS` | vacío |
| `VERTEX_SOAR_DRY_RUN` | `0` (con `1` nunca toca el firewall) |

## Límites conocidos

- **Grounding no es anti-inyección completo.** Si el atacante logra meter su IP dentro del
  propio log, esa IP sí aparece en el contexto. Eso lo cubre la fase siguiente (el Portero / V-SRT).
- **La expiración no corre en segundo plano.** Se aplica al arrancar, en cada alerta y con
  `POST /api/v1/blocks/expire`.
- **El ledger detecta cambios, no los impide.** Quien tenga a la vez el `.duckdb` y la clave
  puede reescribir la cadena entera; por eso existe `/ledger/anchor`, para guardar el último
  hash fuera de la máquina.
- La bóveda de la v1.0 (`vertex_nemesis_vault.duckdb`) no se migra: queda intacta como
  histórico y la v1.1 empieza una cadena nueva.

## Release firmado

```powershell
.\Invoke-VertexRelease.ps1
```

Genera `releases\Vertex-Nemesis-SOAR_v1.1.0_<fecha>.zip` y su `.sha256`. Nunca empaqueta
`venv`, `libro`, bóvedas ni claves.
