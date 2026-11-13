"""Configuración central de Vertex Nemesis SOAR.

Todas las rutas son relativas a la carpeta del proyecto, así que renombrar
la carpeta no rompe nada (el venv sí hay que recrearlo, ver README).
Cada valor se puede cambiar con una variable de entorno.
"""
import os
import platform
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Bóveda forense (ledger encadenado). Archivo nuevo: la bóveda v1.0
# (vertex_nemesis_vault.duckdb) se deja intacta como evidencia histórica.
DB_PATH = Path(os.getenv("VERTEX_SOAR_DB", BASE_DIR / "vertex_soar_vault.duckdb"))

# Clave HMAC del ledger. Vive FUERA del proyecto y fuera de la base de datos:
# quien edite el .duckdb sin esta clave no puede volver a sellar las filas.
KEY_PATH = Path(os.getenv("VERTEX_VAULT_KEY_FILE", Path.home() / ".vertex" / "soar_vault.key"))

# LM Studio (solo local)
LM_STUDIO_URL = os.getenv("VERTEX_LM_URL", "http://127.0.0.1:1234/v1")
VERTEX_MODEL = os.getenv("VERTEX_MODEL", "").strip()  # vacío = autodetectar

# Contención
BLOCK_TTL_MINUTES = int(os.getenv("VERTEX_BLOCK_TTL_MINUTES", "60"))
RULE_PREFIX = "VTX_"  # el SOAR solo toca reglas de firewall con este prefijo
EXTRA_PROTECTED_IPS = [
    ip.strip() for ip in os.getenv("VERTEX_PROTECTED_IPS", "").split(",") if ip.strip()
]

# Aprobación humana (fase 2.1)
# Token del operador: sin él no se aprueba ni se rechaza nada. Vive fuera del proyecto.
OPERATOR_TOKEN_PATH = Path(os.getenv("VERTEX_OPERATOR_TOKEN_FILE",
                                     Path.home() / ".vertex" / "soar_operator.token"))
# Minutos que una acción pendiente espera decisión antes de caducar sola.
PENDING_TTL_MINUTES = int(os.getenv("VERTEX_PENDING_TTL_MINUTES", "30"))

# Seguridad de ejecución: fuera de Windows nunca se ejecuta netsh de verdad.
IS_WINDOWS = platform.system() == "Windows"
FORCE_DRY_RUN = os.getenv("VERTEX_SOAR_DRY_RUN", "0") == "1" or not IS_WINDOWS
