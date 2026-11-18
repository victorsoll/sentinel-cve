"""Configuration centralisée — tout vient des variables d'environnement (.env).

V2 : tous les réglages qui pouvaient être modifiés « à la main » dans le code
(quotas IA, max_tokens par appel, prompt système) sont désormais pilotés par
.env, pour qu'une mise à jour du code n'écrase plus jamais vos réglages."""
import os
from dotenv import load_dotenv

load_dotenv()


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


def _list(name: str, default: str = "") -> list[str]:
    return [x.strip() for x in os.getenv(name, default).split(",") if x.strip()]


# ---------- GLPI ----------
GLPI_BASE_URL = os.getenv("GLPI_BASE_URL", "").rstrip("/")
GLPI_APP_TOKEN = os.getenv("GLPI_APP_TOKEN", "")
GLPI_USER_TOKEN = os.getenv("GLPI_USER_TOKEN", "")
GLPI_MAX_OR_CRITERIA = int(os.getenv("GLPI_MAX_OR_CRITERIA", "12"))

GLPI_FIELD_LOCATION = int(os.getenv("GLPI_FIELD_LOCATION", "3"))
GLPI_FIELD_KERNEL_VERSION = int(os.getenv("GLPI_FIELD_KERNEL_VERSION", "48"))
GLPI_FIELD_SOFTWARE_INSTALL_COUNT = int(os.getenv("GLPI_FIELD_SOFTWARE_INSTALL_COUNT", "72"))

# ---------- Moteur déterministe ----------
DETERMINISTIC_ENABLED = _bool("DETERMINISTIC_ENABLED", True)
PRODUCT_RULES_FILE = os.getenv("PRODUCT_RULES_FILE", "/app/output/product_rules.json")
GLPI_EXCLUDED_STATES_REGEX = os.getenv("GLPI_EXCLUDED_STATES_REGEX", "Out of Park")
DETERMINISTIC_MAX_HOSTS = int(os.getenv("DETERMINISTIC_MAX_HOSTS", "5000"))

# ---------- CERT-FR ----------
CERTFR_BASE_URL = os.getenv("CERTFR_BASE_URL", "https://www.cert.ssi.gouv.fr").rstrip("/")
CERTFR_AVIS_FEED = os.getenv("CERTFR_AVIS_FEED", f"{CERTFR_BASE_URL}/avis/feed/")
CERTFR_ALERTE_FEED = os.getenv("CERTFR_ALERTE_FEED", f"{CERTFR_BASE_URL}/alerte/feed/")
CERTFR_LOOKBACK_DAYS = int(os.getenv("CERTFR_LOOKBACK_DAYS", "90"))
# Rubriques analysées (croisées avec l'inventaire, comptent dans le score).
CERTFR_ANALYZED_SECTIONS = _list("CERTFR_ANALYZED_SECTIONS", "avis,alerte")
# Rubriques affichées pour information (pas de croisement, pas de score).
CERTFR_INFO_SECTIONS = _list("CERTFR_INFO_SECTIONS", "actualite,cti,dur,ioc")
# Garde-fou de pagination : nombre max de pages lues par rubrique (10 bulletins/page).
CERTFR_MAX_PAGES = int(os.getenv("CERTFR_MAX_PAGES", "80"))
# Pause entre deux pages (politesse envers le site du CERT-FR).
CERTFR_PAGE_DELAY_S = float(os.getenv("CERTFR_PAGE_DELAY_S", "0.5"))

# ---------- Agent IA (Anthropic Claude, tool use) ----------
AI_ENABLED = _bool("AI_ENABLED", False)
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5-20250929")
AI_MAX_TOOL_ITERATIONS = int(os.getenv("AI_MAX_TOOL_ITERATIONS", "8"))
# Plafond de tokens de SORTIE par appel au modèle (était codé en dur à 2048 en V1).
AI_MAX_TOKENS_PER_CALL = int(os.getenv("AI_MAX_TOKENS_PER_CALL", "2048"))
# Garde-fous de budget PAR CYCLE.
AI_MAX_CALLS_PER_CYCLE = int(os.getenv("AI_MAX_CALLS_PER_CYCLE", "200"))
AI_MAX_TOKENS_PER_CYCLE = int(os.getenv("AI_MAX_TOKENS_PER_CYCLE", "1000000"))
AI_CACHE_TTL_DAYS = int(os.getenv("AI_CACHE_TTL_DAYS", "7"))
# Prompt système personnalisé : si ce fichier existe, il remplace le prompt
# par défaut de agent_pipeline.py. Placé dans output/ (volume persistant) pour
# survivre aux reconstructions de l'image.
AI_SYSTEM_PROMPT_FILE = os.getenv("AI_SYSTEM_PROMPT_FILE", "/app/output/system_prompt.txt")

# ---------- Azure DevOps (ÉCRITURE uniquement : création de requirements) ----------
# ADO n'est plus une source d'analyse en V2 : il sert uniquement de
# destination pour créer un requirement à partir d'un bulletin croisé.
ADO_ORG = os.getenv("ADO_ORG", "")
ADO_PROJECT = os.getenv("ADO_PROJECT", "")
ADO_PAT = os.getenv("ADO_PAT", "")
ADO_WRITE_ENABLED = _bool("ADO_WRITE_ENABLED", False)
# Type du work item principal : "Requirement" (process CMMI), "User Story"
# (Agile), "Product Backlog Item" (Scrum), "Issue" (Basic).
ADO_WORK_ITEM_TYPE = os.getenv("ADO_WORK_ITEM_TYPE", "Requirement")
# Type des sous-tâches créées quand plusieurs personnes sont affectées.
ADO_TASK_TYPE = os.getenv("ADO_TASK_TYPE", "Task")
# Feature parente sous laquelle rattacher les requirements (0 = aucune).
# Reprend ADO_ROOT_FEATURE_ID de la V1 si ADO_PARENT_ID n'est pas défini.
ADO_PARENT_ID = int(os.getenv("ADO_PARENT_ID", os.getenv("ADO_ROOT_FEATURE_ID", "0")) or 0)
ADO_AREA_PATH = os.getenv("ADO_AREA_PATH", "")
ADO_ITERATION_PATH = os.getenv("ADO_ITERATION_PATH", "")
# Équipe(s) dont les membres sont proposés dans le sélecteur de personnes.
# Vide = toutes les équipes du projet.
ADO_TEAMS = _list("ADO_TEAMS", "")
# Tags ajoutés à chaque requirement (en plus de la référence du bulletin).
ADO_TAGS = _list("ADO_TAGS", "sentinel-cve")
ADO_SET_PRIORITY = _bool("ADO_SET_PRIORITY", True)

# ---------- Divers ----------
SCHEDULE_CRON_MINUTE = os.getenv("SCHEDULE_CRON_MINUTE", "44")
SCHEDULE_CRON_HOUR = os.getenv("SCHEDULE_CRON_HOUR", "3")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "/app/output")
TIMEZONE = os.getenv("TIMEZONE", "Europe/Paris")

# ---------- Actions depuis le dashboard (cycle manuel, création ADO) ----------
# Jeton demandé UNE fois dans le navigateur (jamais écrit dans la page HTML,
# contrairement à la V1). ACTION_TOKEN, ou TRIGGER_TOKEN pour compatibilité V1.
ACTION_TOKEN = os.getenv("ACTION_TOKEN", "") or os.getenv("TRIGGER_TOKEN", "")
TRIGGER_TOKEN = ACTION_TOKEN  # alias V1
TRIGGER_PORT = int(os.getenv("TRIGGER_PORT", "5001"))
