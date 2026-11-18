#!/usr/bin/env bash
# =====================================================================
# Sentinel CVE — installation de la V2
# À lancer depuis ~/sentinel-cve :   bash install_v2.sh
# 1. sauvegarde les fichiers actuels dans backup-v1-<date>/
# 2. écrit les fichiers V2
# 3. vérifie la syntaxe Python
# Ne touche NI au .env, NI à output/ (base SQLite et dashboard conservés).
# =====================================================================
set -euo pipefail
cd "$(dirname "$0")"
[ -f docker-compose.yml ] && [ -d app ] || { echo "Lancer depuis le dossier sentinel-cve"; exit 1; }

BK="backup-v1-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BK"
cp -a app tests .env.example README.md "$BK"/ 2>/dev/null || true
echo "Sauvegarde V1 : $BK/"
mkdir -p app/templates tests

cat > app/config.py << 'SENTINEL_V2_EOF'
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
SENTINEL_V2_EOF
echo "  écrit : app/config.py"

cat > app/certfr_client.py << 'SENTINEL_V2_EOF'
"""
Récupération des publications CERT-FR.

V2 — pourquoi on ne se contente plus des flux RSS : un flux RSS CERT-FR ne
contient que les dernières publications, alors que le CERT-FR publie plus
de 100 avis par mois. Sur une fenêtre de 90 jours, la V1 en ratait donc la
grande majorité. On lit désormais les pages de liste paginées du site
(/avis/, /avis/page/2/, ...) jusqu'à sortir de la fenêtre de suivi, et le
RSS ne sert plus qu'à compléter (résumé) ou à prendre le relais si la
structure HTML du site change.

Le parseur HTML ne dépend d'aucune classe CSS : il repère les liens vers
/<rubrique>/CERTFR-AAAA-XXX-NNNN/ et la mention « Publié le … » autour,
ce qui le rend robuste aux refontes graphiques du site.
"""
import logging
import re
import time
from datetime import date, datetime, timedelta, timezone

import feedparser
import requests
from bs4 import BeautifulSoup

import config

log = logging.getLogger(__name__)

USER_AGENT = "sentinel-cve/2.0 (+veille interne)"

SECTION_LABELS = {
    "avis": "Avis",
    "alerte": "Alerte",
    "actualite": "Bulletin d'actualité",
    "cti": "Menaces et incidents",
    "dur": "Durcissement",
    "ioc": "Indicateurs de compromission",
}

FR_MONTHS = {
    "janvier": 1, "fevrier": 2, "février": 2, "mars": 3, "avril": 4, "mai": 5,
    "juin": 6, "juillet": 7, "aout": 8, "août": 8, "septembre": 9,
    "octobre": 10, "novembre": 11, "decembre": 12, "décembre": 12,
}
_DATE_RE = re.compile(
    r"Publié\s+le\s+(\d{1,2})(?:er)?\s+([A-Za-zÀ-ÿ]+)\s+(\d{4})", re.IGNORECASE
)
_REF_RE = re.compile(r"CERTFR-\d{4}-[A-Z]{2,4}-\d+")
_ALERT_STATUS_RE = re.compile(r"Alerte\s+(en cours|close)", re.IGNORECASE)


class ListingStructureError(Exception):
    """La page de liste ne ressemble plus à ce que le parseur attend
    (aucune date « Publié le » trouvée) : on bascule sur le RSS."""


# ---------------------------------------------------------------- RSS (V1)
def _within_lookback(entry, days: int) -> bool:
    published = entry.get("published_parsed") or entry.get("updated_parsed")
    if not published:
        return True  # on garde par défaut plutôt que de perdre un avis
    dt = datetime(*published[:6], tzinfo=timezone.utc)
    return dt >= datetime.now(timezone.utc) - timedelta(days=days)


def fetch_feed(url: str, lookback_days: int | None = None) -> list[dict]:
    lookback_days = lookback_days or config.CERTFR_LOOKBACK_DAYS
    parsed = feedparser.parse(url)
    out = []
    for entry in parsed.entries:
        if not _within_lookback(entry, lookback_days):
            continue
        published = entry.get("published_parsed") or entry.get("updated_parsed")
        iso = datetime(*published[:3]).date().isoformat() if published else ""
        out.append({
            "ref": entry.get("title", "").split(" ")[0],  # ex. CERTFR-2026-AVI-1232
            "title": entry.get("title", ""),
            "link": entry.get("link", ""),
            "summary": entry.get("summary", ""),
            # "date" et non "published" : clé attendue partout ailleurs.
            "date": iso or entry.get("published", ""),
        })
    return out


def fetch_avis(lookback_days: int | None = None) -> list[dict]:
    return fetch_feed(config.CERTFR_AVIS_FEED, lookback_days)


def fetch_alertes(lookback_days: int | None = None) -> list[dict]:
    return fetch_feed(config.CERTFR_ALERTE_FEED, lookback_days)


# ------------------------------------------------------- pages HTML (V2)
def parse_fr_date(text: str) -> date | None:
    """« Publié le 07 octobre 2026 » / « Publié le 1er mars 2026 » -> date."""
    m = _DATE_RE.search(text or "")
    if not m:
        return None
    day, month_name, year = m.groups()
    month = FR_MONTHS.get(month_name.lower())
    if not month:
        return None
    try:
        return date(int(year), month, int(day))
    except ValueError:
        return None


def _clean_title(title: str, ref: str) -> str:
    """« CERTFR-2026-AVI-1232 : Vulnérabilité dans X » -> « Vulnérabilité dans X »."""
    t = (title or "").strip()
    if ref and t.startswith(ref):
        t = t[len(ref):].lstrip(" :–-")
    return t.strip()


def parse_listing_html(html: str, section: str, base_url: str | None = None) -> list[dict]:
    """Extrait les publications d'une page de liste CERT-FR.
    Renvoie des dicts {ref, title, link, date (ISO), summary, kind, alert_status}
    dans l'ordre de la page."""
    base_url = (base_url or config.CERTFR_BASE_URL).rstrip("/")
    soup = BeautifulSoup(html, "html.parser")
    link_re = re.compile(rf"/{re.escape(section)}/({_REF_RE.pattern})/?")

    anchors_by_ref: dict[str, list] = {}
    order: list[str] = []
    for a in soup.find_all("a", href=True):
        m = link_re.search(a["href"])
        if not m:
            continue
        ref = m.group(1)
        if ref not in anchors_by_ref:
            anchors_by_ref[ref] = []
            order.append(ref)
        anchors_by_ref[ref].append(a)

    items = []
    for ref in order:
        anchors = anchors_by_ref[ref]
        # Titre = texte de lien le plus long qui n'est pas juste la référence.
        texts = [a.get_text(" ", strip=True) for a in anchors]
        texts = [t for t in texts if t and t != ref]
        title = _clean_title(max(texts, key=len) if texts else ref, ref)

        # Conteneur = plus petit ancêtre qui contient « Publié le » et une
        # seule référence (sinon on serait remonté jusqu'à la liste entière).
        container = None
        node = anchors[0]
        for _ in range(8):
            node = node.parent
            if node is None or node.name in ("body", "html", "[document]"):
                break
            txt = node.get_text(" ", strip=True)
            if "Publié le" in txt or "publié le" in txt:
                if len(set(_REF_RE.findall(txt))) <= 1:
                    container = node
                break
        ctext = container.get_text(" ", strip=True) if container else ""

        published = parse_fr_date(ctext)
        summary = ""
        if container is not None:
            paras = [
                p.get_text(" ", strip=True) for p in container.find_all(["p", "div", "section"])
                if not p.find(["p", "div", "section"])
            ]
            paras = [
                p for p in paras
                if p and p != title and "Publié le" not in p and not _REF_RE.fullmatch(p)
            ]
            summary = max(paras, key=len) if paras else ""
        status_m = _ALERT_STATUS_RE.search(ctext)

        href = anchors[0]["href"]
        link = href if href.startswith("http") else f"{base_url}{href if href.startswith('/') else '/' + href}"
        items.append({
            "ref": ref,
            "title": title,
            "link": link,
            "date": published.isoformat() if published else "",
            "summary": summary,
            "kind": section,
            "alert_status": (f"Alerte {status_m.group(1).lower()}" if status_m else ""),
        })
    return items


def fetch_section(section: str, lookback_days: int | None = None, max_pages: int | None = None,
                  session: requests.Session | None = None) -> tuple[list[dict], dict]:
    """Parcourt /<section>/page/N/ jusqu'à sortir de la fenêtre de suivi.
    Renvoie (publications, méta {pages, stopped_because})."""
    lookback_days = lookback_days or config.CERTFR_LOOKBACK_DAYS
    max_pages = max_pages or config.CERTFR_MAX_PAGES
    cutoff = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).date()
    s = session or requests.Session()
    s.headers.setdefault("User-Agent", USER_AGENT)

    out: list[dict] = []
    seen: set[str] = set()
    meta = {"pages": 0, "stopped_because": "max_pages"}
    for page in range(1, max_pages + 1):
        url = f"{config.CERTFR_BASE_URL}/{section}/" + (f"page/{page}/" if page > 1 else "")
        r = s.get(url, timeout=30)
        if r.status_code == 404:
            meta["stopped_because"] = "fin_des_pages"
            break
        r.raise_for_status()
        meta["pages"] = page
        items = parse_listing_html(r.text, section)
        if not items:
            meta["stopped_because"] = "page_vide"
            break
        if page == 1 and not any(it["date"] for it in items):
            raise ListingStructureError(
                f"{url} : {len(items)} liens trouvés mais aucune date « Publié le » — structure HTML non reconnue"
            )
        page_has_recent = False
        for it in items:
            if it["ref"] in seen:
                continue
            seen.add(it["ref"])
            d = date.fromisoformat(it["date"]) if it["date"] else None
            if d is None or d >= cutoff:
                out.append(it)
                page_has_recent = True
            elif it.get("alert_status") == "Alerte en cours":
                out.append(it)  # alerte ancienne mais toujours en cours : on la garde
        if not page_has_recent:
            meta["stopped_because"] = "hors_fenetre"
            break
        if config.CERTFR_PAGE_DELAY_S:
            time.sleep(config.CERTFR_PAGE_DELAY_S)
    return out, meta


def _rss_url(section: str) -> str:
    if section == "avis":
        return config.CERTFR_AVIS_FEED
    if section == "alerte":
        return config.CERTFR_ALERTE_FEED
    return f"{config.CERTFR_BASE_URL}/{section}/feed/"


def collect_section(section: str, lookback_days: int | None = None) -> tuple[list[dict], dict]:
    """HTML paginé en priorité, RSS pour compléter / prendre le relais.
    Renvoie (publications, santé {ok, mode, count, pages, error})."""
    health = {"ok": False, "state": "down", "mode": "", "count": 0, "pages": 0, "error": ""}
    items: list[dict] = []
    try:
        items, meta = fetch_section(section, lookback_days)
        health["pages"] = meta["pages"]
        health["mode"] = "pages HTML"
    except (requests.RequestException, ListingStructureError) as exc:
        health["error"] = f"pages HTML : {exc}"
        log.warning("CERT-FR %s : lecture des pages HTML impossible (%s), repli RSS.", section, exc)

    try:
        rss = fetch_feed(_rss_url(section), lookback_days)
    except Exception as exc:  # noqa: BLE001
        rss = []
        health["error"] = (health["error"] + " ; " if health["error"] else "") + f"RSS : {exc}"

    by_ref = {it["ref"]: it for it in items}
    added_from_rss = 0
    for e in rss:
        ref = e["ref"]
        if not _REF_RE.fullmatch(ref or ""):
            continue
        if ref in by_ref:
            if len(e.get("summary") or "") > len(by_ref[ref].get("summary") or ""):
                by_ref[ref]["summary"] = BeautifulSoup(e["summary"], "html.parser").get_text(" ", strip=True)
        else:
            new = {
                "ref": ref,
                "title": _clean_title(e["title"], ref),
                "link": e["link"],
                "date": e["date"],
                "summary": BeautifulSoup(e.get("summary") or "", "html.parser").get_text(" ", strip=True),
                "kind": section,
                "alert_status": "",
            }
            items.append(new)
            by_ref[ref] = new
            added_from_rss += 1

    if not health["mode"]:
        health["mode"] = "RSS seul (dégradé)" if rss else ""
    elif added_from_rss:
        health["mode"] += f" + {added_from_rss} via RSS"
    health["count"] = len(items)
    # ok = lu normalement ; degraded = erreur mais des publications récupérées
    # (RSS) ; down = rien récupéré du tout.
    health["state"] = "ok" if not health["error"] else ("degraded" if items else "down")
    health["ok"] = health["state"] != "down"
    items.sort(key=lambda b: (b.get("date") or "", b["ref"]), reverse=True)
    return items, health


def collect_all(lookback_days: int | None = None) -> dict:
    """Toutes les rubriques configurées.
    Renvoie {"bulletins": [...analysés...], "info": [...], "health": {section: {...}}}."""
    result = {"bulletins": [], "info": [], "health": {}}
    for section in config.CERTFR_ANALYZED_SECTIONS:
        items, health = collect_section(section, lookback_days)
        result["bulletins"].extend(items)
        result["health"][section] = health
    for section in config.CERTFR_INFO_SECTIONS:
        items, health = collect_section(section, lookback_days)
        result["info"].extend(items)
        result["health"][section] = health
    return result


def fetch_detail(link: str) -> dict:
    """Texte intégral d'une publication (systèmes affectés, versions, CVE)."""
    r = requests.get(link, timeout=30, headers={"User-Agent": USER_AGENT})
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")
    content = soup.select_one("div.entry-content, main, article")
    text = content.get_text("\n", strip=True) if content else soup.get_text("\n", strip=True)
    return {"link": link, "text": text}
SENTINEL_V2_EOF
echo "  écrit : app/certfr_client.py"

cat > app/db.py << 'SENTINEL_V2_EOF'
"""Persistance SQLite (output/sentinel.db), partagée entre les cycles.

Tables :
- score_history          : score + décompte par statut à chaque cycle (graphiques)
- changelog              : une phrase par cycle
- bulletin_analysis_cache: cache du verdict IA par bulletin (déduplication du coût)
- cycle_runs             : métriques de chaque cycle (durée, budget IA, santé des sources)
- cycle_bulletins        : bulletins du DERNIER cycle (lus par l'API de création ADO,
                           qui ne fait jamais confiance au contenu envoyé par le navigateur)
- ado_creations          : journal d'audit des work items créés dans Azure DevOps
"""
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

import config

DB_PATH = os.path.join(config.OUTPUT_DIR, "sentinel.db")


def _connect():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    return sqlite3.connect(DB_PATH)


def _columns(conn, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def init_db():
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS score_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                score INTEGER NOT NULL
            )
        """)
        # Migration V1 -> V2 : décompte par statut, pour le graphique du taux de concernés.
        existing = _columns(conn, "score_history")
        for col in ("n_concerne", "n_a_verifier", "n_non_concerne", "n_total"):
            if col not in existing:
                conn.execute(f"ALTER TABLE score_history ADD COLUMN {col} INTEGER")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS changelog (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                entry TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS bulletin_analysis_cache (
                ref TEXT PRIMARY KEY,
                content_hash TEXT NOT NULL,
                result_json TEXT NOT NULL,
                analyzed_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cycle_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                trigger TEXT,
                duration_s REAL,
                ai_calls INTEGER,
                ai_tokens INTEGER,
                ai_cached INTEGER,
                ai_pending INTEGER,
                n_bulletins INTEGER,
                sources_json TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cycle_bulletins (
                ref TEXT PRIMARY KEY,
                kind TEXT,
                title TEXT,
                link TEXT,
                date TEXT,
                status TEXT,
                data_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ado_creations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                ref TEXT NOT NULL,
                work_item_id INTEGER NOT NULL,
                work_item_type TEXT,
                title TEXT,
                assigned_to TEXT,
                url TEXT,
                parent_id INTEGER
            )
        """)
        conn.commit()


# ------------------------------------------------------------ cache IA
def get_cached_analysis(ref: str, content_hash: str, max_age_days: int) -> dict | None:
    if not ref:
        return None
    init_db()
    with _connect() as conn:
        row = conn.execute(
            "SELECT content_hash, result_json, analyzed_at FROM bulletin_analysis_cache WHERE ref = ?",
            (ref,),
        ).fetchone()
    if row is None:
        return None
    cached_hash, result_json, analyzed_at = row
    if cached_hash != content_hash:
        return None
    try:
        analyzed_dt = datetime.fromisoformat(analyzed_at)
    except ValueError:
        return None
    if datetime.now(timezone.utc) - analyzed_dt > timedelta(days=max_age_days):
        return None
    try:
        return json.loads(result_json)
    except json.JSONDecodeError:
        return None


def save_analysis(ref: str, content_hash: str, result: dict) -> None:
    if not ref:
        return
    init_db()
    now_iso = datetime.now(timezone.utc).isoformat()
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO bulletin_analysis_cache (ref, content_hash, result_json, analyzed_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ref) DO UPDATE SET
                content_hash = excluded.content_hash,
                result_json = excluded.result_json,
                analyzed_at = excluded.analyzed_at
            """,
            (ref, content_hash, json.dumps(result), now_iso),
        )
        conn.commit()


# ------------------------------------------------------------ score
def insert_score(ts: datetime, score: int, counts: dict | None = None):
    init_db()
    counts = counts or {}
    with _connect() as conn:
        conn.execute(
            "INSERT INTO score_history (ts, score, n_concerne, n_a_verifier, n_non_concerne, n_total) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ts.isoformat(), score, counts.get("concerne"), counts.get("a_verifier"),
             counts.get("non_concerne"), counts.get("total")),
        )
        conn.execute("""
            DELETE FROM score_history WHERE id NOT IN (
                SELECT id FROM score_history ORDER BY id DESC LIMIT 120
            )
        """)
        conn.commit()


def get_history() -> list[dict]:
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT ts, score, n_concerne, n_a_verifier, n_non_concerne, n_total "
            "FROM score_history ORDER BY id ASC"
        ).fetchall()
    return [
        {"ts": ts, "score": score, "concerne": c, "a_verifier": a, "non_concerne": n, "total": t}
        for ts, score, c, a, n, t in rows
    ]


def latest_score() -> int | None:
    hist = get_history()
    return hist[-1]["score"] if hist else None


# ------------------------------------------------------------ changelog
def insert_changelog_entry(ts: datetime, entry: str):
    init_db()
    with _connect() as conn:
        conn.execute("INSERT INTO changelog (ts, entry) VALUES (?, ?)", (ts.isoformat(), entry))
        conn.execute("""
            DELETE FROM changelog WHERE id NOT IN (
                SELECT id FROM changelog ORDER BY id DESC LIMIT 30
            )
        """)
        conn.commit()


def get_changelog(limit: int = 10) -> list[dict]:
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT ts, entry FROM changelog ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [{"ts": ts, "entry": entry} for ts, entry in rows]


# ------------------------------------------------------------ cycles
def insert_cycle_run(ts: datetime, trigger: str, duration_s: float, ai: dict,
                     n_bulletins: int, sources: dict) -> None:
    init_db()
    with _connect() as conn:
        conn.execute(
            "INSERT INTO cycle_runs (ts, trigger, duration_s, ai_calls, ai_tokens, ai_cached, ai_pending, "
            "n_bulletins, sources_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ts.isoformat(), trigger, round(duration_s, 1), ai.get("calls", 0), ai.get("tokens", 0),
             ai.get("cached", 0), ai.get("pending", 0), n_bulletins, json.dumps(sources)),
        )
        conn.execute("""
            DELETE FROM cycle_runs WHERE id NOT IN (
                SELECT id FROM cycle_runs ORDER BY id DESC LIMIT 120
            )
        """)
        conn.commit()


def get_cycle_runs(limit: int = 60) -> list[dict]:
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT ts, trigger, duration_s, ai_calls, ai_tokens, ai_cached, ai_pending, n_bulletins "
            "FROM cycle_runs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    keys = ("ts", "trigger", "duration_s", "ai_calls", "ai_tokens", "ai_cached", "ai_pending", "n_bulletins")
    return [dict(zip(keys, r)) for r in reversed(rows)]


def replace_cycle_bulletins(bulletins: list[dict]) -> None:
    """Remplace d'un bloc les bulletins du dernier cycle."""
    init_db()
    now_iso = datetime.now(timezone.utc).isoformat()
    with _connect() as conn:
        conn.execute("DELETE FROM cycle_bulletins")
        conn.executemany(
            "INSERT OR REPLACE INTO cycle_bulletins (ref, kind, title, link, date, status, data_json, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (b.get("ref"), b.get("kind"), b.get("title"), b.get("link"), b.get("date"),
                 b.get("status"), json.dumps(b, default=str), now_iso)
                for b in bulletins if b.get("ref")
            ],
        )
        conn.commit()


def get_cycle_bulletin(ref: str) -> dict | None:
    init_db()
    with _connect() as conn:
        row = conn.execute("SELECT data_json FROM cycle_bulletins WHERE ref = ?", (ref,)).fetchone()
    return json.loads(row[0]) if row else None


# ------------------------------------------------------------ audit ADO
def insert_ado_creation(ref: str, work_item_id: int, work_item_type: str, title: str,
                        assigned_to: str, url: str, parent_id: int | None) -> None:
    init_db()
    with _connect() as conn:
        conn.execute(
            "INSERT INTO ado_creations (ts, ref, work_item_id, work_item_type, title, assigned_to, url, parent_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), ref, work_item_id, work_item_type, title,
             assigned_to, url, parent_id),
        )
        conn.commit()


def get_ado_creations_by_ref() -> dict[str, list[dict]]:
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT ts, ref, work_item_id, work_item_type, assigned_to, url FROM ado_creations ORDER BY id ASC"
        ).fetchall()
    out: dict[str, list[dict]] = {}
    for ts, ref, wid, wtype, who, url in rows:
        out.setdefault(ref, []).append(
            {"ts": ts, "id": wid, "type": wtype, "assigned_to": who, "url": url}
        )
    return out
SENTINEL_V2_EOF
echo "  écrit : app/db.py"

cat > app/ado_client.py << 'SENTINEL_V2_EOF'
"""
Client Azure DevOps — V2 : ÉCRITURE uniquement (plus de lecture de tickets
pour l'analyse, les mises à jour CERT étant déjà suivies dans ADO).

Rôle : créer un requirement à partir d'un bulletin croisé (CERT-FR × GLPI),
affecté à une ou plusieurs personnes présentes dans ADO.

Règles :
- ADO n'accepte qu'UNE personne dans System.AssignedTo. Avec plusieurs
  personnes : le requirement est affecté à la première (responsable), et une
  Task enfant est créée pour CHAQUE personne choisie.
- Anti-doublon : avant de créer, on cherche un work item portant déjà le tag
  de la référence du bulletin (ex. CERTFR-2026-AVI-1279).
- Prévisualisation sans rien créer : paramètre validateOnly=true de l'API.

Droits du PAT nécessaires : Work Items (Read & Write) + Project and Team (Read).
"""
import html
import logging
from datetime import datetime
from urllib.parse import quote

import requests
from requests.auth import HTTPBasicAuth

import config

log = logging.getLogger(__name__)

API_VERSION = "7.1"
MAX_HOSTS_IN_DESCRIPTION = 50
STATUS_LABELS = {"concerne": "Concerné", "a_verifier": "À vérifier", "non_concerne": "Non concerné"}
KIND_LABELS = {"avis": "Avis", "alerte": "Alerte"}


class ADOError(Exception):
    """Erreur renvoyée par Azure DevOps, avec le message lisible de l'API."""


# ------------------------------------------------------------ fonctions pures
def wiql_escape(value: str) -> str:
    return (value or "").replace("'", "''")


def build_title(bulletin: dict) -> str:
    title = f"[{bulletin.get('ref', '')}] {bulletin.get('title', '')}".strip()
    return title[:255]


def priority_for(bulletin: dict) -> int:
    if bulletin.get("kind") == "alerte":
        return 1
    if bulletin.get("status") == "concerne":
        return 2
    return 3


def build_tags(bulletin: dict, extra_tags: list[str] | None = None) -> str:
    tags = list(extra_tags if extra_tags is not None else config.ADO_TAGS)
    ref = bulletin.get("ref")
    if ref:
        tags.append(ref)
    # ";" est le séparateur de tags ADO : on le retire des valeurs.
    return "; ".join(dict.fromkeys(t.replace(";", " ").strip() for t in tags if t.strip()))


def build_description_html(bulletin: dict, generated_at: str | None = None) -> str:
    """Description HTML du requirement. Tout le contenu vient de flux externes
    (CERT-FR) ou de l'IA : TOUT est échappé."""
    e = lambda v: html.escape(str(v or ""))  # noqa: E731
    generated_at = generated_at or datetime.now().strftime("%d/%m/%Y %H:%M")
    rows = [
        ("Référence", e(bulletin.get("ref"))),
        ("Type", e(KIND_LABELS.get(bulletin.get("kind"), bulletin.get("kind")))
         + (f" — {e(bulletin.get('alert_status'))}" if bulletin.get("alert_status") else "")),
        ("Publié le", e(bulletin.get("date"))),
        ("Statut Sentinel", e(STATUS_LABELS.get(bulletin.get("status"), bulletin.get("status")))),
        ("Périmètre", e(bulletin.get("count_label"))),
        ("Versions installées", e(bulletin.get("installed_summary"))),
        ("Version cible", e(bulletin.get("target_version"))),
        ("Catégorie", e(bulletin.get("type_label"))),
    ]
    parts = [
        f"<h3>{e(bulletin.get('title'))}</h3>",
        "<table>" + "".join(
            f"<tr><td><b>{k}</b></td><td>{v}</td></tr>" for k, v in rows if v
        ) + "</table>",
    ]
    if bulletin.get("link"):
        link = e(bulletin["link"])
        parts.append(f'<p>Bulletin CERT-FR : <a href="{link}">{link}</a></p>')
    if bulletin.get("limit_note"):
        parts.append(f"<p><b>Analyse :</b> {e(bulletin['limit_note'])}</p>")

    hosts = bulletin.get("hosts") or []
    if hosts:
        shown = hosts[:MAX_HOSTS_IN_DESCRIPTION]
        parts.append(f"<p><b>Équipements concernés ({len(hosts)}) :</b></p>")
        parts.append(
            "<table><tr><th>Équipement</th><th>Site</th><th>Installé</th><th>Cible</th></tr>"
            + "".join(
                f"<tr><td>{e(h.get('name'))}</td><td>{e(h.get('site'))}</td>"
                f"<td>{e(h.get('installed'))}</td>"
                f"<td>{e(h.get('target') or bulletin.get('target_version'))}</td></tr>"
                for h in shown
            )
            + "</table>"
        )
        if len(hosts) > len(shown):
            parts.append(f"<p>… et {len(hosts) - len(shown)} autre(s), voir le dashboard Sentinel CVE.</p>")
    parts.append(f"<p><i>Créé depuis Sentinel CVE le {e(generated_at)}.</i></p>")
    return "\n".join(parts)


def _common_ops(area_path: str, iteration_path: str) -> list[dict]:
    ops = []
    if area_path:
        ops.append({"op": "add", "path": "/fields/System.AreaPath", "value": area_path})
    if iteration_path:
        ops.append({"op": "add", "path": "/fields/System.IterationPath", "value": iteration_path})
    return ops


def _parent_op(parent_api_url: str) -> dict:
    return {
        "op": "add",
        "path": "/relations/-",
        "value": {"rel": "System.LinkTypes.Hierarchy-Reverse", "url": parent_api_url},
    }


def build_requirement_ops(bulletin: dict, assignee: dict | None, parent_api_url: str | None = None,
                          area_path: str = "", iteration_path: str = "",
                          tags: list[str] | None = None, set_priority: bool = True) -> list[dict]:
    ops = [
        {"op": "add", "path": "/fields/System.Title", "value": build_title(bulletin)},
        {"op": "add", "path": "/fields/System.Description", "value": build_description_html(bulletin)},
        {"op": "add", "path": "/fields/System.Tags", "value": build_tags(bulletin, tags)},
    ]
    if assignee:
        ops.append({"op": "add", "path": "/fields/System.AssignedTo", "value": assignee["unique_name"]})
    if set_priority:
        ops.append({"op": "add", "path": "/fields/Microsoft.VSTS.Common.Priority", "value": priority_for(bulletin)})
    ops += _common_ops(area_path, iteration_path)
    if parent_api_url:
        ops.append(_parent_op(parent_api_url))
    return ops


def build_task_ops(bulletin: dict, assignee: dict, parent_api_url: str | None,
                   area_path: str = "", iteration_path: str = "", tags: list[str] | None = None) -> list[dict]:
    title = f"[{bulletin.get('ref', '')}] Traitement — {assignee.get('display_name') or assignee['unique_name']}"
    ops = [
        {"op": "add", "path": "/fields/System.Title", "value": title[:255]},
        {"op": "add", "path": "/fields/System.Description",
         "value": f"<p>Part de traitement de {html.escape(assignee.get('display_name') or '')} "
                  f"pour le bulletin {html.escape(bulletin.get('ref') or '')}. "
                  "Détails dans le requirement parent.</p>"},
        {"op": "add", "path": "/fields/System.Tags", "value": build_tags(bulletin, tags)},
        {"op": "add", "path": "/fields/System.AssignedTo", "value": assignee["unique_name"]},
    ]
    ops += _common_ops(area_path, iteration_path)
    if parent_api_url:
        ops.append(_parent_op(parent_api_url))
    return ops


def plan_items(bulletin: dict, assignees: list[dict]) -> list[dict]:
    """Ce qui sera créé, lisible par un humain (utilisé pour la prévisualisation)."""
    plan = [{
        "role": "requirement",
        "type": config.ADO_WORK_ITEM_TYPE,
        "title": build_title(bulletin),
        "assigned_to": assignees[0]["display_name"] if assignees else "(non affecté)",
        "parent_id": config.ADO_PARENT_ID or None,
    }]
    if len(assignees) > 1:
        for a in assignees:
            plan.append({
                "role": "task",
                "type": config.ADO_TASK_TYPE,
                "title": f"[{bulletin.get('ref', '')}] Traitement — {a['display_name']}",
                "assigned_to": a["display_name"],
                "parent_id": "requirement ci-dessus",
            })
    return plan


# ------------------------------------------------------------ client HTTP
class ADOClient:
    def __init__(self, org: str | None = None, project: str | None = None, pat: str | None = None):
        self.org = org or config.ADO_ORG
        self.project = project or config.ADO_PROJECT
        self.auth = HTTPBasicAuth("", pat or config.ADO_PAT)
        self.org_url = f"https://dev.azure.com/{quote(self.org)}"
        self.project_url = f"{self.org_url}/{quote(self.project)}"

    # -- utilitaires
    def _request(self, method: str, url: str, **kw) -> dict:
        kw.setdefault("timeout", 30)
        params = kw.pop("params", {}) or {}
        params.setdefault("api-version", API_VERSION)
        r = requests.request(method, url, params=params, auth=self.auth, **kw)
        if r.status_code in (401, 203):
            raise ADOError("Authentification Azure DevOps refusée (PAT invalide, expiré ou sans les droits requis).")
        if r.status_code >= 400:
            try:
                msg = r.json().get("message") or r.text
            except ValueError:
                msg = r.text
            raise ADOError(f"Azure DevOps HTTP {r.status_code} : {msg[:500]}")
        return r.json() if r.content else {}

    def web_url(self, work_item_id: int) -> str:
        return f"{self.project_url}/_workitems/edit/{work_item_id}"

    def api_url(self, work_item_id: int) -> str:
        return f"{self.org_url}/_apis/wit/workItems/{work_item_id}"

    # -- personnes
    def list_people(self) -> list[dict]:
        """Membres des équipes du projet (toutes, ou celles de ADO_TEAMS)."""
        teams = self._request(
            "GET", f"{self.org_url}/_apis/projects/{quote(self.project)}/teams", params={"$top": 500}
        ).get("value", [])
        wanted = {t.lower() for t in config.ADO_TEAMS}
        if wanted:
            teams = [t for t in teams if (t.get("name") or "").lower() in wanted]
        people: dict[str, dict] = {}
        for team in teams:
            members = self._request(
                "GET",
                f"{self.org_url}/_apis/projects/{quote(self.project)}/teams/{team['id']}/members",
                params={"$top": 500},
            ).get("value", [])
            for m in members:
                ident = m.get("identity") or {}
                if ident.get("isContainer"):
                    continue  # groupe, pas une personne
                unique = (ident.get("uniqueName") or "").strip()
                if not unique:
                    continue
                entry = people.setdefault(unique.lower(), {
                    "display_name": ident.get("displayName") or unique,
                    "unique_name": unique,
                    "teams": [],
                })
                entry["teams"].append(team.get("name"))
        return sorted(people.values(), key=lambda p: p["display_name"].lower())

    # -- anti-doublon
    def find_existing(self, ref: str) -> list[dict]:
        query = (
            "SELECT [System.Id] FROM WorkItems "
            "WHERE [System.TeamProject] = @project "
            f"AND [System.Tags] CONTAINS '{wiql_escape(ref)}' "
            "AND [System.State] <> 'Removed'"
        )
        data = self._request("POST", f"{self.project_url}/_apis/wit/wiql", json={"query": query})
        ids = [w["id"] for w in data.get("workItems", [])][:50]
        if not ids:
            return []
        items = self._request(
            "GET", f"{self.org_url}/_apis/wit/workitems",
            params={"ids": ",".join(map(str, ids)),
                    "fields": "System.Id,System.Title,System.State,System.WorkItemType,System.AssignedTo"},
        ).get("value", [])
        out = []
        for it in items:
            f = it.get("fields", {})
            who = f.get("System.AssignedTo")
            out.append({
                "id": it.get("id"),
                "title": f.get("System.Title", ""),
                "state": f.get("System.State", ""),
                "type": f.get("System.WorkItemType", ""),
                "assigned_to": who.get("displayName") if isinstance(who, dict) else (who or ""),
                "url": self.web_url(it.get("id")),
            })
        return out

    # -- création
    def create_work_item(self, work_item_type: str, ops: list[dict], validate_only: bool = False) -> dict:
        params = {"validateOnly": "true"} if validate_only else {}
        return self._request(
            "POST",
            f"{self.project_url}/_apis/wit/workitems/${quote(work_item_type)}",
            params=params,
            json=ops,
            headers={"Content-Type": "application/json-patch+json"},
        )

    def create_from_bulletin(self, bulletin: dict, assignees: list[dict], validate_only: bool = False) -> dict:
        """Crée le requirement (+ une Task par personne si plusieurs).
        Renvoie {"created": [...], "errors": [...]}. Pas de rollback : si une
        Task échoue, le requirement reste créé et l'erreur est remontée."""
        parent_api = self.api_url(config.ADO_PARENT_ID) if config.ADO_PARENT_ID else None
        req_ops = build_requirement_ops(
            bulletin, assignees[0] if assignees else None, parent_api,
            config.ADO_AREA_PATH, config.ADO_ITERATION_PATH, None, config.ADO_SET_PRIORITY,
        )
        result = {"created": [], "errors": []}
        req = self.create_work_item(config.ADO_WORK_ITEM_TYPE, req_ops, validate_only)
        if validate_only:
            result["validated"] = True
            return result
        req_id = req["id"]
        result["created"].append({
            "id": req_id, "type": config.ADO_WORK_ITEM_TYPE, "url": self.web_url(req_id),
            "assigned_to": assignees[0]["display_name"] if assignees else "",
            "title": build_title(bulletin), "parent_id": config.ADO_PARENT_ID or None,
        })
        if len(assignees) > 1:
            for a in assignees:
                try:
                    ops = build_task_ops(bulletin, a, self.api_url(req_id),
                                         config.ADO_AREA_PATH, config.ADO_ITERATION_PATH)
                    t = self.create_work_item(config.ADO_TASK_TYPE, ops)
                    result["created"].append({
                        "id": t["id"], "type": config.ADO_TASK_TYPE, "url": self.web_url(t["id"]),
                        "assigned_to": a["display_name"], "title": ops[0]["value"], "parent_id": req_id,
                    })
                except ADOError as exc:
                    result["errors"].append(f"Task pour {a['display_name']} : {exc}")
        return result
SENTINEL_V2_EOF
echo "  écrit : app/ado_client.py"

cat > app/agent_pipeline.py << 'SENTINEL_V2_EOF'
"""
Pipeline agentique : un agent Claude (API Anthropic, tool use) mène
l'investigation complète pour chaque bulletin CERT-FR (avis, alertes),
comme le ferait un analyste humain — recherches GLPI multiples, lecture du
texte intégral de l'avis, vérification croisée externe (security-tracker
Debian, cve.org...), avant de trancher.

V2 :
- Azure DevOps n'est plus une source d'analyse (outil ado_get_comments et
  association ticket↔bulletin supprimés) : ADO sert uniquement à CRÉER des
  requirements depuis le dashboard (voir ado_client.py).
- Le prompt système peut être remplacé par un fichier (AI_SYSTEM_PROMPT_FILE,
  dans output/ par défaut) : vos ajustements de prompt survivent aux mises à jour.
- max_tokens par appel réglable (AI_MAX_TOKENS_PER_CALL).
- Compteurs de cycle : appels, tokens, verdicts repris du cache, bulletins
  laissés en attente faute de budget (affichés dans le dashboard).

Si AI_ENABLED=false ou si la clé API manque, toutes les fonctions publiques
retombent sur un statut "a_verifier" documenté plutôt que de deviner.
"""
import hashlib
import json
import logging
import os

import requests
from bs4 import BeautifulSoup

import config
import db
from glpi_client import GLPIClient, GLPIError

log = logging.getLogger(__name__)


def _content_hash(bulletin: dict) -> str:
    """Empreinte du contenu pertinent d'un bulletin : si elle change (texte
    CERT-FR mis à jour...), le cache est invalidé et l'IA est relancée."""
    raw = "|".join([
        str(bulletin.get("ref", "")),
        str(bulletin.get("title", "")),
        str(bulletin.get("date", "")),
        str(bulletin.get("summary", ""))[:2000],
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

# Domaines externes autorisés pour la vérification croisée (évite qu'un
# agent aille chercher n'importe où sur le web).
ALLOWED_FETCH_DOMAINS = (
    "cert.ssi.gouv.fr",
    "security-tracker.debian.org",
    "www.cve.org",
    "cve.org",
    "nvd.nist.gov",
    "access.redhat.com",
    "ubuntu.com",
    "learn.microsoft.com",
    "msrc.microsoft.com",
    "endoflife.date",
)

DEFAULT_SYSTEM_PROMPT = """\
Tu es l'analyste sécurité de Sentinel CVE. Ton travail : pour CHAQUE bulletin \
(avis ou alerte CERT-FR), déterminer s'il concerne \
réellement le parc informatique décrit dans GLPI, avec des preuves \
vérifiables — jamais une supposition.

RÈGLES ABSOLUES
- N'invente JAMAIS un nom de poste, un numéro de version ou un chiffre. \
Tout doit venir d'un appel d'outil réel.
- Si l'avis vise une version/branche précise, VÉRIFIE la correspondance \
exacte avec ce qui est installé (ne confonds pas deux branches qui \
partagent un numéro proche — ex. paquet linux vs linux-6.12 sous Debian).
- Utilise list_search_options si tu ne connais pas l'ID d'un champ GLPI \
avant de faire une recherche dessus.
- Une recherche GLPI par nom de logiciel peut renvoyer des faux positifs \
(composants génériques, SDK...) : vérifie la pertinence avant de compter \
une installation comme concernée.
- Un même logiciel peut exister sous PLUSIEURS fiches Software distinctes \
dans GLPI (ex : un paquet Linux "mariadb-server" ET un exécutable Windows \
"MariaDB 10.3 (x64)" pour la même techno, avec des parcs de postes \
totalement différents). Avant de conclure, recherche d'abord TOUTES les \
fiches Software dont le nom contient le mot-clé du bulletin (glpi_search \
sur itemtype Software, recherche large "contains", insensible à la casse) \
— ne t'arrête JAMAIS à la première fiche trouvée. Vérifie ensuite les \
installations de CHACUNE des fiches pertinentes (glpi_software_install_count \
ou glpi_search sur Item_SoftwareVersion pour chaque software_id identifié), \
en couvrant tous les types d'équipements concernés (postes Windows, \
serveurs Linux, équipements réseau via glpi_network_equipment_by_manufacturer \
si pertinent). Le champ "hosts" du verdict final doit lister l'ensemble des \
équipements trouvés sur TOUTES ces fiches, pas seulement la première.
- Si l'information manque pour trancher avec certitude, statut \
"a_verifier" — jamais "concerne" ni "non_concerne" par défaut.
- Utilise fetch_external_page uniquement pour lever une ambiguïté précise \
(nomenclature éditeur, correspondance CVE↔paquet) — pas systématiquement.
- Termine TOUJOURS par un appel à l'outil submit_analysis. C'est le seul \
moyen de renvoyer ton verdict.
- Sois concis dans limit_note (2-4 phrases), factuel, mentionne les \
vérifications faites et leurs résultats chiffrés.
"""

# Compatibilité : certains scripts lisaient agent_pipeline.SYSTEM_PROMPT.
SYSTEM_PROMPT = DEFAULT_SYSTEM_PROMPT


def get_system_prompt() -> str:
    """Prompt personnalisé (fichier AI_SYSTEM_PROMPT_FILE) s'il existe et
    n'est pas vide, sinon le prompt par défaut ci-dessus. Relu à chaque
    bulletin : modifier le fichier suffit, sans redémarrer le conteneur."""
    path = config.AI_SYSTEM_PROMPT_FILE
    try:
        if path and os.path.isfile(path):
            with open(path, encoding="utf-8") as f:
                custom = f.read().strip()
            if custom:
                return custom
    except OSError as exc:
        log.warning("Prompt personnalisé illisible (%s) : prompt par défaut utilisé.", exc)
    return DEFAULT_SYSTEM_PROMPT


TOOLS = [
    {
        "name": "glpi_list_search_options",
        "description": "Liste les champs de recherche disponibles pour un type d'objet GLPI (ex: Computer, Software, NetworkEquipment), avec leur ID numérique. À utiliser avant glpi_search si l'ID d'un champ est inconnu.",
        "input_schema": {
            "type": "object",
            "properties": {"itemtype": {"type": "string", "description": "Ex: Computer, Software, NetworkEquipment"}},
            "required": ["itemtype"],
        },
    },
    {
        "name": "glpi_search",
        "description": "Recherche générique dans GLPI. criteria est une liste de {field, searchtype, value} (searchtype: 'contains' pour tout champ texte/liste, 'equals' seulement pour un ID numérique pur). Renvoie au plus 200 lignes.",
        "input_schema": {
            "type": "object",
            "properties": {
                "itemtype": {"type": "string"},
                "criteria": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "field": {"type": ["string", "integer"]},
                            "searchtype": {"type": "string", "enum": ["contains", "equals"]},
                            "value": {"type": "string"},
                        },
                        "required": ["field", "value"],
                    },
                },
                "forcedisplay": {"type": "array", "items": {"type": "integer"}, "description": "IDs de champs à inclure dans le résultat, ex: [1,3,48]"},
            },
            "required": ["itemtype", "criteria"],
        },
    },
    {
        "name": "glpi_count",
        "description": "Compte le nombre de résultats d'une recherche GLPI sans les rapatrier (rapide, pour vérifier avant une recherche complète).",
        "input_schema": {
            "type": "object",
            "properties": {
                "itemtype": {"type": "string"},
                "criteria": {"type": "array", "items": {"type": "object"}},
            },
            "required": ["itemtype", "criteria"],
        },
    },
    {
        "name": "glpi_hosts_with_kernel",
        "description": "Postes dont le champ noyau (kernel version, PAS la version de distribution générique) contient la chaîne donnée.",
        "input_schema": {
            "type": "object",
            "properties": {"kernel_contains": {"type": "string"}},
            "required": ["kernel_contains"],
        },
    },
    {
        "name": "glpi_software_install_count",
        "description": "Nombre d'installations d'un logiciel GLPI (par son ID Software), éventuellement filtré sur une version. Fiable pour compter, contrairement à une recherche texte libre sur Item_SoftwareVersion qui peut être polluée par d'autres logiciels partageant le même numéro.",
        "input_schema": {
            "type": "object",
            "properties": {
                "software_id": {"type": "integer"},
                "version_contains": {"type": "string"},
            },
            "required": ["software_id"],
        },
    },
    {
        "name": "glpi_network_equipment_by_manufacturer",
        "description": "Équipements réseau GLPI dont le fabricant contient la chaîne donnée (ex: Fortinet, Cisco, NetApp).",
        "input_schema": {
            "type": "object",
            "properties": {"manufacturer_contains": {"type": "string"}},
            "required": ["manufacturer_contains"],
        },
    },
    {
        "name": "certfr_fetch_detail",
        "description": "Récupère le texte intégral d'un avis/alerte CERT-FR à partir de son URL (systèmes affectés, versions corrigées, CVE listées).",
        "input_schema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "fetch_external_page",
        "description": (
            "Récupère le texte d'une page web externe de référence pour lever une ambiguïté précise "
            "(ex: security-tracker.debian.org pour savoir à quel paquet une CVE appartient, cve.org "
            "pour le détail d'une CVE). Domaines autorisés : " + ", ".join(ALLOWED_FETCH_DOMAINS)
        ),
        "input_schema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
]

SUBMIT_TOOL = {
    "name": "submit_analysis",
    "description": "Renvoie le verdict final pour ce bulletin. Appel obligatoire pour terminer l'analyse.",
    "input_schema": {
        "type": "object",
        "properties": {
            "status": {"type": "string", "enum": ["concerne", "a_verifier", "non_concerne"]},
            "hosts": {
                "type": "array",
                "description": "Postes concernés identifiés, avec preuve GLPI. Laisser vide si non applicable (ex: décompte agrégé seulement).",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "site": {"type": "string"},
                        "installed": {"type": "string"},
                        "target": {"type": "string"},
                    },
                    "required": ["name"],
                },
            },
            "count_label": {"type": "string", "description": "Ex: '13 postes', '4 installs / 7 total', '91 postes nommés / 4776 installs'"},
            "installed_summary": {"type": "string", "description": "Résumé bref des versions installées trouvées"},
            "target_version": {"type": "string", "description": "Version cible/corrigée d'après l'avis"},
            "type_label": {"type": "string", "description": "Ex: 'Application (base de données)', 'Noyau (kernel)', 'Agent de supervision'"},
            "limit_note": {"type": "string", "description": "2-4 phrases factuelles expliquant le verdict et les vérifications faites"},
        },
        "required": ["status", "limit_note"],
    },
}


class BudgetExceeded(Exception):
    """Levée quand le plafond d'appels ou de tokens du cycle est atteint."""


class _CycleBudget:
    """Compteur d'appels/tokens IA, remis à zéro à chaque cycle (reset_budget).
    Un seul cycle s'exécute à la fois (pas de concurrence dans ce projet),
    un état au niveau module est donc suffisant — pas besoin de le faire
    voyager en paramètre dans toute la chaîne d'appels."""

    def __init__(self, max_calls: int, max_tokens: int):
        self.max_calls = max_calls
        self.max_tokens = max_tokens
        self.calls = 0
        self.tokens = 0
        self.cached = 0   # bulletins dont le verdict vient du cache (0 appel)
        self.pending = 0  # bulletins non analysés faute de budget

    def check(self):
        if self.calls >= self.max_calls:
            raise BudgetExceeded(
                f"plafond de {self.max_calls} appels IA/cycle atteint "
                f"({self.calls} déjà effectués)"
            )
        if self.tokens >= self.max_tokens:
            raise BudgetExceeded(
                f"plafond de {self.max_tokens} tokens IA/cycle atteint "
                f"({self.tokens} déjà consommés)"
            )

    def record(self, usage) -> None:
        self.calls += 1
        if usage is not None:
            self.tokens += getattr(usage, "input_tokens", 0) + getattr(usage, "output_tokens", 0)

    def summary(self) -> str:
        return (f"{self.calls}/{self.max_calls} appels, {self.tokens}/{self.max_tokens} tokens, "
                f"{self.cached} depuis le cache, {self.pending} en attente de budget")

    def stats(self) -> dict:
        return {
            "calls": self.calls, "max_calls": self.max_calls,
            "tokens": self.tokens, "max_tokens": self.max_tokens,
            "cached": self.cached, "pending": self.pending,
        }


_budget = _CycleBudget(config.AI_MAX_CALLS_PER_CYCLE, config.AI_MAX_TOKENS_PER_CYCLE)


def reset_budget() -> None:
    """À appeler UNE FOIS au début de chaque cycle (main.run_cycle), avant
    tout appel IA. Remet le compteur à zéro pour le nouveau cycle."""
    global _budget
    _budget = _CycleBudget(config.AI_MAX_CALLS_PER_CYCLE, config.AI_MAX_TOKENS_PER_CYCLE)


def budget_summary() -> str:
    return _budget.summary()


def budget_stats() -> dict:
    return _budget.stats()


def _client():
    if not config.AI_ENABLED:
        return None
    if not config.ANTHROPIC_API_KEY:
        log.warning("AI_ENABLED=true mais ANTHROPIC_API_KEY manquante — analyse IA ignorée.")
        return None
    import anthropic
    return anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)


def _fallback(reason: str, pending: bool = False, ai_error: bool = False) -> dict:
    return {
        "pending_ai": pending,
        "ai_error": ai_error,
        "status": "a_verifier",
        "hosts": [],
        "count_label": "",
        "installed_summary": "",
        "target_version": "",
        "type_label": "",
        "limit_note": reason,
    }


def _dispatch_tool(name: str, tool_input: dict, glpi: GLPIClient) -> str:
    try:
        if name == "glpi_list_search_options":
            r = requests.get(
                f"{glpi.base_url}/listSearchOptions/{tool_input['itemtype']}",
                headers=glpi._headers(),
                timeout=30,
            )
            r.raise_for_status()
            # On tronque : la liste complète est très longue et coûte cher en tokens.
            data = r.json()
            trimmed = {
                k: {"name": v.get("name"), "field": v.get("field"), "table": v.get("table")}
                for k, v in data.items()
                if isinstance(v, dict) and "name" in v
            }
            return json.dumps(trimmed)[:6000]

        if name == "glpi_search":
            res = glpi.search_all(
                tool_input["itemtype"],
                tool_input.get("criteria", []),
                tool_input.get("forcedisplay"),
            )
            return json.dumps(res[:200])[:8000]

        if name == "glpi_count":
            n = glpi.count(tool_input["itemtype"], tool_input.get("criteria", []))
            return json.dumps({"count": n})

        if name == "glpi_hosts_with_kernel":
            res = glpi.hosts_with_kernel(tool_input["kernel_contains"])
            return json.dumps(res[:200])[:8000]

        if name == "glpi_software_install_count":
            n = glpi.software_install_count(
                tool_input["software_id"], tool_input.get("version_contains")
            )
            return json.dumps({"install_count": n})

        if name == "glpi_network_equipment_by_manufacturer":
            res = glpi.network_equipment_by_manufacturer(tool_input["manufacturer_contains"])
            return json.dumps(res[:200])[:8000]

        if name == "certfr_fetch_detail":
            import certfr_client
            detail = certfr_client.fetch_detail(tool_input["url"])
            return json.dumps({"text": detail["text"][:6000]})

        if name == "fetch_external_page":
            url = tool_input["url"]
            if not any(d in url for d in ALLOWED_FETCH_DOMAINS):
                return json.dumps({"error": f"Domaine non autorisé. Autorisés : {ALLOWED_FETCH_DOMAINS}"})
            r = requests.get(url, timeout=30, headers={"User-Agent": "sentinel-cve/1.0"})
            r.raise_for_status()
            soup = BeautifulSoup(r.text, "html.parser")
            text = soup.get_text("\n", strip=True)
            return json.dumps({"text": text[:6000]})

        return json.dumps({"error": f"Outil inconnu : {name}"})
    except GLPIError as exc:
        return json.dumps({"error": f"Erreur GLPI : {exc}"})
    except requests.RequestException as exc:
        return json.dumps({"error": f"Erreur réseau : {exc}"})
    except Exception as exc:  # noqa: BLE001 — un outil qui plante ne doit pas casser la boucle
        log.exception("Outil %s a échoué", name)
        return json.dumps({"error": str(exc)})


def analyze_bulletin(glpi: GLPIClient, bulletin: dict) -> dict:
    """Fait mener l'investigation complète d'un bulletin par l'agent.
    Renvoie {status, hosts, count_label, installed_summary, target_version,
    type_label, limit_note}."""
    client = _client()
    if client is None:
        return _fallback("Analyse IA désactivée (AI_ENABLED=false ou clé API absente) — statut par défaut.")

    ref = bulletin.get("ref", "")
    content_hash = _content_hash(bulletin)
    cached = db.get_cached_analysis(ref, content_hash, config.AI_CACHE_TTL_DAYS)
    if cached is not None:
        log.info(
            "Bulletin %s : verdict repris du cache (inchangé depuis < %d j) — aucun appel IA.",
            ref, config.AI_CACHE_TTL_DAYS,
        )
        _budget.cached += 1
        return cached

    user_prompt = (
        f"RÉFÉRENCE : {bulletin.get('ref')}\n"
        f"RUBRIQUE : {bulletin.get('kind', '')} {bulletin.get('alert_status', '')}\n"
        f"TITRE : {bulletin.get('title')}\n"
        f"DATE : {bulletin.get('date')}\n"
        f"LIEN : {bulletin.get('link')}\n"
        f"RÉSUMÉ (flux RSS, peut être incomplet) : {bulletin.get('summary', '')[:2000]}\n\n"
        "Mène l'investigation (GLPI, texte intégral de l'avis si besoin, vérification externe si besoin) "
        "et termine par submit_analysis."
    )

    messages = [{"role": "user", "content": user_prompt}]
    all_tools = TOOLS + [SUBMIT_TOOL]

    for _ in range(config.AI_MAX_TOOL_ITERATIONS):
        try:
            _budget.check()
        except BudgetExceeded as exc:
            log.warning("Budget IA épuisé pour %s : %s.", bulletin.get("ref"), exc)
            _budget.pending += 1
            return _fallback(
                f"En attente d'analyse : budget IA du cycle épuisé ({exc}). "
                "Sera analysé au prochain cycle.", pending=True,
            )

        try:
            resp = client.messages.create(
                model=config.ANTHROPIC_MODEL,
                max_tokens=config.AI_MAX_TOKENS_PER_CALL,
                system=get_system_prompt(),
                tools=all_tools,
                messages=messages,
            )
        except Exception as exc:  # noqa: BLE001
            log.error("Appel API Anthropic échoué pour %s : %s", bulletin.get("ref"), exc)
            return _fallback(f"Appel IA échoué : {exc}", ai_error=True)

        _budget.record(getattr(resp, "usage", None))

        tool_uses = [b for b in resp.content if b.type == "tool_use"]

        if not tool_uses:
            # Pas d'appel d'outil : l'agent n'a pas conclu correctement.
            return _fallback("L'agent n'a pas appelé submit_analysis — analyse incomplète.")

        submit = next((t for t in tool_uses if t.name == "submit_analysis"), None)
        if submit:
            result = dict(submit.input)
            result.setdefault("hosts", [])
            result.setdefault("count_label", "")
            result.setdefault("installed_summary", "")
            result.setdefault("target_version", "")
            result.setdefault("type_label", "")
            result["pending_ai"] = False
            db.save_analysis(ref, content_hash, result)
            return result

        # Sinon : exécuter les outils demandés et poursuivre la boucle.
        messages.append({"role": "assistant", "content": resp.content})
        tool_results = []
        for t in tool_uses:
            output = _dispatch_tool(t.name, t.input, glpi)
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": t.id,
                "content": output,
            })
        messages.append({"role": "user", "content": tool_results})

    return _fallback(f"Limite de {config.AI_MAX_TOOL_ITERATIONS} itérations atteinte sans conclusion — à revérifier manuellement.")


def write_changelog_entry(now_str: str, prev_score: int | None, new_score: int, counts: dict) -> str:
    """Rédige la ligne de changelog du cycle. Retombe sur une phrase
    déterministe si l'IA est désactivée."""
    delta = "" if prev_score is None else f" ({prev_score} → {new_score})"
    deterministic = (
        f"Cycle du {now_str} : {counts.get('concerne', 0)} concerné(s), "
        f"{counts.get('a_verifier', 0)} à vérifier, {counts.get('non_concerne', 0)} non concerné(s). "
        f"Score{delta} : {new_score}."
    )
    client = _client()
    if client is None:
        return deterministic
    try:
        _budget.check()
    except BudgetExceeded as exc:
        log.warning("Budget IA épuisé, changelog en version déterministe : %s.", exc)
        return deterministic
    try:
        prompt = (
            f"Rédige UNE phrase de changelog technique en français pour ce cycle Sentinel CVE, "
            f"factuelle et concise (style journal des modifications) :\n"
            f"Date : {now_str}\nScore précédent : {prev_score}\nNouveau score : {new_score}\n"
            f"Décompte : {counts}\n"
            "Ne mentionne que ces faits, n'invente rien d'autre."
        )
        resp = client.messages.create(
            model=config.ANTHROPIC_MODEL,
            max_tokens=200,
            messages=[{"role": "user", "content": prompt}],
        )
        _budget.record(getattr(resp, "usage", None))
        text = "".join(b.text for b in resp.content if b.type == "text").strip()
        return text or deterministic
    except Exception:  # noqa: BLE001
        return deterministic
SENTINEL_V2_EOF
echo "  écrit : app/agent_pipeline.py"

cat > app/stats.py << 'SENTINEL_V2_EOF'
"""Données des graphiques du dashboard — fonctions pures (testées).

Tout est calculé côté Python et injecté en JSON dans la page : le navigateur
ne fait que dessiner, il ne recalcule rien."""
import re
from collections import Counter
from datetime import date, timedelta

STATUSES = ("concerne", "a_verifier", "non_concerne")

_PRODUCT_RE = re.compile(
    r"\b(?:dans|affectant)\s+(?:les\s+produits\s+|le\s+produit\s+|les\s+|le\s+|la\s+|l['’]\s*)?(.+)$",
    re.IGNORECASE,
)
# Regroupements utiles : le titre CERT-FR dit « le noyau Linux de Debian »,
# « les produits Microsoft »… on veut des barres lisibles par éditeur/techno.
_ALIASES = {
    "noyau": "Linux (noyau)",
    "navigateurs": "Navigateurs",
}


def concerned_rate(counts: dict) -> float:
    total = counts.get("total") or sum(counts.get(s, 0) or 0 for s in STATUSES)
    return round(100 * (counts.get("concerne") or 0) / total, 1) if total else 0.0


def status_counts(bulletins: list[dict]) -> dict:
    c = Counter(b.get("status") for b in bulletins)
    out = {s: c.get(s, 0) for s in STATUSES}
    out["total"] = sum(out.values())
    return out


def by_kind(bulletins: list[dict]) -> dict:
    out: dict[str, dict] = {}
    for b in bulletins:
        k = out.setdefault(b.get("kind") or "autre", {s: 0 for s in STATUSES})
        if b.get("status") in STATUSES:
            k[b["status"]] += 1
    return out


def product_of(title: str) -> str:
    """« Multiples vulnérabilités dans les produits Veeam » -> « Veeam »
    (premier mot du produit = éditeur ou techno, pour regrouper)."""
    m = _PRODUCT_RE.search(title or "")
    label = (m.group(1) if m else (title or "")).strip(" .")
    if not label:
        return "Autre"
    first = label.split()[0].strip(",;:()")
    return _ALIASES.get(first.lower(), first[:1].upper() + first[1:])


def top_products(bulletins: list[dict], statuses=("concerne", "a_verifier"), n: int = 10) -> list[dict]:
    per: dict[str, Counter] = {}
    for b in bulletins:
        if b.get("status") not in statuses:
            continue
        per.setdefault(product_of(b.get("title", "")), Counter())[b["status"]] += 1
    rows = [{"label": k, **{s: v.get(s, 0) for s in STATUSES}, "total": sum(v.values())} for k, v in per.items()]
    rows.sort(key=lambda r: (-r.get("concerne", 0), -r["total"], r["label"]))
    return rows[:n]


def weekly(bulletins: list[dict], weeks: int = 13, today: date | None = None) -> list[dict]:
    """Bulletins publiés par semaine (lundi->dimanche), empilés par statut."""
    today = today or date.today()
    this_monday = today - timedelta(days=today.weekday())
    buckets = []
    for i in range(weeks - 1, -1, -1):
        start = this_monday - timedelta(weeks=i)
        buckets.append({"start": start.isoformat(), "label": f"S{start.isocalendar()[1]:02d}",
                        **{s: 0 for s in STATUSES}})
    index = {b["start"]: b for b in buckets}
    for b in bulletins:
        try:
            d = date.fromisoformat((b.get("date") or "")[:10])
        except ValueError:
            continue
        monday = (d - timedelta(days=d.weekday())).isoformat()
        if monday in index and b.get("status") in STATUSES:
            index[monday][b["status"]] += 1
    return buckets


def rate_history(history: list[dict]) -> list[dict]:
    """Historique du taux de bulletins concernés (cycles V2 seulement : les
    cycles V1 n'enregistraient pas le décompte par statut)."""
    out = []
    for h in history:
        if h.get("total"):
            out.append({
                "ts": h["ts"],
                "rate": concerned_rate(h),
                "concerne": h.get("concerne") or 0,
                "a_verifier": h.get("a_verifier") or 0,
                "non_concerne": h.get("non_concerne") or 0,
                "total": h["total"],
            })
    return out


def build_chart_data(bulletins: list[dict], history: list[dict], cycle_runs: list[dict]) -> dict:
    return {
        "status": status_counts(bulletins),
        "by_kind": by_kind(bulletins),
        "weekly": weekly(bulletins),
        "top_products": top_products(bulletins),
        "score_history": [{"ts": h["ts"], "score": h["score"]} for h in history],
        "rate_history": rate_history(history),
        "cycles": cycle_runs,
    }
SENTINEL_V2_EOF
echo "  écrit : app/stats.py"

cat > app/main.py << 'SENTINEL_V2_EOF'
"""
Orchestrateur V2 : CERT-FR (toutes rubriques) × GLPI -> agent IA -> score -> HTML.
Azure DevOps n'est plus lu : il sert uniquement à créer des requirements
depuis le dashboard (webapi.py + ado_client.py).

Usage :
  python main.py            # scheduler (cycle planifié) + serveur HTTP interne
  python main.py --once     # un seul cycle puis quitte
"""
import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from zoneinfo import ZoneInfo

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from jinja2 import Environment, FileSystemLoader

import agent_pipeline
import certfr_client
import config
import db
import scoring
import stats
import webapi
from glpi_client import GLPIClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("main")

TZ = ZoneInfo(config.TIMEZONE)

STATUS_LABELS = {"concerne": "Concerné", "a_verifier": "À vérifier", "non_concerne": "Non concerné"}


def sort_bulletins(bulletins: list[dict]) -> list[dict]:
    """Alertes d'abord (priorité du budget IA), puis du plus récent au plus ancien."""
    bulletins.sort(key=lambda b: b.get("date") or "", reverse=True)
    bulletins.sort(key=lambda b: 0 if b.get("kind") == "alerte" else 1)  # tri stable
    return bulletins


def _source(name: str, state: str, detail: str, count: int | None = None, **extra) -> dict:
    return {"name": name, "state": state, "detail": detail, "count": count, **extra}


def collect_certfr() -> tuple[list[dict], list[dict], dict]:
    try:
        data = certfr_client.collect_all()
    except Exception as exc:  # noqa: BLE001
        log.error("CERT-FR injoignable : %s", exc)
        return [], [], _source("CERT-FR", "down", f"Injoignable : {exc}")
    health = data["health"]
    states = [h["state"] for h in health.values()]
    state = "down" if all(s == "down" for s in states) else ("degraded" if any(s != "ok" for s in states) else "ok")
    detail = " · ".join(
        f"{certfr_client.SECTION_LABELS.get(sec, sec)} {h['count']}"
        + (f" ({h['pages']} p.)" if h.get("pages") else "")
        + ("" if h["state"] == "ok" else f" ⚠ {h['mode'] or 'erreur'}")
        for sec, h in health.items()
    )
    errors = [f"{sec} : {h['error']}" for sec, h in health.items() if h.get("error")]
    log.info("CERT-FR : %d bulletins analysables, %d publications d'information.",
             len(data["bulletins"]), len(data["info"]))
    return data["bulletins"], data["info"], _source(
        "CERT-FR", state, detail, len(data["bulletins"]) + len(data["info"]), errors=errors,
    )


def analyze_all(bulletins: list[dict]) -> tuple[list[dict], dict, dict]:
    """Analyse chaque bulletin. Si GLPI est injoignable, AUCUN bulletin n'est
    déclaré « non concerné » : tous passent « à vérifier » (règle D6)."""
    glpi_health = _source("GLPI", "ok", "Session API ouverte", None)
    try:
        with GLPIClient() as glpi:
            for b in bulletins:
                b.update(agent_pipeline.analyze_bulletin(glpi, b))
    except Exception as exc:  # noqa: BLE001
        log.error("GLPI injoignable : %s", exc)
        glpi_health = _source("GLPI", "down", f"Injoignable : {exc}")
        for b in bulletins:
            if "status" not in b:
                b.update(agent_pipeline._fallback(
                    "GLPI injoignable pendant ce cycle : impossible de vérifier l'inventaire."
                ))
    for b in bulletins:
        b["status_label"] = STATUS_LABELS[b["status"]]
    counts = stats.status_counts(bulletins)
    return bulletins, counts, glpi_health


def ai_source() -> dict:
    s = agent_pipeline.budget_stats()
    if not config.AI_ENABLED:
        return _source("Claude (IA)", "off", "Désactivé (AI_ENABLED=false)", **s)
    if not config.ANTHROPIC_API_KEY:
        return _source("Claude (IA)", "down", "Clé ANTHROPIC_API_KEY absente", **s)
    detail = f"{s['calls']} appels · {s['tokens']:,} tokens · {s['cached']} depuis le cache".replace(",", " ")
    state = "ok"
    if s["pending"]:
        state = "degraded"
        detail += f" · {s['pending']} en attente (budget atteint)"
    return _source("Claude (IA)", state, detail, **s)


def ado_source() -> dict:
    if not config.ADO_WRITE_ENABLED:
        return _source("Azure DevOps", "off", "Création de requirements désactivée (ADO_WRITE_ENABLED=false)")
    if not (config.ADO_ORG and config.ADO_PROJECT and config.ADO_PAT):
        return _source("Azure DevOps", "down", "ADO_ORG / ADO_PROJECT / ADO_PAT incomplets")
    return _source("Azure DevOps", "ok",
                   f"Écriture : {config.ADO_WORK_ITEM_TYPE} dans « {config.ADO_PROJECT} »"
                   + (f", sous #{config.ADO_PARENT_ID}" if config.ADO_PARENT_ID else ""))


def run_cycle(trigger: str = "manuel (CLI)"):
    log.info("--- Nouveau cycle Sentinel CVE (%s) ---", trigger)
    t0 = time.monotonic()
    now = datetime.now(TZ)
    now_str = now.strftime("%d/%m/%Y %Hh%M")
    agent_pipeline.reset_budget()

    bulletins, info, certfr_health = collect_certfr()
    sort_bulletins(bulletins)
    bulletins, counts, glpi_health = analyze_all(bulletins)
    sources = {
        "certfr": certfr_health,
        "glpi": glpi_health,
        "ai": ai_source(),
        "ado": ado_source(),
    }

    partial_reasons = [f"{s['name']} injoignable" for s in (certfr_health, glpi_health) if s["state"] == "down"]
    score = scoring.compute_score(counts["concerne"], counts["a_verifier"], counts["non_concerne"])
    prev_score = db.latest_score()
    if not partial_reasons:
        # On n'enregistre pas un cycle partiel : il fausserait les courbes.
        db.insert_score(now, score, counts)
        changelog_entry = agent_pipeline.write_changelog_entry(now_str, prev_score, score, counts)
        db.insert_changelog_entry(now, changelog_entry)
    else:
        db.insert_changelog_entry(now, f"Cycle du {now_str} partiel ({', '.join(partial_reasons)}) : score non enregistré.")

    db.replace_cycle_bulletins(bulletins)
    ai = agent_pipeline.budget_stats()
    duration = time.monotonic() - t0
    db.insert_cycle_run(now, trigger, duration, ai, len(bulletins), sources)
    log.info("Score : %d/100 (%d bulletins). Budget IA : %s. Durée : %.0fs.",
             score, counts["total"], agent_pipeline.budget_summary(), duration)

    render(bulletins=bulletins, info=info, counts=counts, now_str=now_str, score=score,
           sources=sources, partial_reasons=partial_reasons)


def render(bulletins, info, counts, now_str, score, sources, partial_reasons=None):
    env = Environment(
        loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), "templates")),
        autoescape=True,  # titres/résumés issus de flux externes : échappés par défaut
    )
    tpl = env.get_template("dashboard.html.j2")

    history = db.get_history()
    cycle_runs = db.get_cycle_runs()
    chart_data = stats.build_chart_data(bulletins, history, cycle_runs)
    ado_created = db.get_ado_creations_by_ref()
    for b in bulletins:
        b["ado_items"] = ado_created.get(b["ref"], [])

    avis = [b for b in bulletins if b.get("kind") == "avis"]
    alertes = [b for b in bulletins if b.get("kind") == "alerte"]
    pending = sum(1 for b in bulletins if b.get("pending_ai"))

    html = tpl.render(
        generated_at=f"{now_str} ({config.TIMEZONE})",
        score=score,
        band=scoring.score_band(score),
        counts=counts,
        rate=stats.concerned_rate(counts),
        pending=pending,
        avis=avis,
        alertes=alertes,
        info=info,
        info_labels=certfr_client.SECTION_LABELS,
        bulletins=bulletins,
        sources=sources,
        # "<" échappé : un titre contenant "</script>" ne doit pas casser la page (XSS).
        chart_json=json.dumps(chart_data, default=str).replace("<", "\\u003c"),
        changelog=db.get_changelog(),
        ai_enabled=config.AI_ENABLED,
        actions_enabled=bool(config.ACTION_TOKEN),
        ado_enabled=config.ADO_WRITE_ENABLED and bool(config.ACTION_TOKEN),
        ado_type=config.ADO_WORK_ITEM_TYPE,
        ado_parent_id=config.ADO_PARENT_ID,
        lookback_days=config.CERTFR_LOOKBACK_DAYS,
        schedule=f"{config.SCHEDULE_CRON_HOUR}h{int(config.SCHEDULE_CRON_MINUTE):02d}"
        if str(config.SCHEDULE_CRON_HOUR).isdigit() and str(config.SCHEDULE_CRON_MINUTE).isdigit()
        else f"cron heure={config.SCHEDULE_CRON_HOUR} minute={config.SCHEDULE_CRON_MINUTE}",
        partial_reasons=partial_reasons or [],
    )

    os.makedirs(config.OUTPUT_DIR, exist_ok=True)
    out_path = os.path.join(config.OUTPUT_DIR, "index.html")
    tmp_path = out_path + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(html)
    os.replace(tmp_path, out_path)  # écriture atomique : nginx ne sert jamais une page à moitié écrite
    log.info("Dashboard écrit : %s", out_path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="Exécute un seul cycle puis quitte.")
    args = parser.parse_args()

    db.init_db()

    if args.once:
        run_cycle("manuel (CLI)")
        return

    scheduler = BackgroundScheduler(timezone=str(TZ))
    scheduler.add_job(
        lambda: webapi.run_scheduled(run_cycle),
        CronTrigger(minute=config.SCHEDULE_CRON_MINUTE, hour=config.SCHEDULE_CRON_HOUR, timezone=str(TZ)),
        id="sentinel_cycle",
    )
    log.info("Scheduler démarré (cron: minute=%s hour=%s, tz=%s). Premier cycle immédiat.",
             config.SCHEDULE_CRON_MINUTE, config.SCHEDULE_CRON_HOUR, config.TIMEZONE)
    scheduler.start()
    webapi.run_scheduled(run_cycle, "démarrage")  # en arrière-plan : l'API répond pendant le 1er cycle

    if not config.ACTION_TOKEN:
        log.info("ACTION_TOKEN non défini : boutons « Lancer maintenant » et « Créer dans ADO » inactifs.")

    flask_app = webapi.create_app(run_cycle)
    try:
        flask_app.run(host="0.0.0.0", port=config.TRIGGER_PORT, threaded=True)
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        scheduler.shutdown(wait=False)


if __name__ == "__main__":
    sys.exit(main())
SENTINEL_V2_EOF
echo "  écrit : app/main.py"

cat > app/webapi.py << 'SENTINEL_V2_EOF'
"""Serveur HTTP interne (relayé par nginx sous /api/).

- GET  /api/status          : état du cycle (public)
- POST /api/auth/check      : vérifie le jeton d'action saisi dans le navigateur
- POST /api/trigger         : lance un cycle maintenant
- GET  /api/ado/people      : personnes présentes dans les équipes ADO du projet
- POST /api/ado/preview     : prévisualise ce qui sera créé (validateOnly, anti-doublon)
- POST /api/ado/create      : crée le requirement (+ Tasks si plusieurs personnes)

Sécurité (V2) : toutes les actions exigent l'en-tête X-Action-Token. Le jeton
n'est PLUS écrit dans la page HTML (V1) : l'utilisateur le saisit une fois,
il reste en mémoire de l'onglet. Comparaison à temps constant + délai sur
échec pour freiner le brute-force. Le contenu du requirement est toujours
reconstruit côté serveur à partir de la base : le navigateur n'envoie qu'une
référence de bulletin et des identifiants de personnes.
"""
import hmac
import logging
import threading
import time
from functools import wraps

from flask import Flask, jsonify, request

import config
import db
from ado_client import ADOClient, ADOError, plan_items

log = logging.getLogger("webapi")

MAX_ASSIGNEES = 10
PEOPLE_CACHE_TTL_S = 600

_lock = threading.Lock()
_create_lock = threading.Lock()
_state = {
    "running": False,
    "last_started_at": None,
    "last_finished_at": None,
    "last_error": None,
    "last_trigger": None,
}
_people_cache = {"ts": 0.0, "data": None}


def ado_client_factory() -> ADOClient:
    """Point d'injection (remplacé par un faux client dans les tests)."""
    return ADOClient()


# ------------------------------------------------------------ cycles
def _run_in_background(run_cycle_fn, trigger_label: str) -> bool:
    with _lock:
        if _state["running"]:
            return False
        _state["running"] = True
        _state["last_started_at"] = time.time()
        _state["last_error"] = None
        _state["last_trigger"] = trigger_label

    def _worker():
        try:
            run_cycle_fn(trigger_label)
        except Exception as exc:  # noqa: BLE001 — un cycle qui plante ne doit pas tuer le serveur web
            log.exception("Cycle (%s) : échec", trigger_label)
            _state["last_error"] = str(exc)
        finally:
            _state["running"] = False
            _state["last_finished_at"] = time.time()

    threading.Thread(target=_worker, daemon=True, name="cycle-worker").start()
    return True


def run_scheduled(run_cycle_fn, trigger_label: str = "planifié") -> None:
    if not _run_in_background(run_cycle_fn, trigger_label):
        log.warning("Cycle %s ignoré : un cycle est déjà en cours.", trigger_label)


# ------------------------------------------------------------ sécurité
def _token_ok() -> bool:
    expected = config.ACTION_TOKEN
    given = request.headers.get("X-Action-Token") or request.headers.get("X-Trigger-Token") or ""
    return bool(expected) and hmac.compare_digest(given.encode("utf-8"), expected.encode("utf-8"))


def require_token(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not config.ACTION_TOKEN:
            return jsonify({"error": "Actions désactivées (ACTION_TOKEN non configuré dans .env)."}), 403
        if not _token_ok():
            time.sleep(0.5)
            log.warning("Jeton d'action invalide depuis %s sur %s", request.headers.get("X-Real-IP", request.remote_addr), request.path)
            return jsonify({"error": "Jeton invalide."}), 403
        return fn(*args, **kwargs)
    return wrapper


def require_ado(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not config.ADO_WRITE_ENABLED:
            return jsonify({"error": "Création ADO désactivée (ADO_WRITE_ENABLED=false)."}), 403
        if not (config.ADO_ORG and config.ADO_PROJECT and config.ADO_PAT):
            return jsonify({"error": "ADO_ORG / ADO_PROJECT / ADO_PAT incomplets dans .env."}), 503
        return fn(*args, **kwargs)
    return wrapper


# ------------------------------------------------------------ ADO helpers
def _people(force: bool = False) -> list[dict]:
    if force or _people_cache["data"] is None or time.time() - _people_cache["ts"] > PEOPLE_CACHE_TTL_S:
        _people_cache["data"] = ado_client_factory().list_people()
        _people_cache["ts"] = time.time()
    return _people_cache["data"]


def _parse_request() -> tuple[dict | None, list[dict] | None, tuple | None]:
    """Valide {ref, assignees:[unique_name,...]} -> (bulletin, personnes, erreur)."""
    body = request.get_json(silent=True) or {}
    ref = str(body.get("ref") or "").strip()
    wanted = body.get("assignees") or []
    if not ref:
        return None, None, (jsonify({"error": "Référence de bulletin manquante."}), 400)
    if not isinstance(wanted, list) or not wanted:
        return None, None, (jsonify({"error": "Choisissez au moins une personne."}), 400)
    if len(wanted) > MAX_ASSIGNEES:
        return None, None, (jsonify({"error": f"{MAX_ASSIGNEES} personnes maximum."}), 400)
    bulletin = db.get_cycle_bulletin(ref)
    if bulletin is None:
        return None, None, (jsonify({"error": f"Bulletin {ref} absent du dernier cycle."}), 404)
    people = {p["unique_name"].lower(): p for p in _people()}
    chosen, unknown = [], []
    for u in dict.fromkeys(str(x).strip() for x in wanted):
        (chosen.append(people[u.lower()]) if u.lower() in people else unknown.append(u))
    if unknown:
        return None, None, (jsonify({"error": f"Personne(s) inconnue(s) dans ADO : {', '.join(unknown)}"}), 400)
    return bulletin, chosen, None


# ------------------------------------------------------------ application
def create_app(run_cycle_fn) -> Flask:
    app = Flask(__name__)

    @app.route("/api/status")
    def status():
        return jsonify(_state)

    @app.route("/api/auth/check", methods=["POST"])
    @require_token
    def auth_check():
        return jsonify({"ok": True, "ado_enabled": config.ADO_WRITE_ENABLED})

    @app.route("/api/trigger", methods=["POST"])
    @require_token
    def trigger():
        if not _run_in_background(run_cycle_fn, "manuel"):
            return jsonify({"error": "Un cycle est déjà en cours."}), 409
        return jsonify({"status": "démarré"}), 202

    @app.route("/api/ado/people")
    @require_token
    @require_ado
    def ado_people():
        try:
            return jsonify({"people": _people(force=request.args.get("refresh") == "1")})
        except ADOError as exc:
            return jsonify({"error": str(exc)}), 502
        except Exception as exc:  # noqa: BLE001
            log.exception("Liste des personnes ADO")
            return jsonify({"error": f"Azure DevOps injoignable : {exc}"}), 502

    @app.route("/api/ado/preview", methods=["POST"])
    @require_token
    @require_ado
    def ado_preview():
        try:
            bulletin, chosen, err = _parse_request()
            if err:
                return err
            client = ado_client_factory()
            existing = client.find_existing(bulletin["ref"])
            validation_error = None
            try:
                client.create_from_bulletin(bulletin, chosen, validate_only=True)
            except ADOError as exc:
                validation_error = str(exc)
            return jsonify({
                "ref": bulletin["ref"],
                "plan": plan_items(bulletin, chosen),
                "existing": existing,
                "validation_error": validation_error,
            })
        except ADOError as exc:
            return jsonify({"error": str(exc)}), 502
        except Exception as exc:  # noqa: BLE001
            log.exception("Prévisualisation ADO")
            return jsonify({"error": f"Azure DevOps injoignable : {exc}"}), 502

    @app.route("/api/ado/create", methods=["POST"])
    @require_token
    @require_ado
    def ado_create():
        if not _create_lock.acquire(blocking=False):
            return jsonify({"error": "Une création est déjà en cours, réessayez dans quelques secondes."}), 409
        try:
            bulletin, chosen, err = _parse_request()
            if err:
                return err
            body = request.get_json(silent=True) or {}
            client = ado_client_factory()
            existing = client.find_existing(bulletin["ref"])
            if existing and not body.get("allow_duplicate"):
                return jsonify({
                    "error": "Un work item existe déjà pour ce bulletin.",
                    "existing": existing,
                }), 409
            result = client.create_from_bulletin(bulletin, chosen)
            for item in result["created"]:
                db.insert_ado_creation(bulletin["ref"], item["id"], item["type"], item["title"],
                                       item["assigned_to"], item["url"], item.get("parent_id")
                                       if isinstance(item.get("parent_id"), int) else None)
            log.info("ADO : %d work item(s) créé(s) pour %s (%s).", len(result["created"]),
                     bulletin["ref"], ", ".join(p["display_name"] for p in chosen))
            return jsonify(result), 201 if not result["errors"] else 207
        except ADOError as exc:
            return jsonify({"error": str(exc)}), 502
        except Exception as exc:  # noqa: BLE001
            log.exception("Création ADO")
            return jsonify({"error": f"Azure DevOps injoignable : {exc}"}), 502
        finally:
            _create_lock.release()

    return app
SENTINEL_V2_EOF
echo "  écrit : app/webapi.py"

cat > app/templates/_bulletin.html.j2 << 'SENTINEL_V2_EOF'
<details class="bulletin" data-status="{{ b.status }}" data-kind="{{ b.kind }}"{% if b.ado_items %} data-ado="1"{% endif %}>
  <summary>
    <span class="b-ref">{{ b.ref | replace("CERTFR-", "") }}<span class="date">{{ b.date[:10] if b.date else "" }}</span></span>
    <span class="b-title">{{ b.title }}
      {% if b.alert_status %}<span class="tag {{ 'tag-live' if 'cours' in b.alert_status else '' }}">{{ b.alert_status }}</span>{% endif %}
      {% if b.pending_ai %}<span class="tag">en attente IA</span>{% endif %}
      {% for w in b.ado_items %}{% if loop.first %}<span class="tag tag-ado">ADO #{{ w.id }}{% if b.ado_items|length > 1 %} +{{ b.ado_items|length - 1 }}{% endif %}</span>{% endif %}{% endfor %}
    </span>
    <span class="pill {{ b.status }}">{{ b.status_label }}</span>
    <span class="b-count">{{ b.count_label }}</span>
    <span class="chev" aria-hidden="true">▶</span>
  </summary>
  <div class="b-body">
    {% if b.installed_summary or b.target_version or b.type_label %}
    <div class="b-meta">
      {% if b.installed_summary %}<div><b>Installé</b><span class="mono">{{ b.installed_summary }}</span></div>{% endif %}
      {% if b.target_version %}<div><b>Version cible</b><span class="mono">{{ b.target_version }}</span></div>{% endif %}
      {% if b.type_label %}<div><b>Catégorie</b><span>{{ b.type_label }}</span></div>{% endif %}
    </div>
    {% endif %}
    {% if b.summary %}<p class="b-summary">{{ b.summary | truncate(400) }}</p>{% endif %}
    <div class="b-actions">
      {% if b.link %}<a class="b-cta" href="{{ b.link }}" target="_blank" rel="noopener">CERT-FR ↗</a>{% endif %}
      {% if ado_enabled %}
      <button type="button" class="b-cta b-ado" data-ado-ref="{{ b.ref }}" data-ado-title="{{ b.title }}">＋ Créer un {{ ado_type }} ADO</button>
      {% endif %}
      {% for w in b.ado_items %}
      <a class="b-link mono" href="{{ w.url }}" target="_blank" rel="noopener">{{ w.type }} #{{ w.id }}{% if w.assigned_to %} · {{ w.assigned_to }}{% endif %} ↗</a>
      {% endfor %}
    </div>
    {% if b.hosts %}
    <div class="host-table-wrap">
      <table class="hosts">
        <thead><tr><th>Équipement</th><th>Site</th><th>Version installée</th><th>Cible</th></tr></thead>
        <tbody>
          {% for h in b.hosts %}
          <tr>
            <td class="mono">{{ h.name }}</td>
            <td>{{ h.site or "—" }}</td>
            <td class="mono">{{ h.installed or "non renseigné" }}</td>
            <td class="mono">{{ h.target or b.target_version or "—" }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% endif %}
    {% if b.limit_note %}<div class="limit-note">{{ b.limit_note }}</div>{% endif %}
  </div>
</details>
SENTINEL_V2_EOF
echo "  écrit : app/templates/_bulletin.html.j2"

cat > app/templates/dashboard.html.j2 << 'SENTINEL_V2_EOF'
<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Sentinel CVE</title>
<meta name="description" content="Publications CERT-FR croisées avec l'inventaire GLPI, création de requirements Azure DevOps.">
<style>
  :root{
    --bg:#080c16; --sidebar:#0a0f1c; --surface:#101828; --surface-2:#0c1220; --surface-3:#080c16;
    --surface-hover:#141f34; --border:#1e2a42; --border-soft:#161f33;
    --text:#eef1f8; --text-dim:#95a1bd; --text-faint:#5f6a8a;
    --accent:#4da3ff; --accent-2:#7c9eff; --accent-soft:#152845; --accent-glow:rgba(77,163,255,.18);
    --crit:#f0564d; --crit-bg:#241318; --crit-bd:#472029;
    --warn:#f0a83e; --warn-bg:#241d10; --warn-bd:#47361a;
    --ok:#32d296; --ok-bg:#0e2019; --ok-bd:#1a3c2e;
    --off:#5f6a8a;
    --radius-lg:14px; --radius-md:10px; --radius-sm:7px;
    --shadow-1:0 1px 2px rgba(0,0,0,.35); --shadow-2:0 8px 24px -8px rgba(0,0,0,.5);
    color-scheme: dark;
  }
  *{box-sizing:border-box;}
  ::selection{ background:var(--accent-glow); color:var(--text); }
  body{ background:var(--bg); color:var(--text); margin:0; display:flex; min-height:100vh; font-family:"Manrope",system-ui,-apple-system,sans-serif; -webkit-font-smoothing:antialiased; }
  h1,h2,h3{ text-wrap:balance; }
  a{ color:inherit; }
  [hidden]{ display:none !important; }
  .mono{ font-family:"IBM Plex Mono",ui-monospace,monospace; font-variant-numeric:tabular-nums; }

  /* ---------- sidebar ---------- */
  .sidebar{ width:232px; flex:0 0 232px; background:var(--sidebar); border-right:1px solid var(--border-soft); padding:20px 14px; display:flex; flex-direction:column; gap:20px; position:sticky; top:0; align-self:flex-start; height:100vh; overflow-y:auto; }
  .brand{ display:flex; align-items:center; gap:11px; padding:2px 6px 16px; border-bottom:1px solid var(--border-soft); }
  .brand .mark{ width:34px; height:34px; border-radius:10px; flex:none; background:radial-gradient(circle at 32% 28%, var(--accent-2), var(--accent) 55%, #1b4d85 100%); box-shadow:0 0 0 1px rgba(255,255,255,.06) inset, 0 4px 14px -4px var(--accent-glow); display:flex; align-items:center; justify-content:center; }
  .brand .mark svg{ width:18px; height:18px; }
  .brand .names{ display:flex; flex-direction:column; line-height:1.3; }
  .brand .names b{ font-size:14.5px; font-weight:800; letter-spacing:-.01em; }
  .brand .names span{ font-size:10.5px; color:var(--text-faint); font-weight:600; letter-spacing:.04em; text-transform:uppercase; }
  nav{ display:flex; flex-direction:column; gap:2px; }
  nav a{ display:flex; align-items:center; justify-content:space-between; gap:8px; padding:9px 10px 9px 12px; border-radius:8px; color:var(--text-dim); text-decoration:none; font-size:13.5px; font-weight:600; transition:background .12s, color .12s; border-left:2px solid transparent; }
  nav a:hover{ background:var(--surface); color:var(--text); }
  nav a.active{ background:var(--accent-soft); color:var(--text); border-left-color:var(--accent); }
  nav a .count{ font-family:"IBM Plex Mono",monospace; font-size:10.5px; font-weight:600; color:var(--text-faint); background:var(--surface-2); border:1px solid var(--border); border-radius:20px; padding:1px 7px; }
  nav a.active .count{ color:var(--accent); border-color:var(--accent-soft); }
  nav a .lbl-short{ display:none; }
  .side-sources{ margin-top:auto; padding-top:14px; border-top:1px solid var(--border-soft); display:flex; flex-direction:column; gap:8px; font-size:11.5px; color:var(--text-dim); }
  .side-sources b{ font-size:10.5px; text-transform:uppercase; letter-spacing:.05em; color:var(--text-faint); }
  .dot{ width:8px; height:8px; border-radius:50%; flex:none; display:inline-block; background:var(--off); }
  .dot.ok{ background:var(--ok); box-shadow:0 0 0 3px var(--ok-bg); }
  .dot.degraded{ background:var(--warn); box-shadow:0 0 0 3px var(--warn-bg); }
  .dot.down{ background:var(--crit); box-shadow:0 0 0 3px var(--crit-bg); }
  .src-row{ display:flex; align-items:center; gap:9px; }

  @media (max-width:860px){
    body{ flex-direction:column; }
    .sidebar{ width:100%; flex:none; height:auto; position:sticky; top:0; z-index:5; flex-direction:row; align-items:center; padding:10px 14px; gap:10px; overflow-x:auto; border-right:none; border-bottom:1px solid var(--border-soft); }
    .brand{ border-bottom:none; padding:0; flex:none; }
    .brand .names{ display:none; }
    nav{ flex-direction:row; gap:3px; flex:1 1 auto; }
    nav a{ white-space:nowrap; padding:7px 9px; border-left:none; border-bottom:2px solid transparent; gap:5px; font-size:12.5px; }
    nav a.active{ border-left-color:transparent; border-bottom-color:var(--accent); }
    nav a .lbl-full{ display:none; } nav a .lbl-short{ display:inline; }
    .side-sources{ display:none; }
  }

  /* ---------- layout ---------- */
  main{ flex:1; min-width:0; padding:22px 34px 70px; max-width:1680px; margin:0 auto; width:100%; }
  @media (max-width:860px){ main{ padding:16px 16px 50px; } }
  .topbar{ display:flex; flex-wrap:wrap; gap:14px; align-items:flex-start; justify-content:space-between; margin-bottom:18px; }
  .topbar h1{ font-size:21px; margin:0; font-weight:800; letter-spacing:-.015em; }
  .topbar .sub{ font-size:12.5px; color:var(--text-dim); margin-top:3px; max-width:62ch; line-height:1.5; }
  .toolbar{ display:flex; gap:8px; align-items:center; flex-wrap:wrap; background:var(--surface); border:1px solid var(--border); border-radius:var(--radius-md); padding:8px 10px; box-shadow:var(--shadow-1); max-width:100%; }
  input[type="search"], input[type="password"], input[type="text"]{ background:var(--surface-2); border:1px solid var(--border); color:var(--text); border-radius:7px; padding:8px 12px; font-size:13px; font-family:inherit; min-width:0; }
  .toolbar input[type="search"]{ flex:1 1 190px; max-width:260px; }
  input:focus, button:focus-visible, a:focus-visible{ outline:2px solid var(--accent); outline-offset:2px; }
  .segmented{ display:flex; gap:2px; background:var(--surface-2); border:1px solid var(--border); border-radius:7px; padding:2px; }
  .seg-btn{ font-family:inherit; font-size:12px; font-weight:700; color:var(--text-dim); background:transparent; border:none; padding:6px 10px; border-radius:5px; cursor:pointer; white-space:nowrap; }
  .seg-btn:hover{ color:var(--text); }
  .seg-btn.active{ background:var(--surface); color:var(--text); box-shadow:var(--shadow-1); }
  .seg-btn.active.st-crit{ color:var(--crit); } .seg-btn.active.st-warn{ color:var(--warn); } .seg-btn.active.st-ok{ color:var(--ok); }
  @media (max-width:640px){ .toolbar{ width:100%; } .toolbar input[type="search"]{ flex-basis:100%; max-width:100%; } .segmented{ overflow-x:auto; max-width:100%; } }
  .ghost-btn, .primary-btn{ font-family:inherit; font-size:12px; font-weight:700; border-radius:7px; padding:7px 12px; cursor:pointer; white-space:nowrap; }
  .ghost-btn{ color:var(--text-dim); background:var(--surface); border:1px solid var(--border); }
  .ghost-btn:hover{ color:var(--text); border-color:var(--accent-soft); }
  .primary-btn{ color:#06101f; background:var(--accent); border:1px solid var(--accent); }
  .primary-btn:hover{ filter:brightness(1.1); }
  .primary-btn:disabled, .ghost-btn:disabled{ opacity:.5; cursor:not-allowed; filter:none; }
  .lock-state{ font-size:11.5px; color:var(--text-faint); }
  .lock-state.on{ color:var(--ok); }

  .banner{ display:flex; gap:10px; align-items:flex-start; padding:12px 14px; border-radius:var(--radius-md); font-size:12.5px; line-height:1.55; margin-bottom:18px; background:var(--warn-bg); border:1px solid var(--warn-bd); color:var(--warn); }
  .banner.crit{ background:var(--crit-bg); border-color:var(--crit-bd); color:var(--crit); }

  section{ margin-bottom:34px; scroll-margin-top:18px; }
  .section-title{ display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:13px; flex-wrap:wrap; }
  .section-title h2{ font-size:16px; margin:0; font-weight:800; letter-spacing:-.01em; }
  .section-title .note{ font-size:12px; color:var(--text-faint); }
  .section-actions{ display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
  .card{ background:var(--surface); border:1px solid var(--border); border-radius:var(--radius-lg); padding:18px 20px; box-shadow:var(--shadow-1); min-width:0; }
  .card h3{ font-size:13.5px; margin:0; font-weight:800; }
  .card .ch{ display:flex; align-items:baseline; justify-content:space-between; gap:10px; flex-wrap:wrap; margin-bottom:12px; }
  .card .note{ font-size:11.5px; color:var(--text-faint); }

  /* ---------- overview ---------- */
  .overview-grid{ display:grid; grid-template-columns:minmax(0,290px) minmax(0,290px) minmax(0,1fr); gap:14px; margin-bottom:14px; }
  @media (max-width:1180px){ .overview-grid{ grid-template-columns:minmax(0,1fr) minmax(0,1fr); } .overview-grid .trend{ grid-column:1 / -1; } }
  @media (max-width:640px){ .overview-grid{ grid-template-columns:minmax(0,1fr); } }
  .score-card{ display:flex; flex-direction:column; align-items:center; text-align:center; }
  .gauge-wrap{ position:relative; width:210px; max-width:100%; }
  .gauge-wrap svg{ display:block; width:100%; height:auto; }
  .gauge-center{ position:absolute; left:0; right:0; top:56%; text-align:center; }
  .big-num{ font-family:"IBM Plex Mono",monospace; font-size:36px; font-weight:700; line-height:1; letter-spacing:-.02em; }
  .big-num .of{ font-size:15px; color:var(--text-faint); font-weight:500; }
  .score-label{ font-size:11px; color:var(--text-faint); margin-top:8px; font-weight:700; text-transform:uppercase; letter-spacing:.05em; }
  .score-band{ display:inline-flex; align-items:center; font-size:11.5px; font-weight:600; margin-top:9px; padding:4px 11px; border-radius:999px; }
  .score-delta{ font-family:"IBM Plex Mono",monospace; font-size:11px; font-weight:700; margin-top:7px; padding:2px 8px; border-radius:999px; }
  .score-delta.up{ color:var(--ok); background:var(--ok-bg); } .score-delta.down{ color:var(--crit); background:var(--crit-bg); }
  .formula{ margin-top:12px; font-size:11px; color:var(--text-faint); line-height:1.6; border-top:1px solid var(--border-soft); padding-top:10px; text-align:left; }
  .rate-card{ display:flex; flex-direction:column; align-items:center; text-align:center; }
  .donut-wrap{ position:relative; width:170px; max-width:100%; }
  .donut-wrap svg{ display:block; width:100%; height:auto; }
  .donut-center{ position:absolute; inset:0; display:flex; flex-direction:column; align-items:center; justify-content:center; }
  .donut-center .big-num{ font-size:30px; color:var(--crit); }
  .donut-center small{ font-size:10.5px; color:var(--text-faint); font-weight:700; text-transform:uppercase; letter-spacing:.05em; margin-top:4px; }
  .legend-inline{ display:flex; flex-wrap:wrap; gap:6px 14px; justify-content:center; margin-top:12px; font-size:11.5px; color:var(--text-dim); }
  .legend-inline span{ display:inline-flex; align-items:center; gap:6px; }
  .legend-inline i{ width:9px; height:9px; border-radius:3px; display:inline-block; }
  .chart-svg{ display:block; width:100%; height:auto; }
  .chart-empty{ padding:12px 14px; background:var(--surface-2); border:1px solid var(--border-soft); border-radius:8px; font-size:12px; color:var(--text-dim); margin-top:8px; line-height:1.5; }

  .kpis{ display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:14px; margin-bottom:30px; }
  @media (max-width:1180px){ .kpis{ grid-template-columns:repeat(3,minmax(0,1fr)); } }
  @media (max-width:640px){ .kpis{ grid-template-columns:repeat(2,minmax(0,1fr)); } }
  .kpi{ background:var(--surface); border:1px solid var(--border); border-radius:var(--radius-lg); padding:14px 16px; border-top:2.5px solid var(--border); box-shadow:var(--shadow-1); display:flex; flex-direction:column; gap:6px; min-width:0; }
  .kpi.crit{ border-top-color:var(--crit); } .kpi.warn{ border-top-color:var(--warn); } .kpi.ok{ border-top-color:var(--ok); } .kpi.acc{ border-top-color:var(--accent); }
  .kpi .label{ font-size:10.5px; text-transform:uppercase; letter-spacing:.05em; color:var(--text-faint); font-weight:700; }
  .kpi .value{ font-family:"IBM Plex Mono",monospace; font-size:24px; font-weight:700; }
  .kpi .value .of{ font-size:12px; color:var(--text-faint); font-weight:500; }
  .kpi .sub{ font-size:11.5px; color:var(--text-dim); line-height:1.45; }

  /* ---------- charts ---------- */
  .charts-grid{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:14px; }
  .charts-grid .wide{ grid-column:1 / -1; }
  @media (max-width:980px){ .charts-grid{ grid-template-columns:minmax(0,1fr); } }
  .hbars{ display:flex; flex-direction:column; gap:9px; }
  .hbar{ display:grid; grid-template-columns:minmax(0,130px) minmax(0,1fr) 68px; gap:10px; align-items:center; font-size:12.5px; }
  .hbar .lbl{ overflow:hidden; text-overflow:ellipsis; white-space:nowrap; color:var(--text-dim); font-weight:600; }
  .hbar .track{ display:flex; height:14px; background:var(--surface-2); border-radius:4px; overflow:hidden; }
  .hbar .track span{ display:block; height:100%; }
  .hbar .val{ text-align:right; color:var(--text-dim); font-size:11.5px; white-space:nowrap; }

  /* ---------- sources ---------- */
  .sources-grid{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:14px; }
  .source-card .name{ display:flex; align-items:center; gap:9px; font-weight:800; font-size:13.5px; }
  .source-card .state{ margin-left:auto; font-size:10.5px; text-transform:uppercase; letter-spacing:.05em; font-weight:700; color:var(--text-faint); }
  .source-card .state.ok{ color:var(--ok); } .source-card .state.degraded{ color:var(--warn); } .source-card .state.down{ color:var(--crit); }
  .source-card p{ margin:10px 0 0; font-size:12px; color:var(--text-dim); line-height:1.55; overflow-wrap:anywhere; }
  .source-card .err{ color:var(--warn); font-size:11.5px; }
  .source-card.soon{ border-style:dashed; background:transparent; box-shadow:none; }

  /* ---------- bulletins ---------- */
  .pill{ display:inline-flex; align-items:center; gap:6px; padding:3px 10px; border-radius:999px; font-size:11px; font-weight:700; border:1px solid transparent; white-space:nowrap; }
  .pill::before{ content:""; width:6px; height:6px; border-radius:50%; background:currentColor; }
  .pill.concerne{ background:var(--crit-bg); color:var(--crit); border-color:var(--crit-bd); }
  .pill.a_verifier{ background:var(--warn-bg); color:var(--warn); border-color:var(--warn-bd); }
  .pill.non_concerne{ background:var(--ok-bg); color:var(--ok); border-color:var(--ok-bd); }
  .tag{ display:inline-block; margin-left:6px; padding:1px 7px; border-radius:5px; font-size:10.5px; font-weight:700; color:var(--text-dim); background:var(--surface-2); border:1px solid var(--border); vertical-align:1px; white-space:nowrap; }
  .tag-live{ color:var(--crit); border-color:var(--crit-bd); background:var(--crit-bg); }
  .tag-ado{ color:var(--accent); border-color:var(--accent-soft); background:var(--accent-soft); }
  .bulletins{ display:flex; flex-direction:column; gap:8px; }
  details.bulletin{ background:var(--surface); border:1px solid var(--border); border-left:3px solid var(--border); border-radius:var(--radius-md); overflow:hidden; box-shadow:var(--shadow-1); }
  details.bulletin[data-status="concerne"]{ border-left-color:var(--crit); }
  details.bulletin[data-status="a_verifier"]{ border-left-color:var(--warn); }
  details.bulletin[data-status="non_concerne"]{ border-left-color:var(--ok); }
  details.bulletin[open]{ border-color:var(--accent-soft); box-shadow:var(--shadow-2); }
  details.bulletin summary{ list-style:none; cursor:pointer; padding:12px 16px; display:grid; grid-template-columns:100px 1fr auto auto 16px; gap:14px; align-items:center; }
  details.bulletin summary:hover{ background:var(--surface-hover); }
  details.bulletin summary::-webkit-details-marker{ display:none; }
  .b-ref{ font-family:"IBM Plex Mono",monospace; font-size:11.5px; color:var(--text-faint); }
  .b-ref .date{ display:block; margin-top:2px; }
  .b-title{ font-size:13.5px; font-weight:700; line-height:1.45; min-width:0; overflow-wrap:break-word; }
  .b-count{ font-family:"IBM Plex Mono",monospace; font-size:12px; color:var(--text-dim); text-align:right; white-space:nowrap; }
  .chev{ color:var(--text-faint); transition:transform .15s; font-size:11px; }
  details.bulletin[open] .chev{ transform:rotate(90deg); color:var(--accent); }
  @media (max-width:760px){
    details.bulletin summary{ grid-template-columns:minmax(0,1fr) auto; grid-template-areas:"ref chev" "title title" "pill count"; row-gap:6px; }
    details.bulletin summary .b-ref{ grid-area:ref; } details.bulletin summary .chev{ grid-area:chev; }
    details.bulletin summary .b-title{ grid-area:title; } details.bulletin summary .pill{ grid-area:pill; justify-self:start; }
    details.bulletin summary .b-count{ grid-area:count; white-space:normal; }
  }
  .b-body{ padding:0 16px 16px; border-top:1px solid var(--border-soft); }
  .b-meta{ display:flex; flex-wrap:wrap; gap:22px; padding:14px 0 4px; font-size:12.5px; }
  .b-meta div b{ display:block; font-size:10.5px; text-transform:uppercase; letter-spacing:.05em; color:var(--text-faint); font-weight:700; margin-bottom:3px; }
  .b-summary{ font-size:12.5px; color:var(--text-dim); line-height:1.6; margin:10px 0 0; max-width:95ch; }
  .b-actions{ display:flex; flex-wrap:wrap; gap:8px; align-items:center; margin:14px 0; }
  .b-cta{ display:inline-flex; align-items:center; gap:6px; padding:7px 13px; border-radius:8px; background:var(--accent-soft); color:var(--accent); text-decoration:none; font-size:12.5px; font-weight:700; border:1px solid var(--accent-soft); font-family:inherit; cursor:pointer; }
  .b-cta:hover{ filter:brightness(1.2); }
  .b-ado{ background:transparent; border-color:var(--accent); }
  .b-link{ font-size:11.5px; color:var(--accent); text-decoration:none; padding:5px 9px; border:1px solid var(--border); border-radius:7px; }
  .host-table-wrap{ overflow:auto; max-height:360px; border:1px solid var(--border-soft); border-radius:8px; }
  table.data{ width:100%; border-collapse:collapse; }
  table.hosts{ width:100%; border-collapse:collapse; min-width:520px; }
  table.hosts th, table.hosts td, table.data th, table.data td{ text-align:left; padding:8px 13px; font-size:12.5px; border-bottom:1px solid var(--border-soft); vertical-align:top; }
  table.hosts th, table.data th{ font-size:10.5px; text-transform:uppercase; letter-spacing:.05em; color:var(--text-faint); background:var(--surface-2); font-weight:700; position:sticky; top:0; z-index:1; }
  table.hosts tbody tr:hover, table.data tbody tr:hover{ background:var(--surface-hover); }
  .table-wrap{ overflow:auto; max-height:520px; border:1px solid var(--border); border-radius:var(--radius-md); background:var(--surface); }
  .empty-note{ padding:12px 14px; background:var(--surface-2); border:1px solid var(--border-soft); border-radius:8px; font-size:12.5px; color:var(--text-dim); line-height:1.55; }
  .limit-note{ margin-top:10px; font-size:11.5px; color:var(--text-faint); line-height:1.6; max-width:110ch; }
  .more-row{ display:flex; justify-content:center; margin-top:10px; }

  /* ---------- aide / footer ---------- */
  .help-grid{ display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:14px; }
  .help-card b{ display:block; font-size:10.5px; text-transform:uppercase; letter-spacing:.05em; color:var(--text-faint); font-weight:700; margin-bottom:8px; }
  .help-card p{ margin:0; font-size:12.5px; color:var(--text-dim); line-height:1.6; }
  .help-card a{ color:var(--accent); }
  footer{ margin-top:38px; padding-top:20px; border-top:1px solid var(--border-soft); font-size:12px; color:var(--text-faint); line-height:1.7; max-width:90ch; }
  footer strong{ color:var(--text-dim); }
  .changelog{ background:var(--surface); border:1px solid var(--border); border-radius:var(--radius-md); padding:2px 16px; margin:14px 0; }
  .changelog summary{ cursor:pointer; padding:12px 0; font-size:12px; font-weight:700; color:var(--text-dim); }
  .changelog-body{ padding:12px 0 14px; border-top:1px solid var(--border-soft); }

  /* ---------- modales ---------- */
  dialog{ background:var(--surface); color:var(--text); border:1px solid var(--border); border-radius:var(--radius-lg); padding:0; width:min(640px, calc(100vw - 32px)); max-height:calc(100vh - 48px); box-shadow:0 24px 60px -12px rgba(0,0,0,.7); }
  dialog::backdrop{ background:rgba(3,6,12,.72); }
  .dlg-head{ padding:16px 20px; border-bottom:1px solid var(--border-soft); display:flex; align-items:flex-start; gap:12px; }
  .dlg-head h3{ margin:0; font-size:15px; font-weight:800; }
  .dlg-head p{ margin:4px 0 0; font-size:12px; color:var(--text-dim); line-height:1.5; }
  .dlg-head .x{ margin-left:auto; }
  .dlg-body{ padding:16px 20px; display:flex; flex-direction:column; gap:12px; overflow:auto; max-height:calc(100vh - 220px); }
  .dlg-foot{ padding:14px 20px; border-top:1px solid var(--border-soft); display:flex; gap:8px; justify-content:flex-end; flex-wrap:wrap; align-items:center; }
  .dlg-foot .msg{ margin-right:auto; font-size:12px; color:var(--text-dim); }
  .msg.err{ color:var(--crit); } .msg.ok{ color:var(--ok); }
  .field label{ display:block; font-size:10.5px; text-transform:uppercase; letter-spacing:.05em; color:var(--text-faint); font-weight:700; margin-bottom:6px; }
  .field input{ width:100%; }
  .people-list{ display:flex; flex-direction:column; gap:2px; max-height:260px; overflow:auto; border:1px solid var(--border-soft); border-radius:8px; padding:4px; background:var(--surface-2); }
  .person{ display:flex; align-items:center; gap:10px; padding:7px 9px; border-radius:6px; cursor:pointer; font-size:13px; }
  .person:hover{ background:var(--surface-hover); }
  .person input{ accent-color:var(--accent); width:16px; height:16px; }
  .person .who{ min-width:0; }
  .person .who small{ display:block; color:var(--text-faint); font-size:11px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .chips{ display:flex; flex-wrap:wrap; gap:6px; min-height:28px; }
  .chip{ display:inline-flex; align-items:center; gap:6px; padding:4px 6px 4px 10px; border-radius:999px; background:var(--accent-soft); color:var(--text); font-size:12px; font-weight:600; }
  .chip.lead{ background:var(--accent); color:#06101f; }
  .chip button{ background:transparent; border:none; color:inherit; cursor:pointer; font-size:13px; padding:0 4px; opacity:.75; }
  .chip button:hover{ opacity:1; }
  .plan{ display:flex; flex-direction:column; gap:6px; }
  .plan-item{ display:grid; grid-template-columns:auto 1fr; gap:4px 10px; padding:10px 12px; background:var(--surface-2); border:1px solid var(--border-soft); border-radius:8px; font-size:12.5px; }
  .plan-item .t{ grid-column:2; color:var(--text-dim); font-size:11.5px; }
  .plan-item.task{ margin-left:22px; }
  .hint{ font-size:11.5px; color:var(--text-faint); line-height:1.5; }
  .warn-box{ padding:10px 12px; border-radius:8px; background:var(--warn-bg); border:1px solid var(--warn-bd); color:var(--warn); font-size:12.5px; line-height:1.5; }
  .warn-box a{ color:inherit; }
  .crit-box{ padding:10px 12px; border-radius:8px; background:var(--crit-bg); border:1px solid var(--crit-bd); color:var(--crit); font-size:12.5px; line-height:1.5; overflow-wrap:anywhere; }
  .ok-box{ padding:10px 12px; border-radius:8px; background:var(--ok-bg); border:1px solid var(--ok-bd); color:var(--ok); font-size:12.5px; line-height:1.7; }
  .ok-box a{ color:inherit; }
  .check-line{ display:flex; gap:8px; align-items:center; font-size:12.5px; color:var(--text-dim); }
</style>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;500;600;700;800&family=IBM+Plex+Mono:wght@400;500;600;700&display=swap">
</head>
<body>

<aside class="sidebar">
  <div class="brand">
    <div class="mark">
      <svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="2.4" fill="#fff" stroke="none"/>
        <path d="M12 3v3.4M12 17.6V21M3 12h3.4M17.6 12H21" opacity=".9"/>
        <circle cx="12" cy="12" r="7.5" opacity=".55"/>
      </svg>
    </div>
    <div class="names"><b>Sentinel CVE</b><span>V2 · CERT-FR × GLPI</span></div>
  </div>
  <nav id="nav">
    <a href="#overview" class="active"><span class="lbl-full">Vue d'ensemble</span><span class="lbl-short">Vue</span></a>
    <a href="#graphiques"><span class="lbl-full">Graphiques</span><span class="lbl-short">Graphes</span></a>
    <a href="#alertes"><span class="lbl-full">Alertes</span><span class="lbl-short">Alertes</span> <span class="count">{{ alertes|length }}</span></a>
    <a href="#avis"><span class="lbl-full">Avis</span><span class="lbl-short">Avis</span> <span class="count">{{ avis|length }}</span></a>
    <a href="#publications"><span class="lbl-full">Autres publications</span><span class="lbl-short">Infos</span> <span class="count">{{ info|length }}</span></a>
    <a href="#sources"><span class="lbl-full">Sources</span><span class="lbl-short">Sources</span></a>
    <a href="#aide"><span class="lbl-full">Comment ça marche ?</span><span class="lbl-short">Aide</span></a>
  </nav>
  <div class="side-sources">
    <b>État des sources</b>
    {% for key, s in sources.items() %}
    <div class="src-row" title="{{ s.detail }}"><span class="dot {{ s.state }}"></span>{{ s.name }}</div>
    {% endfor %}
  </div>
</aside>

<main>
  <div class="topbar">
    <div>
      <h1>Veille CERT-FR × inventaire</h1>
      <div class="sub">Généré le {{ generated_at }} · fenêtre de {{ lookback_days }} jours · cycle automatique à {{ schedule }}{% if not ai_enabled %} · agent IA désactivé : tous les bulletins restent « à vérifier »{% endif %}</div>
    </div>
    <div class="toolbar">
      <div class="segmented" role="group" aria-label="Filtrer par statut" id="statusFilter">
        <button type="button" class="seg-btn active" data-status="">Tous</button>
        <button type="button" class="seg-btn st-crit" data-status="concerne">Concerné</button>
        <button type="button" class="seg-btn st-warn" data-status="a_verifier">À vérifier</button>
        <button type="button" class="seg-btn st-ok" data-status="non_concerne">Non concerné</button>
      </div>
      <input type="search" id="searchInput" placeholder="Rechercher (réf., produit, poste…)" aria-label="Rechercher">
      {% if actions_enabled %}
      <button type="button" class="ghost-btn" id="unlockBtn" title="Saisir le jeton d'action pour lancer un cycle ou créer dans ADO">🔒 Actions</button>
      <button type="button" class="ghost-btn" id="runNowBtn" title="Lance un nouveau cycle maintenant">↻ Lancer maintenant</button>
      <span class="lock-state" id="runNowStatus"></span>
      {% endif %}
    </div>
  </div>

  {% if partial_reasons %}
  <div class="banner crit">⚠ Cycle partiel : {{ partial_reasons | join(", ") }}. Le score de ce cycle n'est pas enregistré dans l'historique et aucun bulletin n'est déclaré « non concerné » faute de pouvoir vérifier.</div>
  {% endif %}
  {% if pending %}
  <div class="banner">⏳ {{ pending }} bulletin(s) en attente d'analyse : le budget IA du cycle a été atteint. Ils seront analysés aux prochains cycles (les verdicts déjà obtenus sont gardés en cache). Pour accélérer, augmentez AI_MAX_CALLS_PER_CYCLE / AI_MAX_TOKENS_PER_CYCLE dans .env.</div>
  {% endif %}

  <div class="empty-note" id="searchEmpty" hidden style="margin-bottom:18px">
    Aucun bulletin ne correspond à votre recherche ou filtre. <button type="button" id="resetFiltersBtn" class="ghost-btn" style="margin-left:6px;">Réinitialiser</button>
  </div>

  <section id="overview">
    <div class="overview-grid">
      <div class="card score-card">
        <div class="gauge-wrap">
          <svg viewBox="0 0 200 110" aria-hidden="true">
            <path d="M20,100 A80,80 0 0 1 180,100" fill="none" stroke="var(--surface-3)" stroke-width="14" stroke-linecap="round"/>
            <path d="M20,100 A80,80 0 0 1 180,100" fill="none" stroke="var(--{{ band.key }})" stroke-width="14" stroke-linecap="round" stroke-dasharray="{{ (score / 100 * 251.3) | round(1) }} 300"/>
          </svg>
          <div class="gauge-center"><div class="big-num">{{ score }}<span class="of">/100</span></div></div>
        </div>
        <div class="score-label">Score de conformité</div>
        <span class="score-band" style="background:var(--{{ band.key }}-bg); color:var(--{{ band.key }}); border:1px solid var(--{{ band.key }}-bd)">{{ band.label }}</span>
        <span class="score-delta" id="scoreDelta"></span>
        <div class="formula">(non concerné × 1 + à vérifier × 0,5) / total, sur {{ counts.total }} bulletin(s). Pondéré par bulletin, pas par poste.</div>
      </div>

      <div class="card rate-card">
        <div class="donut-wrap">
          <svg id="donutSvg" class="chart-svg" viewBox="0 0 120 120" role="img" aria-label="Répartition des bulletins par statut"></svg>
          <div class="donut-center"><div class="big-num">{{ rate }}<span class="of">%</span></div><small>concernés</small></div>
        </div>
        <div class="legend-inline">
          <span><i style="background:var(--crit)"></i>{{ counts.concerne }} concerné(s)</span>
          <span><i style="background:var(--warn)"></i>{{ counts.a_verifier }} à vérifier</span>
          <span><i style="background:var(--ok)"></i>{{ counts.non_concerne }} non concerné(s)</span>
        </div>
      </div>

      <div class="card trend">
        <div class="ch"><h3>Score et taux de concernés</h3><span class="note">un point par cycle complet</span></div>
        <svg id="trendSvg" class="chart-svg" viewBox="0 0 640 190" role="img" aria-label="Évolution du score et du taux de bulletins concernés"></svg>
        <div id="trendEmpty" class="chart-empty" hidden></div>
        <div class="legend-inline" style="justify-content:flex-start">
          <span><i style="background:var(--accent)"></i>Score /100</span>
          <span><i style="background:var(--crit)"></i>% de bulletins concernés</span>
        </div>
      </div>
    </div>

    <div class="kpis">
      <div class="kpi crit"><div class="label">Concernés</div><div class="value">{{ counts.concerne }} <span class="of">/ {{ counts.total }}</span></div><div class="sub">Mise à jour requise sur au moins un équipement.</div></div>
      <div class="kpi warn"><div class="label">À vérifier</div><div class="value">{{ counts.a_verifier }}</div><div class="sub">Donnée d'inventaire insuffisante pour trancher{% if pending %}, dont {{ pending }} en attente IA{% endif %}.</div></div>
      <div class="kpi ok"><div class="label">Non concernés</div><div class="value">{{ counts.non_concerne }}</div><div class="sub">Absent du parc, déjà à jour ou hors périmètre.</div></div>
      <div class="kpi acc"><div class="label">Alertes en cours</div><div class="value">{{ alertes | selectattr("alert_status", "equalto", "Alerte en cours") | list | length }}</div><div class="sub">Sur {{ alertes|length }} alerte(s) suivie(s).</div></div>
      <div class="kpi"><div class="label">Requirements ADO</div><div class="value">{{ bulletins | selectattr("ado_items") | list | length }}</div><div class="sub">Bulletins déjà transmis à Azure DevOps depuis Sentinel.</div></div>
    </div>
  </section>

  <section id="graphiques">
    <div class="section-title"><h2>Graphiques</h2><span class="note">Calculés sur les {{ counts.total }} avis et alertes de la fenêtre</span></div>
    <div class="charts-grid">
      <div class="card wide">
        <div class="ch"><h3>Taux de bulletins concernés par cycle</h3><span class="note">répartition en % de chaque cycle · ligne = % concernés</span></div>
        <svg id="rateSvg" class="chart-svg" viewBox="0 0 900 220" role="img" aria-label="Répartition des statuts par cycle"></svg>
        <div id="rateEmpty" class="chart-empty" hidden></div>
      </div>
      <div class="card">
        <div class="ch"><h3>Publications par semaine</h3><span class="note">13 dernières semaines, par statut</span></div>
        <svg id="weeklySvg" class="chart-svg" viewBox="0 0 640 230" role="img" aria-label="Bulletins publiés par semaine"></svg>
        <div class="ch" style="margin:18px 0 10px"><h3>Avis et alertes par statut</h3><span class="note">nombre de bulletins</span></div>
        <div class="hbars" id="kindBars"></div>
        <div class="legend-inline" style="justify-content:flex-start">
          <span><i style="background:var(--crit)"></i>Concerné</span><span><i style="background:var(--warn)"></i>À vérifier</span><span><i style="background:var(--ok)"></i>Non concerné</span>
        </div>
      </div>
      <div class="card">
        <div class="ch"><h3>Éditeurs et technos les plus exposés</h3><span class="note">concernés + à vérifier</span></div>
        <div class="hbars" id="productsBars"></div>
      </div>
      <div class="card wide">
        <div class="ch"><h3>Consommation IA par cycle</h3><span class="note">tokens (barres) · plafond {{ "{:,}".format(sources.ai.max_tokens or 0).replace(",", " ") }}</span></div>
        <svg id="budgetSvg" class="chart-svg" viewBox="0 0 900 200" role="img" aria-label="Tokens consommés par cycle"></svg>
        <div id="budgetEmpty" class="chart-empty" hidden></div>
      </div>
    </div>
  </section>

  <section id="alertes">
    <div class="section-title">
      <h2>Alertes CERT-FR</h2>
      <span class="note">{{ alertes|length }} alerte(s) · menaces actives, à traiter en priorité</span>
    </div>
    <div class="bulletins" data-list>
      {% for b in alertes %}{% include "_bulletin.html.j2" %}{% else %}<div class="empty-note">Aucune alerte CERT-FR dans la fenêtre de suivi.</div>{% endfor %}
    </div>
  </section>

  <section id="avis">
    <div class="section-title">
      <h2>Avis CERT-FR</h2>
      <span class="note">{{ avis|length }} avis sur {{ lookback_days }} jours</span>
      <div class="section-actions">
        <button type="button" class="ghost-btn" id="expandAllBtn">Tout déplier</button>
        <button type="button" class="ghost-btn" id="collapseAllBtn">Tout replier</button>
      </div>
    </div>
    <div class="bulletins" data-list data-page="50">
      {% for b in avis %}{% include "_bulletin.html.j2" %}{% else %}<div class="empty-note">Aucun avis CERT-FR dans la fenêtre de suivi.</div>{% endfor %}
    </div>
  </section>

  <section id="publications">
    <div class="section-title">
      <h2>Autres publications CERT-FR</h2>
      <span class="note">pour information : non croisées avec l'inventaire, hors score</span>
      <div class="segmented" id="infoFilter" role="group" aria-label="Filtrer par rubrique">
        <button type="button" class="seg-btn active" data-kind="">Toutes</button>
        {% for k in info | map(attribute="kind") | unique %}<button type="button" class="seg-btn" data-kind="{{ k }}">{{ info_labels.get(k, k) }}</button>{% endfor %}
      </div>
    </div>
    {% if info %}
    <div class="table-wrap">
      <table class="data">
        <thead><tr><th>Date</th><th>Rubrique</th><th>Référence</th><th>Titre</th></tr></thead>
        <tbody id="infoBody">
          {% for p in info %}
          <tr data-kind="{{ p.kind }}">
            <td class="mono" style="white-space:nowrap">{{ p.date }}</td>
            <td style="white-space:nowrap">{{ info_labels.get(p.kind, p.kind) }}</td>
            <td class="mono" style="white-space:nowrap"><a href="{{ p.link }}" target="_blank" rel="noopener">{{ p.ref | replace("CERTFR-", "") }} ↗</a></td>
            <td>{{ p.title }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    {% else %}
    <div class="empty-note">Aucune autre publication dans la fenêtre (ou rubriques désactivées via CERTFR_INFO_SECTIONS).</div>
    {% endif %}
  </section>

  <section id="sources">
    <div class="section-title"><h2>Sources</h2><span class="note">état constaté pendant le dernier cycle</span></div>
    <div class="sources-grid">
      {% for key, s in sources.items() %}
      <div class="card source-card">
        <div class="name"><span class="dot {{ s.state }}"></span>{{ s.name }}<span class="state {{ s.state }}">{{ {"ok": "OK", "degraded": "Dégradé", "down": "En panne", "off": "Désactivé"}[s.state] }}</span></div>
        <p>{{ s.detail }}</p>
        {% for e in s.errors or [] %}<p class="err">{{ e }}</p>{% endfor %}
      </div>
      {% endfor %}
      <div class="card source-card soon">
        <div class="name"><span class="dot"></span>Catalyst Center · FortiManager · FortiAnalyzer<span class="state">À venir</span></div>
        <p>Versions des équipements réseau (IOS-XE, FortiOS). Seront branchés dès que les accès API seront disponibles.</p>
      </div>
    </div>
  </section>

  <section id="aide">
    <div class="section-title"><h2>Comment ça marche ?</h2><span class="note">GLPI en lecture seule · ADO uniquement à la demande</span></div>
    <div class="help-grid">
      <div class="card help-card"><b>Sources</b><p>Toutes les publications <a href="https://www.cert.ssi.gouv.fr/" target="_blank" rel="noopener">CERT-FR</a> de la fenêtre (pages du site, pas seulement le flux RSS). Avis et alertes sont croisés avec l'inventaire GLPI par un agent IA outillé ; les autres rubriques sont affichées pour information.</p></div>
      <div class="card help-card"><b>Statuts</b><p><span class="pill concerne">Concerné</span> mise à jour requise<br><span class="pill a_verifier" style="margin-top:6px">À vérifier</span> donnée insuffisante<br><span class="pill non_concerne" style="margin-top:6px">Non concerné</span> rien à faire</p></div>
      <div class="card help-card"><b>Azure DevOps</b><p>Le bouton « Créer » d'un bulletin ouvre un aperçu : personnes à affecter (membres des équipes du projet), anti-doublon, puis création. Plusieurs personnes = un {{ ado_type }} pour la première, et une tâche par personne.</p></div>
      <div class="card help-card"><b>Fréquence et coût</b><p>Un cycle à {{ schedule }}. Chaque verdict IA est gardé en cache tant que le bulletin ne change pas : seuls les nouveaux bulletins coûtent des tokens.</p></div>
    </div>
  </section>

  <footer>
    <strong>Méthodologie.</strong> GLPI est lu sans jamais être modifié. Chaque avis et alerte est analysé par un agent IA outillé (recherches GLPI, texte intégral de l'avis, vérification externe si besoin) ; aucun statut n'est deviné. Si une source est injoignable, les bulletins passent « à vérifier », jamais « non concerné ».
    <details class="changelog">
      <summary>Historique des cycles ({{ changelog|length }})</summary>
      <div class="changelog-body">
        {% for c in changelog %}<strong>{{ c.ts[:16] | replace("T", " ") }} :</strong> {{ c.entry }}{% if not loop.last %}<br><br>{% endif %}{% else %}Aucun cycle enregistré.{% endfor %}
      </div>
    </details>
    Dernière génération : {{ generated_at }}.
  </footer>
</main>

{% if actions_enabled %}
<dialog id="tokenDlg" aria-labelledby="tokenTitle">
  <form method="dialog" id="tokenForm">
    <div class="dlg-head"><div><h3 id="tokenTitle">Déverrouiller les actions</h3><p>Saisissez le jeton d'action (ACTION_TOKEN du fichier .env). Il reste en mémoire de cet onglet uniquement, jamais dans la page.</p></div></div>
    <div class="dlg-body">
      <div class="field"><label for="tokenInput">Jeton d'action</label><input type="password" id="tokenInput" autocomplete="current-password" required></div>
    </div>
    <div class="dlg-foot"><span class="msg" id="tokenMsg"></span><button type="button" class="ghost-btn" id="tokenCancel">Annuler</button><button type="submit" class="primary-btn" id="tokenOk">Valider</button></div>
  </form>
</dialog>
{% endif %}

{% if ado_enabled %}
<dialog id="adoDlg" aria-labelledby="adoTitle">
  <div class="dlg-head">
    <div><h3 id="adoTitle">Créer un {{ ado_type }} dans Azure DevOps</h3><p id="adoSubtitle"></p></div>
    <button type="button" class="ghost-btn x" id="adoClose" aria-label="Fermer">✕</button>
  </div>
  <div class="dlg-body" id="adoStepPick">
    <div class="field">
      <label for="peopleSearch">Affecter à (une ou plusieurs personnes)</label>
      <div class="chips" id="chosenChips"></div>
      <p class="hint">La première personne est responsable du {{ ado_type }}{% if ado_parent_id %} (rattaché à #{{ ado_parent_id }}){% endif %}. Avec plusieurs personnes, une tâche est créée pour chacune. Cliquez sur un nom pour le passer responsable.</p>
    </div>
    <input type="search" id="peopleSearch" placeholder="Rechercher une personne…" aria-label="Rechercher une personne">
    <div class="people-list" id="peopleList"><div class="hint" style="padding:8px">Chargement des membres des équipes ADO…</div></div>
  </div>
  <div class="dlg-body" id="adoStepPreview" hidden></div>
  <div class="dlg-foot">
    <span class="msg" id="adoMsg"></span>
    <button type="button" class="ghost-btn" id="adoBack" hidden>← Modifier</button>
    <button type="button" class="primary-btn" id="adoPreviewBtn" disabled>Prévisualiser</button>
    <button type="button" class="primary-btn" id="adoCreateBtn" hidden>Créer dans ADO</button>
  </div>
</dialog>
{% endif %}

<script type="application/json" id="chartData">{{ chart_json | safe }}</script>
<script>
(function(){
  'use strict';
  var DATA = JSON.parse(document.getElementById('chartData').textContent);
  function $(id){ return document.getElementById(id); }
  function cssVar(n){ return getComputedStyle(document.documentElement).getPropertyValue(n).trim(); }
  var C = { crit:cssVar('--crit'), warn:cssVar('--warn'), ok:cssVar('--ok'), accent:cssVar('--accent'),
            border:cssVar('--border'), faint:cssVar('--text-faint'), dim:cssVar('--text-dim'), surface:cssVar('--surface'), s2:cssVar('--surface-2') };
  var ST = [['concerne', C.crit, 'Concerné'], ['a_verifier', C.warn, 'À vérifier'], ['non_concerne', C.ok, 'Non concerné']];
  var NS = 'http://www.w3.org/2000/svg';
  function el(svg, tag, attrs, text){
    var e = document.createElementNS(NS, tag);
    for(var k in attrs){ e.setAttribute(k, attrs[k]); }
    if(text !== undefined){ e.textContent = text; }
    svg.appendChild(e); return e;
  }
  function tip(node, text){ var t = document.createElementNS(NS, 'title'); t.textContent = text; node.appendChild(t); }
  function pad(n){ return String(n).padStart(2,'0'); }
  function fmtTs(iso){ var d = new Date(iso); return pad(d.getDate())+'/'+pad(d.getMonth()+1); }
  function fmtTsLong(iso){ var d = new Date(iso); return pad(d.getDate())+'/'+pad(d.getMonth()+1)+' '+pad(d.getHours())+'h'+pad(d.getMinutes()); }
  function nfmt(n){ return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ' '); }
  var MONO = 'IBM Plex Mono, monospace';

  /* ---------- donut ---------- */
  (function(){
    var svg = $('donutSvg'); if(!svg) return;
    var s = DATA.status, total = s.total || 0, r = 46, cx = 60, cy = 60, circ = 2*Math.PI*r, off = 0;
    el(svg, 'circle', {cx:cx, cy:cy, r:r, fill:'none', stroke:C.s2, 'stroke-width':14});
    if(!total) return;
    ST.forEach(function(st){
      var v = s[st[0]] || 0; if(!v) return;
      var len = circ * v / total;
      var c = el(svg, 'circle', {cx:cx, cy:cy, r:r, fill:'none', stroke:st[1], 'stroke-width':14,
        'stroke-dasharray':len.toFixed(2)+' '+(circ-len).toFixed(2), 'stroke-dashoffset':(-off).toFixed(2),
        transform:'rotate(-90 '+cx+' '+cy+')'});
      tip(c, st[2]+' : '+v+' ('+Math.round(100*v/total)+' %)');
      off += len;
    });
  })();

  /* ---------- axes communs ---------- */
  function yAxis(svg, box, max, ticks, suffix){
    for(var i=0;i<=ticks;i++){
      var v = max*i/ticks, y = box.t + box.h*(1 - i/ticks);
      el(svg, 'line', {x1:box.l, x2:box.l+box.w, y1:y, y2:y, stroke:C.border, 'stroke-width':1});
      el(svg, 'text', {x:box.l-6, y:y+3, 'font-size':10, fill:C.faint, 'text-anchor':'end', 'font-family':MONO}, Math.round(v)+(suffix||''));
    }
  }
  function niceMax(v){ if(v<=5) return 5; var p = Math.pow(10, Math.floor(Math.log10(v))); var m = Math.ceil(v/p); return (m<=2?2:m<=5?5:10)*p; }

  /* ---------- score + taux : courbes ---------- */
  (function(){
    var svg = $('trendSvg'); if(!svg) return;
    var sc = DATA.score_history.slice(-60), rh = {};
    DATA.rate_history.forEach(function(r){ rh[r.ts] = r.rate; });
    var deltaEl = $('scoreDelta');
    if(deltaEl && sc.length >= 2){
      var d = sc[sc.length-1].score - sc[sc.length-2].score;
      if(d !== 0){ deltaEl.classList.add(d>0?'up':'down'); deltaEl.textContent = (d>0?'▲ +':'▼ ')+d+' vs cycle précédent'; }
    }
    var box = {l:34, t:10, w:594, h:150};
    yAxis(svg, box, 100, 4);
    if(sc.length < 2){
      var e = $('trendEmpty'); e.hidden = false;
      e.textContent = 'Historique en construction : '+sc.length+' cycle enregistré. Un point est ajouté à chaque cycle complet.';
      return;
    }
    function x(i){ return box.l + box.w*i/(sc.length-1); }
    function y(v){ return box.t + box.h*(1 - v/100); }
    var dS = sc.map(function(p,i){ return (i?'L':'M')+x(i).toFixed(1)+','+y(p.score).toFixed(1); }).join(' ');
    el(svg, 'path', {d:dS+' L'+x(sc.length-1)+','+(box.t+box.h)+' L'+x(0)+','+(box.t+box.h)+' Z', fill:C.accent, opacity:.10});
    el(svg, 'path', {d:dS, fill:'none', stroke:C.accent, 'stroke-width':2.2, 'stroke-linejoin':'round'});
    var rPts = []; sc.forEach(function(p,i){ if(rh[p.ts] !== undefined) rPts.push([x(i), y(rh[p.ts]), rh[p.ts], p.ts]); });
    if(rPts.length){
      el(svg, 'path', {d:rPts.map(function(p,i){ return (i?'L':'M')+p[0].toFixed(1)+','+p[1].toFixed(1); }).join(' '), fill:'none', stroke:C.crit, 'stroke-width':2, 'stroke-dasharray':'5 4'});
      rPts.forEach(function(p){ tip(el(svg, 'circle', {cx:p[0], cy:p[1], r:3, fill:C.crit}), fmtTsLong(p[3])+' : '+p[2]+' % concernés'); });
    }
    sc.forEach(function(p,i){ tip(el(svg, 'circle', {cx:x(i), cy:y(p.score), r:3.2, fill:C.accent, stroke:C.surface, 'stroke-width':1.5}), fmtTsLong(p.ts)+' : score '+p.score); });
    el(svg, 'text', {x:box.l, y:184, 'font-size':10, fill:C.faint, 'font-family':MONO}, fmtTsLong(sc[0].ts));
    el(svg, 'text', {x:box.l+box.w, y:184, 'font-size':10, fill:C.faint, 'text-anchor':'end', 'font-family':MONO}, fmtTsLong(sc[sc.length-1].ts));
  })();

  /* ---------- barres empilées (verticales) ---------- */
  function stacked(svg, rows, opts){
    var W = +svg.getAttribute('viewBox').split(' ')[2], H = +svg.getAttribute('viewBox').split(' ')[3];
    var box = {l:38, t:12, w:W-38-10, h:H-12-34};
    var max = opts.percent ? 100 : niceMax(Math.max.apply(null, rows.map(function(r){ return r.concerne+r.a_verifier+r.non_concerne; }).concat([1])));
    yAxis(svg, box, max, 4, opts.percent ? '%' : '');
    var n = rows.length, slot = box.w/n, bw = Math.min(34, slot*0.68);
    var every = Math.ceil(n / (opts.maxLabels || 13));
    rows.forEach(function(r, i){
      var tot = r.concerne + r.a_verifier + r.non_concerne, yb = box.t + box.h, x = box.l + slot*i + (slot-bw)/2;
      ST.slice().reverse().forEach(function(st){
        var v = r[st[0]] || 0; if(!v) return;
        var h = box.h * (opts.percent ? (tot ? v/tot*100 : 0) : v) / max;
        yb -= h;
        tip(el(svg, 'rect', {x:x.toFixed(1), y:yb.toFixed(1), width:bw.toFixed(1), height:Math.max(h,0).toFixed(1), fill:st[1], rx:2}),
            r.title+' — '+st[2]+' : '+v+(tot ? ' ('+Math.round(100*v/tot)+' %)' : ''));
      });
      if((n-1-i) % every === 0){
        el(svg, 'text', {x:(x+bw/2).toFixed(1), y:H-14, 'font-size':10, fill:C.faint, 'text-anchor':'middle', 'font-family':MONO}, r.label);
      }
    });
    return {box:box, slot:slot, max:max};
  }

  /* ---------- taux concernés par cycle ---------- */
  (function(){
    var svg = $('rateSvg'); if(!svg) return;
    var rows = DATA.rate_history.slice(-40).map(function(r){
      return {concerne:r.concerne, a_verifier:r.a_verifier, non_concerne:r.non_concerne, label:fmtTs(r.ts), title:fmtTsLong(r.ts)+' · '+r.total+' bulletins', rate:r.rate};
    });
    if(!rows.length){
      svg.hidden = true; var e = $('rateEmpty'); e.hidden = false;
      e.textContent = 'Ce graphique se remplit à partir du premier cycle complet de la V2 (la V1 n\'enregistrait pas le détail par statut).';
      return;
    }
    var g = stacked(svg, rows, {percent:true, maxLabels:20});
    var pts = rows.map(function(r,i){ return [g.box.l + g.slot*i + g.slot/2, g.box.t + g.box.h*(1 - r.rate/100), r]; });
    el(svg, 'path', {d:pts.map(function(p,i){ return (i?'L':'M')+p[0].toFixed(1)+','+p[1].toFixed(1); }).join(' '), fill:'none', stroke:'#fff', 'stroke-width':1.6, opacity:.9});
    pts.forEach(function(p){
      tip(el(svg, 'circle', {cx:p[0], cy:p[1], r:3.4, fill:'#fff', stroke:C.crit, 'stroke-width':2}), p[2].title+' : '+p[2].rate+' % concernés');
    });
    var last = pts[pts.length-1];
    el(svg, 'text', {x:Math.min(last[0]+6, 880), y:last[1]-7, 'font-size':11, 'font-weight':700, fill:'#fff', 'text-anchor':'end', 'font-family':MONO}, last[2].rate+' %');
  })();

  /* ---------- publications par semaine ---------- */
  (function(){
    var svg = $('weeklySvg'); if(!svg) return;
    stacked(svg, DATA.weekly.map(function(w){ return {concerne:w.concerne, a_verifier:w.a_verifier, non_concerne:w.non_concerne, label:w.label, title:'Semaine du '+w.start.split('-').reverse().join('/')}; }), {percent:false});
  })();

  /* ---------- barres horizontales ---------- */
  function hbars(container, rows, max){
    container.innerHTML = '';
    if(!rows.length){ container.innerHTML = '<div class="chart-empty">Aucun bulletin concerné ou à vérifier.</div>'; return; }
    rows.forEach(function(r){
      var line = document.createElement('div'); line.className = 'hbar';
      var lbl = document.createElement('span'); lbl.className = 'lbl'; lbl.textContent = r.label; lbl.title = r.label;
      var track = document.createElement('span'); track.className = 'track';
      ST.forEach(function(st){
        var v = r[st[0]] || 0; if(!v) return;
        var seg = document.createElement('span'); seg.style.width = (100*v/max)+'%'; seg.style.background = st[1];
        seg.title = r.label+' — '+st[2]+' : '+v; track.appendChild(seg);
      });
      var val = document.createElement('span'); val.className = 'val mono';
      val.textContent = r.concerne ? r.concerne+' / '+r.total : String(r.total);
      line.appendChild(lbl); line.appendChild(track); line.appendChild(val); container.appendChild(line);
    });
  }
  (function(){
    var c = $('productsBars'); if(!c) return;
    var rows = DATA.top_products;
    hbars(c, rows, Math.max.apply(null, rows.map(function(r){ return r.total; }).concat([1])));
  })();
  (function(){
    var c = $('kindBars'); if(!c) return;
    var labels = {avis:'Avis', alerte:'Alertes'};
    var rows = Object.keys(DATA.by_kind).map(function(k){
      var v = DATA.by_kind[k]; return {label:labels[k]||k, concerne:v.concerne, a_verifier:v.a_verifier, non_concerne:v.non_concerne, total:v.concerne+v.a_verifier+v.non_concerne};
    });
    hbars(c, rows, Math.max.apply(null, rows.map(function(r){ return r.total; }).concat([1])));
  })();

  /* ---------- budget IA ---------- */
  (function(){
    var svg = $('budgetSvg'); if(!svg) return;
    var rows = DATA.cycles.slice(-30);
    if(!rows.length){ svg.hidden = true; var e = $('budgetEmpty'); e.hidden = false; e.textContent = 'Aucun cycle V2 enregistré pour l\'instant.'; return; }
    var box = {l:52, t:12, w:838, h:156};
    var max = niceMax(Math.max.apply(null, rows.map(function(r){ return r.ai_tokens||0; }).concat([1])));
    for(var i=0;i<=4;i++){
      var y = box.t + box.h*(1-i/4);
      el(svg, 'line', {x1:box.l, x2:box.l+box.w, y1:y, y2:y, stroke:C.border});
      el(svg, 'text', {x:box.l-6, y:y+3, 'font-size':10, fill:C.faint, 'text-anchor':'end', 'font-family':MONO}, max*i/4 >= 1000 ? Math.round(max*i/4/1000)+'k' : Math.round(max*i/4));
    }
    var slot = box.w/rows.length, bw = Math.min(26, slot*.66), every = Math.ceil(rows.length/14);
    rows.forEach(function(r,i){
      var h = box.h*(r.ai_tokens||0)/max, x = box.l + slot*i + (slot-bw)/2;
      var rect = el(svg, 'rect', {x:x, y:box.t+box.h-h, width:bw, height:h, rx:2, fill:r.ai_pending ? C.warn : C.accent, opacity:.85});
      tip(rect, fmtTsLong(r.ts)+' ('+(r.trigger||'')+') : '+nfmt(r.ai_tokens||0)+' tokens, '+(r.ai_calls||0)+' appels, '+(r.ai_cached||0)+' depuis le cache'+(r.ai_pending ? ', '+r.ai_pending+' en attente (budget atteint)' : '')+', '+Math.round(r.duration_s||0)+' s');
      if((rows.length-1-i) % every === 0) el(svg, 'text', {x:x+bw/2, y:192, 'font-size':10, fill:C.faint, 'text-anchor':'middle', 'font-family':MONO}, fmtTs(r.ts));
    });
  })();

  /* ---------- filtres et pagination des listes ---------- */
  var search = $('searchInput'), statusFilter = $('statusFilter'), currentStatus = '';
  var items = Array.prototype.slice.call(document.querySelectorAll('details.bulletin'));
  function normalize(s){ return (s || '').toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, ''); }
  var texts = items.map(function(d){ return normalize(d.textContent); });
  var expanded = {};
  function applyFilter(){
    var q = normalize(search.value).trim(), filtering = !!(q || currentStatus), visible = 0;
    document.querySelectorAll('[data-list]').forEach(function(list, li){
      var limit = +(list.getAttribute('data-page') || 0), shown = 0, hiddenByPage = 0;
      list.querySelectorAll('details.bulletin').forEach(function(d){
        var idx = items.indexOf(d);
        var match = (!q || texts[idx].indexOf(q) !== -1) && (!currentStatus || d.getAttribute('data-status') === currentStatus);
        var show = match;
        if(match && limit && !filtering && !expanded[li] && shown >= limit){ show = false; hiddenByPage++; }
        d.hidden = !show; if(show){ shown++; visible++; }
      });
      var more = list.nextElementSibling && list.nextElementSibling.classList.contains('more-row') ? list.nextElementSibling : null;
      if(limit && !more){
        more = document.createElement('div'); more.className = 'more-row';
        var b = document.createElement('button'); b.type = 'button'; b.className = 'ghost-btn';
        b.addEventListener('click', function(){ expanded[li] = true; applyFilter(); });
        more.appendChild(b); list.parentNode.insertBefore(more, list.nextSibling);
      }
      if(more){ more.hidden = !hiddenByPage; more.firstChild.textContent = 'Afficher les '+hiddenByPage+' autres'; }
    });
    $('searchEmpty').hidden = visible !== 0 || !items.length;
  }
  search.addEventListener('input', applyFilter);
  statusFilter.querySelectorAll('.seg-btn').forEach(function(btn){
    btn.addEventListener('click', function(){
      statusFilter.querySelectorAll('.seg-btn').forEach(function(b){ b.classList.remove('active'); });
      btn.classList.add('active'); currentStatus = btn.getAttribute('data-status') || ''; applyFilter();
    });
  });
  $('resetFiltersBtn').addEventListener('click', function(){
    search.value = ''; currentStatus = '';
    statusFilter.querySelectorAll('.seg-btn').forEach(function(b){ b.classList.toggle('active', !b.getAttribute('data-status')); });
    applyFilter(); search.focus();
  });
  var exp = $('expandAllBtn'), col = $('collapseAllBtn');
  if(exp) exp.addEventListener('click', function(){ document.querySelectorAll('#avis details.bulletin:not([hidden])').forEach(function(d){ d.open = true; }); });
  if(col) col.addEventListener('click', function(){ document.querySelectorAll('#avis details.bulletin').forEach(function(d){ d.open = false; }); });
  applyFilter();

  var infoFilter = $('infoFilter');
  if(infoFilter){
    infoFilter.querySelectorAll('.seg-btn').forEach(function(btn){
      btn.addEventListener('click', function(){
        infoFilter.querySelectorAll('.seg-btn').forEach(function(b){ b.classList.remove('active'); });
        btn.classList.add('active');
        var k = btn.getAttribute('data-kind');
        document.querySelectorAll('#infoBody tr').forEach(function(tr){ tr.hidden = !!k && tr.getAttribute('data-kind') !== k; });
      });
    });
  }

  /* ---------- navigation ---------- */
  var links = document.querySelectorAll('#nav a');
  var sections = Array.prototype.map.call(links, function(l){ return document.querySelector(l.getAttribute('href')); });
  window.addEventListener('scroll', function(){
    var pos = window.scrollY + 120, current = sections[0];
    sections.forEach(function(s){ if(s && s.offsetTop <= pos) current = s; });
    links.forEach(function(l){ l.classList.toggle('active', !!current && l.getAttribute('href') === '#'+current.id); });
  }, {passive:true});

  /* ---------- jeton d'action (jamais écrit dans la page) ---------- */
  var token = null;
  try { token = sessionStorage.getItem('sentinelActionToken'); } catch(e) {}
  var tokenDlg = $('tokenDlg'), pendingAction = null;
  function setToken(t){ token = t; try { t ? sessionStorage.setItem('sentinelActionToken', t) : sessionStorage.removeItem('sentinelActionToken'); } catch(e) {} refreshLock(); }
  function refreshLock(){ var b = $('unlockBtn'); if(b){ b.textContent = token ? '🔓 Actions' : '🔒 Actions'; b.title = token ? 'Actions déverrouillées (cliquer pour verrouiller)' : 'Saisir le jeton d\'action'; } }
  function withToken(action){ if(token){ action(); } else if(tokenDlg){ pendingAction = action; $('tokenMsg').textContent = ''; $('tokenInput').value = ''; tokenDlg.showModal(); } }
  function api(method, url, body){
    return fetch(url, {method:method, headers:{'Content-Type':'application/json', 'X-Action-Token':token || ''}, body: body ? JSON.stringify(body) : undefined})
      .then(function(r){ return r.json().catch(function(){ return {}; }).then(function(j){ if(r.status === 403 && /Jeton/.test(j.error||'')){ setToken(null); } return {status:r.status, body:j}; }); });
  }
  refreshLock();
  if(tokenDlg){
    $('unlockBtn').addEventListener('click', function(){ if(token){ setToken(null); } else { withToken(function(){}); } });
    $('tokenCancel').addEventListener('click', function(){ pendingAction = null; tokenDlg.close(); });
    $('tokenForm').addEventListener('submit', function(ev){
      ev.preventDefault();
      var t = $('tokenInput').value.trim(); if(!t) return;
      $('tokenOk').disabled = true; $('tokenMsg').className = 'msg'; $('tokenMsg').textContent = 'Vérification…';
      token = t;
      api('POST', '/api/auth/check').then(function(res){
        $('tokenOk').disabled = false;
        if(res.status === 200){ setToken(t); tokenDlg.close(); var a = pendingAction; pendingAction = null; if(a) a(); }
        else { token = null; $('tokenMsg').className = 'msg err'; $('tokenMsg').textContent = res.body.error || 'Refusé.'; }
      }).catch(function(){ token = null; $('tokenOk').disabled = false; $('tokenMsg').className = 'msg err'; $('tokenMsg').textContent = 'Serveur injoignable.'; });
    });
  }

  /* ---------- lancer un cycle ---------- */
  var runBtn = $('runNowBtn'), runStatus = $('runNowStatus');
  function pollStatus(){
    fetch('/api/status').then(function(r){ return r.json(); }).then(function(s){
      if(s.running){ runStatus.textContent = 'Cycle en cours…'; setTimeout(pollStatus, 4000); }
      else if(s.last_error){ runStatus.textContent = 'Échec : '+s.last_error; runBtn.disabled = false; }
      else { runStatus.textContent = 'Terminé, rechargement…'; setTimeout(function(){ location.reload(); }, 800); }
    }).catch(function(){ setTimeout(pollStatus, 6000); });
  }
  if(runBtn){
    runBtn.addEventListener('click', function(){
      withToken(function(){
        runBtn.disabled = true; runStatus.textContent = 'Démarrage…';
        api('POST', '/api/trigger').then(function(res){
          if(res.status === 202 || res.status === 409){ runStatus.textContent = res.status === 409 ? 'Un cycle est déjà en cours…' : 'Cycle en cours…'; pollStatus(); }
          else { runStatus.textContent = 'Erreur : '+(res.body.error || res.status); runBtn.disabled = false; }
        }).catch(function(){ runStatus.textContent = 'Serveur injoignable.'; runBtn.disabled = false; });
      });
    });
    fetch('/api/status').then(function(r){ return r.json(); }).then(function(s){ if(s.running){ runBtn.disabled = true; pollStatus(); } }).catch(function(){});
  }

  /* ---------- création ADO ---------- */
  var adoDlg = $('adoDlg'); if(!adoDlg) return;
  var people = null, chosen = [], currentRef = null;
  function esc(s){ var d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; }
  function setMsg(text, kind){ var m = $('adoMsg'); m.textContent = text || ''; m.className = 'msg' + (kind ? ' '+kind : ''); }
  function step(which){
    $('adoStepPick').hidden = which !== 'pick'; $('adoStepPreview').hidden = which === 'pick';
    $('adoPreviewBtn').hidden = which !== 'pick'; $('adoBack').hidden = which !== 'preview';
    $('adoCreateBtn').hidden = which !== 'preview';
  }
  function renderChips(){
    var box = $('chosenChips'); box.innerHTML = '';
    if(!chosen.length){ box.innerHTML = '<span class="hint">Personne sélectionnée.</span>'; }
    chosen.forEach(function(p, i){
      var c = document.createElement('span'); c.className = 'chip' + (i === 0 ? ' lead' : '');
      c.title = i === 0 ? 'Responsable' : 'Cliquer pour passer responsable';
      c.innerHTML = (i === 0 ? '★ ' : '') + esc(p.display_name) + ' <button type="button" aria-label="Retirer">✕</button>';
      c.addEventListener('click', function(ev){
        if(ev.target.tagName === 'BUTTON'){ chosen.splice(i, 1); }
        else if(i > 0){ chosen.splice(i, 1); chosen.unshift(p); }
        renderChips(); renderPeople();
      });
      box.appendChild(c);
    });
    $('adoPreviewBtn').disabled = !chosen.length;
  }
  function renderPeople(){
    var list = $('peopleList'); if(!people) return;
    var q = normalize($('peopleSearch').value).trim(); list.innerHTML = '';
    var shown = people.filter(function(p){ return !q || normalize(p.display_name+' '+p.unique_name+' '+(p.teams||[]).join(' ')).indexOf(q) !== -1; });
    if(!shown.length){ list.innerHTML = '<div class="hint" style="padding:8px">Aucune personne trouvée.</div>'; return; }
    shown.forEach(function(p){
      var row = document.createElement('label'); row.className = 'person';
      var cb = document.createElement('input'); cb.type = 'checkbox';
      cb.checked = chosen.some(function(c){ return c.unique_name === p.unique_name; });
      cb.addEventListener('change', function(){
        if(cb.checked){ chosen.push(p); } else { chosen = chosen.filter(function(c){ return c.unique_name !== p.unique_name; }); }
        renderChips();
      });
      var who = document.createElement('span'); who.className = 'who';
      who.innerHTML = esc(p.display_name) + '<small>' + esc(p.unique_name) + ((p.teams||[]).length ? ' · ' + esc(p.teams.join(', ')) : '') + '</small>';
      row.appendChild(cb); row.appendChild(who); list.appendChild(row);
    });
  }
  function loadPeople(){
    if(people){ renderPeople(); return; }
    api('GET', '/api/ado/people').then(function(res){
      if(res.status !== 200){ $('peopleList').innerHTML = '<div class="crit-box">'+esc(res.body.error || ('Erreur '+res.status))+'</div>'; return; }
      people = res.body.people || []; renderPeople();
    }).catch(function(){ $('peopleList').innerHTML = '<div class="crit-box">Serveur injoignable.</div>'; });
  }
  function openAdo(ref, title){
    currentRef = ref; chosen = []; $('adoSubtitle').textContent = ref + ' — ' + title;
    $('peopleSearch').value = ''; setMsg(''); step('pick'); renderChips(); adoDlg.showModal(); loadPeople();
  }
  document.querySelectorAll('[data-ado-ref]').forEach(function(btn){
    btn.addEventListener('click', function(){ var r = btn.getAttribute('data-ado-ref'), t = btn.getAttribute('data-ado-title'); withToken(function(){ openAdo(r, t); }); });
  });
  $('peopleSearch').addEventListener('input', renderPeople);
  $('adoClose').addEventListener('click', function(){ adoDlg.close(); });
  $('adoBack').addEventListener('click', function(){ setMsg(''); step('pick'); });
  function payload(extra){ var p = {ref:currentRef, assignees:chosen.map(function(c){ return c.unique_name; })}; for(var k in extra||{}) p[k] = extra[k]; return p; }
  var allowDuplicate = false;
  $('adoPreviewBtn').addEventListener('click', function(){
    setMsg('Prévisualisation…'); $('adoPreviewBtn').disabled = true;
    api('POST', '/api/ado/preview', payload()).then(function(res){
      $('adoPreviewBtn').disabled = false;
      if(res.status !== 200){ setMsg(res.body.error || ('Erreur '+res.status), 'err'); return; }
      var b = res.body, box = $('adoStepPreview'), html = '';
      allowDuplicate = false;
      if(b.existing && b.existing.length){
        html += '<div class="warn-box"><b>Déjà présent dans ADO :</b><br>' + b.existing.map(function(w){
          return '<a href="'+esc(w.url)+'" target="_blank" rel="noopener">'+esc(w.type)+' #'+esc(w.id)+'</a> · '+esc(w.state)+' · '+esc(w.assigned_to||'non affecté')+' — '+esc(w.title);
        }).join('<br>') + '<label class="check-line" style="margin-top:8px;color:inherit"><input type="checkbox" id="dupOk"> Créer quand même un nouveau work item</label></div>';
      }
      if(b.validation_error){ html += '<div class="crit-box"><b>Azure DevOps refusera la création :</b> '+esc(b.validation_error)+'</div>'; }
      html += '<div class="plan">' + b.plan.map(function(p){
        return '<div class="plan-item '+(p.role === 'task' ? 'task' : '')+'"><span class="tag" style="margin:0">'+esc(p.type)+'</span><b>'+esc(p.title)+'</b><span class="t">Affecté à '+esc(p.assigned_to)+(p.parent_id ? ' · parent : '+(typeof p.parent_id === 'number' ? '#'+p.parent_id : esc(p.parent_id)) : '')+'</span></div>';
      }).join('') + '</div><p class="hint">Description : statut Sentinel, versions installées et cible, analyse et liste des équipements concernés, lien vers le bulletin CERT-FR.</p>';
      box.innerHTML = html; step('preview');
      var dup = $('dupOk');
      var blocked = !!b.validation_error || (b.existing && b.existing.length);
      $('adoCreateBtn').disabled = blocked;
      if(dup){ dup.addEventListener('change', function(){ allowDuplicate = dup.checked; $('adoCreateBtn').disabled = !!b.validation_error || !dup.checked; }); }
      setMsg(blocked ? '' : 'Prêt. Rien n\'est encore créé.', '');
    }).catch(function(){ $('adoPreviewBtn').disabled = false; setMsg('Serveur injoignable.', 'err'); });
  });
  $('adoCreateBtn').addEventListener('click', function(){
    $('adoCreateBtn').disabled = true; setMsg('Création dans Azure DevOps…');
    api('POST', '/api/ado/create', payload({allow_duplicate:allowDuplicate})).then(function(res){
      if(res.status === 201 || res.status === 207){
        var b = res.body;
        $('adoStepPreview').innerHTML = '<div class="ok-box"><b>Créé :</b><br>' + b.created.map(function(w){
          return '<a href="'+esc(w.url)+'" target="_blank" rel="noopener">'+esc(w.type)+' #'+esc(w.id)+' ↗</a> · '+esc(w.assigned_to);
        }).join('<br>') + '</div>' + (b.errors.length ? '<div class="crit-box">'+b.errors.map(esc).join('<br>')+'</div>' : '');
        $('adoBack').hidden = true; $('adoCreateBtn').hidden = true;
        setMsg('Le badge ADO apparaîtra sur le bulletin au prochain cycle.', 'ok');
      } else {
        $('adoCreateBtn').disabled = false; setMsg(res.body.error || ('Erreur '+res.status), 'err');
      }
    }).catch(function(){ $('adoCreateBtn').disabled = false; setMsg('Serveur injoignable.', 'err'); });
  });
})();
</script>
</body>
</html>
SENTINEL_V2_EOF
echo "  écrit : app/templates/dashboard.html.j2"

cat > .env.example << 'SENTINEL_V2_EOF'
# =====================================================================
# Sentinel CVE V2 — copier en .env puis `chmod 600 .env`
# Ne jamais committer ce fichier ni le coller dans un chat.
# =====================================================================

# ---------- GLPI (lecture seule) ----------
GLPI_BASE_URL=https://glpi.example.internal/apirest.php
GLPI_APP_TOKEN=change-me
GLPI_USER_TOKEN=change-me
GLPI_MAX_OR_CRITERIA=12
GLPI_FIELD_LOCATION=3
GLPI_FIELD_KERNEL_VERSION=48
GLPI_FIELD_SOFTWARE_INSTALL_COUNT=72

# ---------- CERT-FR ----------
CERTFR_LOOKBACK_DAYS=90
# Rubriques croisées avec GLPI (comptent dans le score)
CERTFR_ANALYZED_SECTIONS=avis,alerte
# Rubriques affichées pour information
CERTFR_INFO_SECTIONS=actualite,cti,dur,ioc
# 10 publications par page ; 80 pages = 800 avis max par rubrique
CERTFR_MAX_PAGES=80
CERTFR_PAGE_DELAY_S=0.5

# ---------- Agent IA (API Anthropic) ----------
AI_ENABLED=true
ANTHROPIC_API_KEY=sk-ant-change-me
ANTHROPIC_MODEL=claude-sonnet-4-5-20250929
AI_MAX_TOOL_ITERATIONS=8
AI_MAX_TOKENS_PER_CALL=2048
# Budget par cycle : au-delà, les bulletins restants passent « en attente »
# et sont analysés au cycle suivant (le cache garde ce qui est déjà fait).
AI_MAX_CALLS_PER_CYCLE=200
AI_MAX_TOKENS_PER_CYCLE=1000000
AI_CACHE_TTL_DAYS=7
# Prompt personnalisé (optionnel) : s'il existe, remplace le prompt par défaut
AI_SYSTEM_PROMPT_FILE=/app/output/system_prompt.txt

# ---------- Azure DevOps (création de requirements uniquement) ----------
ADO_WRITE_ENABLED=true
ADO_ORG=Beneteau-Group
ADO_PROJECT=IT PROJECTS PORTFOLIO
# PAT : Work Items (Read & Write) + Project and Team (Read)
ADO_PAT=change-me
# Requirement (CMMI) | User Story (Agile) | Product Backlog Item (Scrum) | Issue (Basic)
ADO_WORK_ITEM_TYPE=Requirement
ADO_TASK_TYPE=Task
# Feature parente (0 = aucune)
ADO_PARENT_ID=12194
ADO_AREA_PATH=
ADO_ITERATION_PATH=
# Équipes proposées dans le sélecteur de personnes (vide = toutes), séparées par des virgules
ADO_TEAMS=
ADO_TAGS=sentinel-cve
ADO_SET_PRIORITY=true

# ---------- Planification et actions ----------
# Un cycle par jour à 03h44
SCHEDULE_CRON_MINUTE=44
SCHEDULE_CRON_HOUR=3
OUTPUT_DIR=/app/output
TIMEZONE=Europe/Paris
# Jeton demandé dans le navigateur pour « Lancer maintenant » et « Créer dans ADO ».
# Générer : openssl rand -hex 32
ACTION_TOKEN=change-me
TRIGGER_PORT=5001
SENTINEL_V2_EOF
echo "  écrit : .env.example"

cat > README.md << 'SENTINEL_V2_EOF'
# Sentinel CVE — V2

Dashboard self-hosted : publications CERT-FR croisées avec l'inventaire GLPI
par un agent IA (API Anthropic), score de conformité, graphiques, et création
de requirements Azure DevOps à la demande.

## Ce qui change en V2

- **CERT-FR exhaustif** : lecture des pages paginées du site (`/avis/page/N/`…)
  jusqu'à la fin de la fenêtre `CERTFR_LOOKBACK_DAYS`, et non plus seulement
  les ~dernières entrées du flux RSS. RSS en complément et en secours.
  Avis + alertes analysés ; actualités, CTI, durcissement, IOC affichés pour info.
- **ADO n'est plus une source** : plus de lecture de tickets ni d'association
  IA ticket↔bulletin. ADO sert à **créer** un requirement depuis un bulletin
  (aperçu `validateOnly`, anti-doublon par tag, une ou plusieurs personnes
  issues des équipes du projet ; plusieurs personnes = une Task chacune).
- **Graphiques** : taux de concernés par cycle, répartition, publications
  par semaine, éditeurs les plus exposés, avis/alertes, consommation IA.
- **Sécurité** : le jeton d'action n'est plus écrit dans la page ; il est
  saisi une fois dans le navigateur (`ACTION_TOKEN`, ou `TRIGGER_TOKEN` V1).
- **Réglages hors du code** : `AI_MAX_TOKENS_PER_CALL`, prompt personnalisable
  via `output/system_prompt.txt`.
- **Règle de sécurité des verdicts** : si GLPI ou CERT-FR est injoignable,
  aucun bulletin n'est déclaré « non concerné » et le score n'est pas enregistré.

## Structure

```
app/
  config.py         variables d'environnement
  certfr_client.py  collecte CERT-FR (pages HTML + RSS)
  glpi_client.py    client GLPI REST (lecture seule)
  agent_pipeline.py agent IA outillé (tool use), budget, cache
  ado_client.py     création de work items Azure DevOps
  stats.py          données des graphiques
  db.py             SQLite : historique, cache IA, cycles, audit ADO
  webapi.py         API interne (cycle manuel, création ADO)
  main.py           orchestrateur + scheduler
  templates/        dashboard.html.j2, _bulletin.html.j2
tests/              pytest (aucun appel réseau)
```

## Tests

```bash
sudo docker compose run --rm --no-deps \
  -v "$PWD/tests:/app/tests" -v "$PWD/requirements-dev.txt:/app/requirements-dev.txt" \
  app sh -c "pip install -q -r requirements-dev.txt && python -m pytest -q tests"
```

## À venir

Catalyst Center (versions IOS-XE) et FortiManager / FortiAnalyzer (versions
FortiOS) dès que les accès API sont disponibles.
SENTINEL_V2_EOF
echo "  écrit : README.md"

cat > tests/test_certfr_listing.py << 'SENTINEL_V2_EOF'
"""Tests de la collecte exhaustive CERT-FR (pages HTML paginées) — V2.

Aucun appel réseau : les pages sont des extraits HTML construits à la main
dans deux mises en page différentes, pour vérifier que le parseur ne dépend
pas des classes CSS du site."""
from datetime import date, timedelta

import pytest
import requests

import certfr_client
import config

FR = ["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août",
      "septembre", "octobre", "novembre", "décembre"]


def fr(d: date) -> str:
    return f"{d.day:02d} {FR[d.month - 1]} {d.year}"


def page_articles(items, section="avis"):
    """Mise en page 1 : <article> avec h3 > a, ligne réf + date, résumé."""
    blocks = []
    for ref, title, d, extra in items:
        blocks.append(f"""
        <article class="item">
          <h3><a href="/{section}/{ref}/">{title}</a></h3>
          <div class="meta"><span>{ref}</span> <span>Publié le {fr(d)}</span> {extra}</div>
          <p>Résumé de {title}.</p>
        </article>""")
    return "<html><body><main>" + "".join(blocks) + "</main></body></html>"


def page_list(items, section="avis"):
    """Mise en page 2 : <ul><li> sans classes, lien absolu, date « 1er »."""
    lis = []
    for ref, title, d, extra in items:
        day = "1er" if d.day == 1 else str(d.day)
        lis.append(f"""<li><div><a href="https://www.cert.ssi.gouv.fr/{section}/{ref}/">{title}</a></div>
          <div>{ref} Publié le {day} {FR[d.month - 1]} {d.year}</div><div>Résumé {ref}</div>{extra}</li>""")
    return "<html><body><ul>" + "".join(lis) + "</ul></body></html>"


class TestParseFrDate:
    def test_date_simple(self):
        assert certfr_client.parse_fr_date("CERTFR-2026-AVI-1 Publié le 07 octobre 2026") == date(2026, 10, 7)

    def test_premier_du_mois(self):
        assert certfr_client.parse_fr_date("Publié le 1er mars 2026") == date(2026, 3, 1)

    def test_accents(self):
        assert certfr_client.parse_fr_date("Publié le 3 décembre 2025") == date(2025, 12, 3)
        assert certfr_client.parse_fr_date("Publié le 15 août 2026") == date(2026, 8, 15)

    def test_absente_ou_invalide(self):
        assert certfr_client.parse_fr_date("pas de date") is None
        assert certfr_client.parse_fr_date("Publié le 31 février 2026") is None


class TestParseListing:
    TODAY = date(2026, 10, 7)
    ITEMS = [
        ("CERTFR-2026-AVI-1279", "Multiples vulnérabilités dans SPIP", date(2026, 10, 7), ""),
        ("CERTFR-2026-AVI-1278", "Multiples vulnérabilités dans les produits Veeam", date(2026, 10, 1), ""),
    ]

    @pytest.mark.parametrize("builder", [page_articles, page_list])
    def test_extrait_ref_titre_date_lien(self, builder):
        items = certfr_client.parse_listing_html(builder(self.ITEMS), "avis")
        assert [i["ref"] for i in items] == ["CERTFR-2026-AVI-1279", "CERTFR-2026-AVI-1278"]
        assert items[0]["title"] == "Multiples vulnérabilités dans SPIP"
        assert items[0]["date"] == "2026-10-07"
        assert items[1]["date"] == "2026-10-01"
        assert items[0]["link"] == "https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1279/"
        assert items[0]["kind"] == "avis"
        assert "SPIP" in items[0]["summary"] or "CERTFR-2026-AVI-1279" in items[0]["summary"]

    def test_ignore_les_liens_d_une_autre_rubrique(self):
        html = page_articles(self.ITEMS) + '<a href="/alerte/CERTFR-2026-ALE-011/">Alerte</a>'
        refs = [i["ref"] for i in certfr_client.parse_listing_html(html, "avis")]
        assert "CERTFR-2026-ALE-011" not in refs

    def test_statut_d_alerte(self):
        html = page_articles([
            ("CERTFR-2026-ALE-011", "Vulnérabilités Citrix", date(2026, 9, 28), "<span>Alerte en cours</span>"),
            ("CERTFR-2026-ALE-005", "Vulnérabilité Ivanti", date(2026, 5, 2), "<span>Alerte close</span>"),
        ], section="alerte")
        items = certfr_client.parse_listing_html(html, "alerte")
        assert items[0]["alert_status"] == "Alerte en cours"
        assert items[1]["alert_status"] == "Alerte close"

    def test_titre_prefixe_par_la_reference_est_nettoye(self):
        assert certfr_client._clean_title("CERTFR-2026-AVI-1 : Vuln X", "CERTFR-2026-AVI-1") == "Vuln X"


class _FakeResp:
    def __init__(self, text="", status=200):
        self.text = text
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(str(self.status_code))


class _FakeSession:
    def __init__(self, pages):
        self.pages = pages  # url -> html
        self.headers = {}
        self.calls = []

    def get(self, url, timeout=None):
        self.calls.append(url)
        if url not in self.pages:
            return _FakeResp(status=404)
        return _FakeResp(self.pages[url])


@pytest.fixture(autouse=True)
def no_delay(monkeypatch):
    monkeypatch.setattr(config, "CERTFR_PAGE_DELAY_S", 0)


def _d(days_ago):
    return date.today() - timedelta(days=days_ago)


class TestFetchSection:
    BASE = "https://www.cert.ssi.gouv.fr"

    def test_pagine_jusqu_a_sortir_de_la_fenetre(self):
        pages = {
            f"{self.BASE}/avis/": page_articles([("CERTFR-2026-AVI-3", "A", _d(1), ""), ("CERTFR-2026-AVI-2", "B", _d(10), "")]),
            f"{self.BASE}/avis/page/2/": page_articles([("CERTFR-2026-AVI-1", "C", _d(60), ""), ("CERTFR-2025-AVI-9", "D", _d(120), "")]),
            f"{self.BASE}/avis/page/3/": page_articles([("CERTFR-2025-AVI-8", "E", _d(130), "")]),
            f"{self.BASE}/avis/page/4/": page_articles([("CERTFR-2025-AVI-7", "F", _d(140), "")]),
        }
        s = _FakeSession(pages)
        items, meta = certfr_client.fetch_section("avis", lookback_days=90, max_pages=50, session=s)
        assert [i["ref"] for i in items] == ["CERTFR-2026-AVI-3", "CERTFR-2026-AVI-2", "CERTFR-2026-AVI-1"]
        assert meta["stopped_because"] == "hors_fenetre"
        assert f"{self.BASE}/avis/page/4/" not in s.calls  # arrêt dès la page 3, entièrement hors fenêtre

    def test_s_arrete_sur_404(self):
        s = _FakeSession({f"{self.BASE}/avis/": page_articles([("CERTFR-2026-AVI-3", "A", _d(1), "")])})
        items, meta = certfr_client.fetch_section("avis", lookback_days=90, max_pages=50, session=s)
        assert len(items) == 1 and meta["stopped_because"] == "fin_des_pages"

    def test_respecte_max_pages(self):
        pages = {f"{self.BASE}/avis/" + (f"page/{n}/" if n > 1 else ""): page_articles([(f"CERTFR-2026-AVI-{n}", "x", _d(1), "")]) for n in range(1, 10)}
        items, meta = certfr_client.fetch_section("avis", lookback_days=90, max_pages=3, session=_FakeSession(pages))
        assert len(items) == 3 and meta["stopped_because"] == "max_pages"

    def test_alerte_ancienne_mais_en_cours_est_gardee(self):
        pages = {f"{self.BASE}/alerte/": page_articles([
            ("CERTFR-2026-ALE-011", "Récente", _d(5), "<span>Alerte close</span>"),
            ("CERTFR-2025-ALE-002", "Ancienne en cours", _d(300), "<span>Alerte en cours</span>"),
            ("CERTFR-2025-ALE-001", "Ancienne close", _d(310), "<span>Alerte close</span>"),
        ], section="alerte")}
        items, _ = certfr_client.fetch_section("alerte", lookback_days=90, max_pages=5, session=_FakeSession(pages))
        refs = [i["ref"] for i in items]
        assert "CERTFR-2025-ALE-002" in refs and "CERTFR-2025-ALE-001" not in refs

    def test_structure_inconnue_leve_une_erreur(self):
        html = '<a href="/avis/CERTFR-2026-AVI-1/">x</a><a href="/avis/CERTFR-2026-AVI-2/">y</a>'
        with pytest.raises(certfr_client.ListingStructureError):
            certfr_client.fetch_section("avis", 90, 5, session=_FakeSession({f"{self.BASE}/avis/": html}))


class TestCollectSection:
    def test_repli_rss_si_les_pages_echouent(self, monkeypatch):
        def boom(*a, **k):
            raise requests.ConnectionError("site injoignable")
        monkeypatch.setattr(certfr_client, "fetch_section", boom)
        monkeypatch.setattr(certfr_client, "fetch_feed", lambda url, d=None: [{
            "ref": "CERTFR-2026-AVI-5", "title": "CERTFR-2026-AVI-5 : Vuln RSS", "link": "l",
            "summary": "<p>résumé</p>", "date": "2026-10-01"}])
        items, health = certfr_client.collect_section("avis", 90)
        assert [i["title"] for i in items] == ["Vuln RSS"]
        assert items[0]["summary"] == "résumé"
        assert health["state"] == "degraded" and "injoignable" in health["error"]

    def test_down_si_rien_du_tout(self, monkeypatch):
        def boom(*a, **k):
            raise requests.ConnectionError("x")
        monkeypatch.setattr(certfr_client, "fetch_section", boom)
        monkeypatch.setattr(certfr_client, "fetch_feed", lambda url, d=None: [])
        items, health = certfr_client.collect_section("avis", 90)
        assert items == [] and health["state"] == "down" and health["ok"] is False

    def test_fusion_html_et_rss_sans_doublon(self, monkeypatch):
        html_items = [{"ref": "CERTFR-2026-AVI-2", "title": "B", "link": "l2", "date": "2026-10-02",
                       "summary": "court", "kind": "avis", "alert_status": ""}]
        monkeypatch.setattr(certfr_client, "fetch_section", lambda s, d=None: (html_items, {"pages": 1, "stopped_because": "hors_fenetre"}))
        monkeypatch.setattr(certfr_client, "fetch_feed", lambda url, d=None: [
            {"ref": "CERTFR-2026-AVI-2", "title": "CERTFR-2026-AVI-2 : B", "link": "l2", "summary": "résumé RSS bien plus long", "date": "2026-10-02"},
            {"ref": "CERTFR-2026-AVI-3", "title": "CERTFR-2026-AVI-3 : C", "link": "l3", "summary": "", "date": "2026-10-03"},
        ])
        items, health = certfr_client.collect_section("avis", 90)
        assert [i["ref"] for i in items] == ["CERTFR-2026-AVI-3", "CERTFR-2026-AVI-2"]  # tri date décroissante
        assert items[1]["summary"] == "résumé RSS bien plus long"
        assert health["state"] == "ok" and "+ 1 via RSS" in health["mode"]
SENTINEL_V2_EOF
echo "  écrit : tests/test_certfr_listing.py"

cat > tests/test_ado_client.py << 'SENTINEL_V2_EOF'
"""Tests du client Azure DevOps (écriture) — V2.

Aucun appel réel : requests.request est remplacé par un faux qui enregistre
les requêtes et renvoie des réponses au format de l'API ADO 7.1."""
import json

import pytest

import ado_client
import config

BULLETIN = {
    "ref": "CERTFR-2026-AVI-1232",
    "title": "Vulnérabilité dans MariaDB",
    "kind": "avis",
    "date": "2026-10-01",
    "link": "https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1232/",
    "status": "concerne",
    "count_label": "4 postes",
    "installed_summary": "10.3.39",
    "target_version": "10.11.9",
    "type_label": "Base de données",
    "limit_note": "3 postes Windows et 1 serveur Linux.",
    "hosts": [{"name": "CN-CNSA", "site": "Cholet", "installed": "10.3.39"},
              {"name": "SRV-<script>", "site": "", "installed": ""}],
}
ALICE = {"display_name": "Alice Martin", "unique_name": "alice@corp.fr"}
BOB = {"display_name": "Bob Durand", "unique_name": "bob@corp.fr"}


class TestPure:
    def test_titre(self):
        assert ado_client.build_title(BULLETIN) == "[CERTFR-2026-AVI-1232] Vulnérabilité dans MariaDB"
        assert len(ado_client.build_title({"ref": "R", "title": "x" * 400})) == 255

    def test_priorite(self):
        assert ado_client.priority_for({"kind": "alerte", "status": "non_concerne"}) == 1
        assert ado_client.priority_for({"kind": "avis", "status": "concerne"}) == 2
        assert ado_client.priority_for({"kind": "avis", "status": "a_verifier"}) == 3

    def test_tags_avec_reference_sans_doublon_ni_point_virgule(self):
        tags = ado_client.build_tags(BULLETIN, ["sentinel-cve", "a;b", "sentinel-cve"])
        assert tags == "sentinel-cve; a b; CERTFR-2026-AVI-1232"

    def test_description_echappe_le_html(self):
        html = ado_client.build_description_html(BULLETIN, "08/10/2026 10:00")
        assert "SRV-&lt;script&gt;" in html and "<script>" not in html
        assert "CN-CNSA" in html and "10.11.9" in html and "Concerné" in html
        assert BULLETIN["link"] in html

    def test_description_tronque_les_postes(self):
        b = dict(BULLETIN, hosts=[{"name": f"PC{i}"} for i in range(80)])
        html = ado_client.build_description_html(b)
        assert "PC49" in html and "PC50" not in html and "30 autre(s)" in html

    def test_ops_requirement(self):
        ops = ado_client.build_requirement_ops(BULLETIN, ALICE, "https://x/_apis/wit/workItems/12194",
                                               "Infra\\Sécu", "Sprint 1", ["sentinel-cve"], True)
        paths = {o["path"]: o["value"] for o in ops}
        assert paths["/fields/System.AssignedTo"] == "alice@corp.fr"
        assert paths["/fields/Microsoft.VSTS.Common.Priority"] == 2
        assert paths["/fields/System.AreaPath"] == "Infra\\Sécu"
        assert paths["/relations/-"]["rel"] == "System.LinkTypes.Hierarchy-Reverse"
        assert all(o["op"] == "add" for o in ops)

    def test_ops_sans_parent_ni_zone(self):
        ops = ado_client.build_requirement_ops(BULLETIN, ALICE, None, "", "", [], False)
        paths = [o["path"] for o in ops]
        assert "/relations/-" not in paths and "/fields/System.AreaPath" not in paths
        assert "/fields/Microsoft.VSTS.Common.Priority" not in paths

    def test_plan_une_personne(self, monkeypatch):
        monkeypatch.setattr(config, "ADO_WORK_ITEM_TYPE", "Requirement")
        plan = ado_client.plan_items(BULLETIN, [ALICE])
        assert len(plan) == 1 and plan[0]["assigned_to"] == "Alice Martin"

    def test_plan_plusieurs_personnes(self, monkeypatch):
        monkeypatch.setattr(config, "ADO_TASK_TYPE", "Task")
        plan = ado_client.plan_items(BULLETIN, [ALICE, BOB])
        assert [p["role"] for p in plan] == ["requirement", "task", "task"]
        assert plan[0]["assigned_to"] == "Alice Martin"
        assert [p["assigned_to"] for p in plan[1:]] == ["Alice Martin", "Bob Durand"]

    def test_wiql_escape(self):
        assert ado_client.wiql_escape("a'b") == "a''b"


class FakeHTTP:
    """Simule l'API ADO : enregistre chaque requête, renvoie des ids croissants."""
    def __init__(self, fail_on_task_for=None):
        self.calls = []
        self.next_id = 5000
        self.fail_on_task_for = fail_on_task_for

    def __call__(self, method, url, params=None, auth=None, json=None, headers=None, timeout=None):
        self.calls.append({"method": method, "url": url, "params": params, "json": json, "headers": headers or {}})
        if "/teams/" in url and url.endswith("/members"):
            team = url.split("/teams/")[1].split("/")[0]
            members = {
                "t1": [{"identity": {"displayName": "Bob Durand", "uniqueName": "bob@corp.fr"}},
                       {"identity": {"displayName": "[Projet]\\Readers", "uniqueName": "grp", "isContainer": True}}],
                "t2": [{"identity": {"displayName": "Alice Martin", "uniqueName": "alice@corp.fr"}},
                       {"identity": {"displayName": "Bob Durand", "uniqueName": "BOB@corp.fr"}}],
            }[team]
            return _Resp(200, {"value": members})
        if url.endswith("/teams"):
            return _Resp(200, {"value": [{"id": "t1", "name": "Infra"}, {"id": "t2", "name": "Sécurité"}]})
        if url.endswith("/wit/wiql"):
            return _Resp(200, {"workItems": []})
        if "/wit/workitems/$" in url:
            if self.fail_on_task_for and json and any(
                    o["path"] == "/fields/System.AssignedTo" and o["value"] == self.fail_on_task_for for o in json) \
                    and "Task" in url:
                return _Resp(400, {"message": "TF401320: champ obligatoire manquant"})
            self.next_id += 1
            return _Resp(200, {"id": self.next_id})
        return _Resp(404, {"message": "inconnu"})


class _Resp:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body
        self.content = json.dumps(body).encode()
        self.text = json.dumps(body)

    def json(self):
        return self._body


@pytest.fixture
def fake(monkeypatch):
    f = FakeHTTP()
    monkeypatch.setattr(ado_client.requests, "request", f)
    monkeypatch.setattr(config, "ADO_PARENT_ID", 12194)
    monkeypatch.setattr(config, "ADO_WORK_ITEM_TYPE", "Requirement")
    monkeypatch.setattr(config, "ADO_TASK_TYPE", "Task")
    monkeypatch.setattr(config, "ADO_TEAMS", [])
    return f


def client():
    return ado_client.ADOClient("Beneteau-Group", "IT PROJECTS PORTFOLIO", "pat")


class TestHTTP:
    def test_url_de_creation_et_content_type(self, fake):
        client().create_from_bulletin(BULLETIN, [ALICE])
        c = [x for x in fake.calls if x["method"] == "POST" and "/workitems/" in x["url"]][0]
        assert c["url"] == "https://dev.azure.com/Beneteau-Group/IT%20PROJECTS%20PORTFOLIO/_apis/wit/workitems/$Requirement"
        assert c["headers"]["Content-Type"] == "application/json-patch+json"
        assert c["params"]["api-version"] == "7.1"
        parent = [o for o in c["json"] if o["path"] == "/relations/-"][0]
        assert parent["value"]["url"].endswith("/_apis/wit/workItems/12194")

    def test_une_personne_un_seul_work_item(self, fake):
        res = client().create_from_bulletin(BULLETIN, [ALICE])
        assert len(res["created"]) == 1 and res["errors"] == []
        assert res["created"][0]["url"].endswith("/_workitems/edit/5001")

    def test_plusieurs_personnes_requirement_plus_une_task_chacune(self, fake):
        res = client().create_from_bulletin(BULLETIN, [ALICE, BOB])
        types = [c["type"] for c in res["created"]]
        assert types == ["Requirement", "Task", "Task"]
        task_calls = [x for x in fake.calls if x["url"].endswith("$Task")]
        for t in task_calls:
            parent = [o for o in t["json"] if o["path"] == "/relations/-"][0]
            assert parent["value"]["url"].endswith("/workItems/5001")  # rattachées au requirement créé
        assert [c["assigned_to"] for c in res["created"]] == ["Alice Martin", "Alice Martin", "Bob Durand"]

    def test_echec_d_une_task_remonte_sans_annuler_le_reste(self, fake):
        fake.fail_on_task_for = "bob@corp.fr"
        res = client().create_from_bulletin(BULLETIN, [ALICE, BOB])
        assert len(res["created"]) == 2
        assert "Bob Durand" in res["errors"][0] and "TF401320" in res["errors"][0]

    def test_validate_only_ne_cree_rien(self, fake):
        res = client().create_from_bulletin(BULLETIN, [ALICE, BOB], validate_only=True)
        assert res["created"] == [] and res["validated"] is True
        posts = [x for x in fake.calls if "/workitems/" in x["url"]]
        assert len(posts) == 1 and posts[0]["params"]["validateOnly"] == "true"

    def test_personnes_dedoublonnees_sans_groupes(self, fake):
        people = client().list_people()
        assert [p["unique_name"].lower() for p in people] == ["alice@corp.fr", "bob@corp.fr"]
        bob = people[1]
        assert set(bob["teams"]) == {"Infra", "Sécurité"}

    def test_filtre_par_equipe(self, fake, monkeypatch):
        monkeypatch.setattr(config, "ADO_TEAMS", ["sécurité"])
        people = client().list_people()
        assert {p["display_name"] for p in people} == {"Alice Martin", "Bob Durand"}
        assert not any("/teams/t1/" in c["url"] for c in fake.calls)

    def test_erreur_lisible(self, monkeypatch):
        monkeypatch.setattr(ado_client.requests, "request", lambda *a, **k: _Resp(401, {}))
        with pytest.raises(ado_client.ADOError, match="PAT"):
            client().find_existing("X")
SENTINEL_V2_EOF
echo "  écrit : tests/test_ado_client.py"

cat > tests/test_webapi.py << 'SENTINEL_V2_EOF'
"""Tests de l'API interne (Flask) : jeton d'action, prévisualisation et
création ADO. Base SQLite temporaire, faux client ADO."""
import pytest

import config
import db
import webapi
from ado_client import ADOError

TOKEN = "s3cret-token"
BULLETIN = {"ref": "CERTFR-2026-AVI-1", "title": "Vuln X", "kind": "avis", "status": "concerne",
            "status_label": "Concerné", "hosts": [], "date": "2026-10-01", "link": "l"}
PEOPLE = [{"display_name": "Alice Martin", "unique_name": "alice@corp.fr", "teams": ["Sécu"]},
          {"display_name": "Bob Durand", "unique_name": "bob@corp.fr", "teams": ["Infra"]}]


class FakeADO:
    existing = []
    validation_error = None
    created_calls = []

    def list_people(self):
        return PEOPLE

    def find_existing(self, ref):
        return list(self.existing)

    def create_from_bulletin(self, bulletin, assignees, validate_only=False):
        if validate_only:
            if self.validation_error:
                raise ADOError(self.validation_error)
            return {"created": [], "errors": [], "validated": True}
        FakeADO.created_calls.append((bulletin["ref"], [a["unique_name"] for a in assignees]))
        return {"created": [{"id": 9001, "type": "Requirement", "url": "u/9001", "assigned_to": assignees[0]["display_name"],
                             "title": "t", "parent_id": 12194}], "errors": []}


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setattr(config, "ACTION_TOKEN", TOKEN)
    monkeypatch.setattr(config, "ADO_WRITE_ENABLED", True)
    monkeypatch.setattr(config, "ADO_ORG", "o")
    monkeypatch.setattr(config, "ADO_PROJECT", "p")
    monkeypatch.setattr(config, "ADO_PAT", "x")
    monkeypatch.setattr(webapi, "ado_client_factory", FakeADO)
    monkeypatch.setattr(webapi.time, "sleep", lambda s: None)
    webapi._people_cache.update({"ts": 0.0, "data": None})
    FakeADO.existing, FakeADO.validation_error, FakeADO.created_calls = [], None, []
    db.replace_cycle_bulletins([BULLETIN])
    return webapi.create_app(lambda trigger: None).test_client()


H = {"X-Action-Token": TOKEN}


class TestJeton:
    def test_status_public(self, app):
        assert app.get("/api/status").status_code == 200

    def test_sans_jeton_refuse(self, app):
        assert app.post("/api/auth/check").status_code == 403
        assert app.get("/api/ado/people").status_code == 403
        assert app.post("/api/ado/create", json={}).status_code == 403

    def test_mauvais_jeton_refuse(self, app):
        assert app.post("/api/auth/check", headers={"X-Action-Token": "nope"}).status_code == 403

    def test_bon_jeton(self, app):
        r = app.post("/api/auth/check", headers=H)
        assert r.status_code == 200 and r.json["ado_enabled"] is True

    def test_ancien_en_tete_v1_accepte(self, app):
        assert app.post("/api/auth/check", headers={"X-Trigger-Token": TOKEN}).status_code == 200

    def test_actions_desactivees_sans_jeton_configure(self, app, monkeypatch):
        monkeypatch.setattr(config, "ACTION_TOKEN", "")
        r = app.post("/api/auth/check", headers={"X-Action-Token": ""})
        assert r.status_code == 403 and "désactivées" in r.json["error"]


class TestADO:
    def test_personnes(self, app):
        r = app.get("/api/ado/people", headers=H)
        assert r.status_code == 200 and len(r.json["people"]) == 2

    def test_ado_desactive(self, app, monkeypatch):
        monkeypatch.setattr(config, "ADO_WRITE_ENABLED", False)
        assert app.get("/api/ado/people", headers=H).status_code == 403

    def test_preview(self, app):
        r = app.post("/api/ado/preview", headers=H, json={"ref": BULLETIN["ref"], "assignees": ["alice@corp.fr", "bob@corp.fr"]})
        assert r.status_code == 200
        assert [p["role"] for p in r.json["plan"]] == ["requirement", "task", "task"]
        assert r.json["existing"] == [] and r.json["validation_error"] is None

    def test_preview_remonte_l_erreur_de_validation(self, app):
        FakeADO.validation_error = "Le champ Requirement Type est obligatoire"
        r = app.post("/api/ado/preview", headers=H, json={"ref": BULLETIN["ref"], "assignees": ["alice@corp.fr"]})
        assert r.status_code == 200 and "Requirement Type" in r.json["validation_error"]

    def test_personne_inconnue_refusee(self, app):
        r = app.post("/api/ado/create", headers=H, json={"ref": BULLETIN["ref"], "assignees": ["mallory@evil.com"]})
        assert r.status_code == 400 and "inconnue" in r.json["error"]
        assert FakeADO.created_calls == []

    def test_aucune_personne_refusee(self, app):
        r = app.post("/api/ado/create", headers=H, json={"ref": BULLETIN["ref"], "assignees": []})
        assert r.status_code == 400

    def test_bulletin_inconnu(self, app):
        r = app.post("/api/ado/create", headers=H, json={"ref": "CERTFR-1999-AVI-1", "assignees": ["alice@corp.fr"]})
        assert r.status_code == 404

    def test_creation_et_journal(self, app):
        r = app.post("/api/ado/create", headers=H, json={"ref": BULLETIN["ref"], "assignees": ["ALICE@corp.fr"]})
        assert r.status_code == 201 and r.json["created"][0]["id"] == 9001
        assert FakeADO.created_calls == [(BULLETIN["ref"], ["alice@corp.fr"])]
        log = db.get_ado_creations_by_ref()[BULLETIN["ref"]]
        assert log[0]["id"] == 9001 and log[0]["assigned_to"] == "Alice Martin"

    def test_doublon_bloque_sauf_confirmation(self, app):
        FakeADO.existing = [{"id": 42, "title": "déjà là", "state": "Active", "type": "Requirement", "assigned_to": "", "url": "u"}]
        body = {"ref": BULLETIN["ref"], "assignees": ["alice@corp.fr"]}
        r = app.post("/api/ado/create", headers=H, json=body)
        assert r.status_code == 409 and r.json["existing"][0]["id"] == 42
        assert FakeADO.created_calls == []
        r = app.post("/api/ado/create", headers=H, json=dict(body, allow_duplicate=True))
        assert r.status_code == 201

    def test_contenu_reconstruit_cote_serveur(self, app):
        # Un titre envoyé par le navigateur est ignoré : seule la base fait foi.
        app.post("/api/ado/create", headers=H, json={"ref": BULLETIN["ref"], "assignees": ["alice@corp.fr"], "title": "<img onerror>"})
        assert FakeADO.created_calls[0][0] == BULLETIN["ref"]


class TestCycle:
    def test_trigger(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "ACTION_TOKEN", TOKEN)
        seen = []
        app = webapi.create_app(lambda trigger: seen.append(trigger)).test_client()
        r = app.post("/api/trigger", headers=H)
        assert r.status_code == 202
        for _ in range(50):
            if seen:
                break
            webapi.time.sleep(0.01)
        assert seen == ["manuel"]
SENTINEL_V2_EOF
echo "  écrit : tests/test_webapi.py"

cat > tests/test_stats_db_render.py << 'SENTINEL_V2_EOF'
"""Tests des données de graphiques, de la migration SQLite V1 -> V2, du
prompt personnalisable et du rendu complet du dashboard."""
import os
import sqlite3
from datetime import date, datetime
from zoneinfo import ZoneInfo

import pytest

import agent_pipeline
import config
import db
import main
import stats


def B(ref, status, kind="avis", d="2026-10-05", title="Vulnérabilité dans GLPI"):
    return {"ref": ref, "status": status, "status_label": main.STATUS_LABELS[status], "kind": kind,
            "date": d, "title": title, "link": "https://x", "hosts": []}


class TestStats:
    @pytest.mark.parametrize("title,expected", [
        ("Multiples vulnérabilités dans les produits Veeam", "Veeam"),
        ("Vulnérabilité dans Metabase", "Metabase"),
        ("Multiples vulnérabilités dans le noyau Linux de Debian", "Linux (noyau)"),
        ("Multiples vulnérabilités dans Microsoft Windows", "Microsoft"),
        ("Vulnérabilité dans l'interface de gestion", "Interface"),
        ("Titre sans motif", "Titre"),
        ("", "Autre"),
    ])
    def test_product_of(self, title, expected):
        assert stats.product_of(title) == expected

    def test_taux(self):
        assert stats.concerned_rate({"concerne": 1, "a_verifier": 1, "non_concerne": 2, "total": 4}) == 25.0
        assert stats.concerned_rate({"concerne": 0, "total": 0}) == 0.0

    def test_top_products_classe_par_concernes(self):
        bs = [B("1", "concerne", title="Vuln dans Veeam"), B("2", "a_verifier", title="Vuln dans GLPI"),
              B("3", "a_verifier", title="Vuln dans GLPI"), B("4", "non_concerne", title="Vuln dans Zimbra")]
        rows = stats.top_products(bs)
        assert [r["label"] for r in rows] == ["Veeam", "GLPI"]
        assert rows[1]["total"] == 2

    def test_weekly(self):
        bs = [B("1", "concerne", d="2026-10-05"), B("2", "ok" if False else "non_concerne", d="2026-10-07"),
              B("3", "concerne", d="2026-09-30"), B("4", "concerne", d="2020-01-01"), B("5", "concerne", d="")]
        w = stats.weekly(bs, weeks=3, today=date(2026, 10, 8))
        assert [x["start"] for x in w] == ["2026-09-21", "2026-09-28", "2026-10-05"]
        assert w[-1]["concerne"] == 1 and w[-1]["non_concerne"] == 1 and w[1]["concerne"] == 1

    def test_rate_history_ignore_les_cycles_v1(self):
        h = [{"ts": "a", "score": 50, "total": None}, {"ts": "b", "score": 60, "concerne": 2, "a_verifier": 0, "non_concerne": 8, "total": 10}]
        assert stats.rate_history(h) == [{"ts": "b", "rate": 20.0, "concerne": 2, "a_verifier": 0, "non_concerne": 8, "total": 10}]


class TestMigration:
    def test_base_v1_migree_sans_perte(self, tmp_path, monkeypatch):
        path = tmp_path / "v1.db"
        with sqlite3.connect(path) as c:
            c.execute("CREATE TABLE score_history (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, score INTEGER NOT NULL)")
            c.execute("INSERT INTO score_history (ts, score) VALUES ('2026-10-01T03:44:00', 55)")
        monkeypatch.setattr(db, "DB_PATH", str(path))
        db.init_db()
        db.insert_score(datetime(2026, 10, 2), 61, {"concerne": 3, "a_verifier": 2, "non_concerne": 5, "total": 10})
        h = db.get_history()
        assert h[0]["score"] == 55 and h[0]["total"] is None
        assert h[1]["concerne"] == 3 and h[1]["total"] == 10
        db.init_db()  # idempotent


class TestPrompt:
    def test_prompt_par_defaut(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "AI_SYSTEM_PROMPT_FILE", str(tmp_path / "absent.txt"))
        p = agent_pipeline.get_system_prompt()
        assert p == agent_pipeline.DEFAULT_SYSTEM_PROMPT
        assert "PLUSIEURS fiches Software" in p  # correctif MariaDB conservé en V2
        assert "Azure DevOps" not in p

    def test_prompt_personnalise(self, tmp_path, monkeypatch):
        f = tmp_path / "p.txt"
        f.write_text("Mon prompt maison", encoding="utf-8")
        monkeypatch.setattr(config, "AI_SYSTEM_PROMPT_FILE", str(f))
        assert agent_pipeline.get_system_prompt() == "Mon prompt maison"

    def test_fichier_vide_ignore(self, tmp_path, monkeypatch):
        f = tmp_path / "p.txt"
        f.write_text("  \n", encoding="utf-8")
        monkeypatch.setattr(config, "AI_SYSTEM_PROMPT_FILE", str(f))
        assert agent_pipeline.get_system_prompt() == agent_pipeline.DEFAULT_SYSTEM_PROMPT

    def test_plus_d_outil_ado(self):
        names = [t["name"] for t in agent_pipeline.TOOLS]
        assert "ado_get_comments" not in names and not hasattr(agent_pipeline, "match_ado_ticket")

    def test_ia_desactivee(self, monkeypatch):
        monkeypatch.setattr(config, "AI_ENABLED", False)
        r = agent_pipeline.analyze_bulletin(None, {"ref": "X"})
        assert r["status"] == "a_verifier" and r["pending_ai"] is False


class TestCycle:
    def test_tri_alertes_d_abord_puis_recents(self):
        bs = [B("a1", "concerne", d="2026-10-01"), B("al", "concerne", kind="alerte", d="2026-01-01"), B("a2", "concerne", d="2026-10-05")]
        assert [b["ref"] for b in main.sort_bulletins(bs)] == ["al", "a2", "a1"]

    def test_glpi_injoignable_rien_en_non_concerne(self, monkeypatch):
        class Boom:
            def __enter__(self):
                raise ConnectionError("GLPI down")

            def __exit__(self, *a):
                return False
        monkeypatch.setattr(main, "GLPIClient", Boom)
        bs, counts, health = main.analyze_all([{"ref": "1", "title": "t"}, {"ref": "2", "title": "u"}])
        assert health["state"] == "down"
        assert counts == {"concerne": 0, "a_verifier": 2, "non_concerne": 0, "total": 2}

    def test_cycle_complet_et_rendu(self, tmp_path, monkeypatch):
        """Cycle de bout en bout avec CERT-FR et GLPI simulés : vérifie la page produite."""
        monkeypatch.setattr(config, "OUTPUT_DIR", str(tmp_path))
        monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "s.db"))
        monkeypatch.setattr(config, "AI_ENABLED", False)
        monkeypatch.setattr(config, "ACTION_TOKEN", "Zq9-jeton-unique")
        monkeypatch.setattr(config, "ADO_WRITE_ENABLED", True)
        monkeypatch.setattr(main.certfr_client, "collect_all", lambda: {
            "bulletins": [
                {"ref": "CERTFR-2026-AVI-1", "title": "Vuln dans </script><b>GLPI", "kind": "avis", "date": "2026-10-05", "link": "l", "summary": "s", "alert_status": ""},
                {"ref": "CERTFR-2026-ALE-1", "title": "Vuln dans Citrix", "kind": "alerte", "date": "2026-10-04", "link": "l", "summary": "", "alert_status": "Alerte en cours"},
            ],
            "info": [{"ref": "CERTFR-2026-ACT-40", "title": "Bulletin d'actualité", "kind": "actualite", "date": "2026-10-06", "link": "l"}],
            "health": {"avis": {"state": "ok", "count": 1, "pages": 1, "mode": "pages HTML", "error": ""},
                       "alerte": {"state": "ok", "count": 1, "pages": 1, "mode": "pages HTML", "error": ""}},
        })

        class FakeGLPI:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        monkeypatch.setattr(main, "GLPIClient", FakeGLPI)
        db.insert_ado_creation("CERTFR-2026-AVI-1", 777, "Requirement", "t", "Alice", "https://ado/777", None)

        main.run_cycle("test")

        html = (tmp_path / "index.html").read_text(encoding="utf-8")
        assert "2026-ACT-40" in html  # publications d'information affichées
        assert "ADO #777" in html and "Créer un Requirement ADO" in html
        assert "</script><b>GLPI" not in html  # titre échappé partout (HTML et JSON)
        assert 'data-token' not in html and "Zq9-jeton-unique" not in html  # le jeton n'est jamais dans la page
        assert "Alerte en cours" in html and "Bulletin d&#39;actualité" in html
        assert db.get_cycle_bulletin("CERTFR-2026-ALE-1")["kind"] == "alerte"
        runs = db.get_cycle_runs()
        assert runs[-1]["trigger"] == "test" and runs[-1]["n_bulletins"] == 2
        assert db.get_history()[-1]["total"] == 2
        assert not os.path.exists(tmp_path / "index.html.tmp")
SENTINEL_V2_EOF
echo "  écrit : tests/test_stats_db_render.py"

python3 -m py_compile app/*.py 2>/dev/null && echo "Syntaxe Python OK" || echo "(python3 absent de l'hôte : la syntaxe sera vérifiée par les tests dans le conteneur)"

echo
echo "Clés présentes dans .env.example mais absentes de votre .env :"
missing=0
while IFS= read -r line; do
  key="${line%%=*}"
  case "$line" in ''|\#*) continue;; esac
  if ! grep -qE "^${key}=" .env 2>/dev/null; then
    if [ "$key" = "ACTION_TOKEN" ] && grep -qE "^TRIGGER_TOKEN=." .env; then continue; fi
    echo "   $key"; missing=1
  fi
done < .env.example
[ "$missing" = 0 ] && echo "   (aucune)"
echo
echo "V2 installée. Étapes suivantes : compléter .env, puis rebuild + tests + redémarrage."
