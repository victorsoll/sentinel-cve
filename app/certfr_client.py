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


def _decode(r: requests.Response) -> str:
    """cert.ssi.gouv.fr n'annonce pas son encodage : requests retombe sur
    latin-1 et casse « Publié le ». On force l'UTF-8 (repli : détection)."""
    try:
        return r.content.decode("utf-8")
    except UnicodeDecodeError:
        r.encoding = r.apparent_encoding or "latin-1"
        return r.text


# ---------------------------------------------------------------- RSS (V1)
def _within_lookback(entry, days: int) -> bool:
    published = entry.get("published_parsed") or entry.get("updated_parsed")
    if not published:
        return True  # on garde par défaut plutôt que de perdre un avis
    dt = datetime(*published[:6], tzinfo=timezone.utc)
    return dt >= datetime.now(timezone.utc) - timedelta(days=days)


def fetch_feed(url: str, lookback_days: int | None = None) -> list[dict]:
    lookback_days = lookback_days or config.CERTFR_LOOKBACK_DAYS
    try:
        resp = requests.get(url, timeout=30, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
        parsed = feedparser.parse(resp.content)
    except requests.RequestException as exc:
        log.warning("RSS %s injoignable (%s)", url, exc)
        parsed = feedparser.parse(b"")
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
        for attempt in range(3):  # pannes DNS / réseau passagères
            try:
                r = s.get(url, timeout=30)
                break
            except requests.ConnectionError:
                if attempt == 2:
                    raise
                time.sleep(5 * (attempt + 1))
        if r.status_code == 404:
            meta["stopped_because"] = "fin_des_pages"
            break
        r.raise_for_status()
        meta["pages"] = page
        items = parse_listing_html(_decode(r), section)
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


_HTTP = requests.Session()
_HTTP.mount("https://", requests.adapters.HTTPAdapter(pool_connections=2, pool_maxsize=8))
_DETAIL_CACHE: dict[str, tuple[float, dict]] = {}


def fetch_detail(link: str) -> dict:
    """Texte intégral d'une publication (systèmes affectés, versions, CVE).
    Connexion persistante, 3 essais, cache 1 h."""
    hit = _DETAIL_CACHE.get(link)
    if hit and time.time() - hit[0] < 3600:
        return hit[1]
    last = None
    for attempt in range(3):
        try:
            r = _HTTP.get(link, timeout=30, headers={"User-Agent": USER_AGENT})
            r.raise_for_status()
            break
        except requests.RequestException as exc:
            last = exc
            time.sleep(3 * (attempt + 1))
    else:
        raise last
    soup = BeautifulSoup(_decode(r), "html.parser")
    content = soup.select_one("div.entry-content, main, article")
    text = content.get_text("\n", strip=True) if content else soup.get_text("\n", strip=True)
    out = {"link": link, "text": text}
    _DETAIL_CACHE[link] = (time.time(), out)
    return out
