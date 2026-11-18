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


DETERMINISTIC_FAILURES: list[str] = []  # refs dont l'analyse a échoué à cause de GLPI/réseau


def _try_deterministic(glpi: GLPIClient, bulletin: dict) -> dict | None:
    """Étape 1 (ADR-001) : croisement déterministe, sans IA ni token. Toute
    erreur => None (l'agent IA prend le relais, jamais de « non concerné »)."""
    if not config.DETERMINISTIC_ENABLED:
        return None
    try:
        import certfr_client
        import deterministic
        from glpi_inventory import Inventory
        text = certfr_client.fetch_detail(bulletin.get("link", ""))["text"]
        return deterministic.analyze(bulletin, text, Inventory(glpi))
    except Exception as exc:  # noqa: BLE001
        log.warning("Moteur déterministe indisponible pour %s : %s", bulletin.get("ref"), exc)
        if isinstance(exc, (requests.RequestException, GLPIError)) or "illisible" in str(exc):
            DETERMINISTIC_FAILURES.append(str(bulletin.get("ref")))
        return None


_UNSET = object()


def analyze_bulletin(glpi: GLPIClient, bulletin: dict, det=_UNSET) -> dict:
    """Fait mener l'investigation complète d'un bulletin par l'agent.
    Renvoie {status, hosts, count_label, installed_summary, target_version,
    type_label, limit_note}."""
    if det is _UNSET:
        det = _try_deterministic(glpi, bulletin)
    if det is not None and det["status"] in ("concerne", "non_concerne"):
        return det

    client = _client()
    if client is None:
        if det is not None:  # verdict déterministe « à vérifier » et motivé
            return det
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
