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
