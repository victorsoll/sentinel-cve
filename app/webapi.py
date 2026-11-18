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
