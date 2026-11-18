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
    agent_pipeline.DETERMINISTIC_FAILURES.clear()
    try:
        with GLPIClient() as glpi:
            # Phase déterministe en parallèle (réseau : avis CERT-FR + GLPI),
            # puis phase IA séquentielle pour ne pas fausser le budget.
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=4) as pool:
                dets = list(pool.map(lambda x: agent_pipeline._try_deterministic(glpi, x), bulletins))
            for b, det in zip(bulletins, dets):
                b.update(agent_pipeline.analyze_bulletin(glpi, b, det))
    except Exception as exc:  # noqa: BLE001
        log.error("GLPI injoignable : %s", exc)
        glpi_health = _source("GLPI", "down", f"Injoignable : {exc}")
        for b in bulletins:
            if "status" not in b:
                b.update(agent_pipeline._fallback(
                    "GLPI injoignable pendant ce cycle : impossible de vérifier l'inventaire."
                ))
    failed = len(set(agent_pipeline.DETERMINISTIC_FAILURES))
    if failed and glpi_health["state"] == "ok":
        # GLPI instable : ces bulletins n'ont pas pu être vérifiés (restent « à vérifier »).
        share = failed / max(len(bulletins), 1)
        glpi_health = _source("GLPI", "down" if share > 0.2 else "degraded",
                              f"Instable : {failed} analyse(s) interrompue(s) sur {len(bulletins)}", None)
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
    if glpi_health["state"] == "degraded":
        partial_reasons.append("GLPI instable")
    kept_previous = False
    if any(x["state"] == "down" for x in (certfr_health, glpi_health)):
        # Une source en panne ne doit pas vider le dashboard : on garde les
        # derniers résultats connus (affichés avec le bandeau « cycle partiel »).
        prev = db.get_all_cycle_bulletins()
        if prev:
            bulletins, kept_previous = prev, True
            counts = stats.status_counts(bulletins)
            log.warning("Cycle partiel (%s) : derniers résultats conservés (%d bulletins).",
                        ", ".join(partial_reasons), len(bulletins))
    score = scoring.compute_score(counts["concerne"], counts["a_verifier"], counts["non_concerne"])
    prev_score = db.latest_score()
    if not partial_reasons:
        # On n'enregistre pas un cycle partiel : il fausserait les courbes.
        db.insert_score(now, score, counts)
        changelog_entry = agent_pipeline.write_changelog_entry(now_str, prev_score, score, counts)
        db.insert_changelog_entry(now, changelog_entry)
    else:
        db.insert_changelog_entry(now, f"Cycle du {now_str} partiel ({', '.join(partial_reasons)}) : score non enregistré.")

    if not kept_previous:
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
