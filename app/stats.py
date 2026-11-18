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
