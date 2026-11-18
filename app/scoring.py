"""Score de sécurité du parc (0-100), pondéré par bulletin (pas par poste).

score = round(100 × (non_concerné + 0,5 × à_vérifier) / total)
Bandes : < 40 critique, < 75 vigilance, sinon conforme."""


def compute_score(concerne: int, a_verifier: int, non_concerne: int) -> int:
    total = concerne + a_verifier + non_concerne
    if total <= 0:
        return 0
    return round(100 * (non_concerne + 0.5 * a_verifier) / total)


def score_band(score: int) -> dict:
    if score < 40:
        return {"key": "crit", "label": "Critique"}
    if score < 75:
        return {"key": "warn", "label": "Vigilance"}
    return {"key": "ok", "label": "Conforme"}


def gauge_dasharray(score: int) -> float:
    """Longueur de l'arc de la jauge (demi-cercle de rayon 80 = 251,3)."""
    return round(max(0, min(100, score)) / 100 * 251.3, 1)
