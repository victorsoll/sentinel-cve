"""Rapprochement déterministe des avis avec l'inventaire GLPI quand il n'y a
pas de règle logicielle : présence d'un produit dans le parc, systèmes
d'exploitation (Windows, Ubuntu, Debian…), avis sans déclaration de version.

Règle d'or inchangée : « absent » n'est conclu que si AUCUN mot distinctif du
produit n'existe dans l'inventaire ; au moindre doute => présent / à vérifier.
"""
import re

import config
from glpi_inventory import Inventory, _tokens

# Mots génériques : ne prouvent pas la présence d'un produit.
STOP = {
    "microsoft", "windows", "server", "servers", "version", "versions", "pour", "les", "des", "the",
    "systèmes", "systemes", "bits", "bit", "édition", "edition", "éditions", "editions", "installation",
    "core", "enterprise", "entreprise", "standard", "professional", "professionnel", "pro", "suite",
    "platform", "plateforme", "service", "services", "cloud", "software", "tools", "client", "data",
    "security", "management", "manager", "and", "for", "avec", "sans", "lts", "esm", "arm64", "x64",
    "x86", "mac", "apps", "app", "premium", "ultimate", "home", "free", "open", "source", "network",
    "networks", "system", "systems", "pack", "update", "mise", "jour", "branch", "upcoming", "linux",
    "noyau", "kernel", "multiples", "vulnérabilités", "vulnérabilité",
}

_WIN_CLIENT = re.compile(r"windows\s+(10|11)\b(?:.*?version\s+(\w+))?", re.IGNORECASE)
_WIN_SERVER = re.compile(r"windows\s+server\s+(\d{4})(\s+r2)?", re.IGNORECASE)
ASSUMED_VERSION = {"debian": "12"}
_DEB_CODENAME = {"buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13", "forky": "14"}
_DISTROS = (
    ("ubuntu", re.compile(r"ubuntu\s+(\d{2}\.\d{2})", re.I)),
    ("debian", re.compile(r"debian\s+(\d+|buster|bullseye|bookworm|trixie|forky)", re.I)),
    ("red hat", re.compile(r"red\s*hat.*?(\d+)", re.I)),
    ("centos", re.compile(r"centos\s+(\d+)", re.I)),
)


def affected_lines(text: str) -> list[str]:
    """Lignes de la section « Systèmes affectés » (jusqu'à « Résumé »)."""
    lines = (text or "").splitlines()
    out, on = [], False
    for raw in lines:
        s = raw.strip()
        if not on:
            on = s.lower().startswith("systèmes affectés")
            continue
        if s.lower().startswith(("résumé", "resume")):
            break
        if s:
            out.append(s.lstrip("-•*· ").strip())
    return out


def _distinct(line: str) -> set[str]:
    return {t for t in _tokens(line) if t not in STOP and not t.isdigit()}


def near_names(inv: Inventory, line: str, limit: int = 3) -> list[str] | None:
    """Noms GLPI contenant TOUS les mots distinctifs de la ligne. [] = absent ;
    None = rien de distinctif dans la ligne (on ne conclut pas)."""
    toks = _distinct(line)
    if not toks:
        return None
    return [n for n, t in inv.name_index() if toks <= t][:limit]


def is_absent(inv: Inventory, line: str) -> bool:
    return near_names(inv, line) == []


def product_phrase(product: str) -> str:
    """« Microsoft Excel 2016 (édition 32 bits) » -> « Microsoft Excel 2016 »."""
    p = re.sub(r"\(.*?\)", " ", product)
    p = re.sub(r"\b(pour|for)\b.*$", " ", p, flags=re.I)
    p = re.sub(r"\b(version|v)\s*\d.*$", " ", p, flags=re.I)
    return re.sub(r"\s+", " ", p).strip()


def auto_rule(product: str) -> dict | None:
    """Règle stricte générée pour un produit sans règle écrite : le nom GLPI doit
    être « [éditeur] <produit> [version / architecture] » — pas « GLPI Agent »
    pour « GLPI »."""
    phrase = product_phrase(product)
    words = [w for w in re.split(r"\s+", phrase) if w]
    if not words or not _distinct(phrase):
        return None
    body = r"\s+".join(re.escape(w) for w in words)
    rx = rf"^(?:[\w.&+-]+\s+)?{body}(?:\s+(?:\d|\(|v\d|x64|x86|64-bit|32-bit|amd64).*)?$"
    seed = max(words, key=len)
    return {"id": f"auto:{phrase.lower()}", "type": "Application", "glpi": rx, "exclude": [],
            "seed": seed, "strip_after": "+-", "keep_parts": 0, "auto": True}


def _hosts(inv: Inventory, rows: list[dict], target: str) -> list[dict]:
    comp = inv.computers()
    out = []
    for r in rows:
        c = comp.get(r["computer_id"]) or {}
        out.append({"name": c.get("name") or f"Computer #{r['computer_id']}",
                    "site": c.get("locations_id") or "non renseigné",
                    "installed": f"{r['os']} {r['version']}".replace(" 0", "").strip(),
                    "target": target})
    return out


def _excluded(c: dict) -> bool:
    st = str(c.get("states_id") or "")
    return bool(st and re.search(getattr(config, "GLPI_EXCLUDED_STATES_REGEX", "Out of Park"), st, re.I))


def match_os(inv: Inventory, line: str, target: str = "") -> tuple[str, list[dict], str] | None:
    """Ligne = un système d'exploitation connu ? Renvoie (état, postes, note) avec
    état 'hosts' (postes dans la branche visée), 'none' (OS suivi mais branche
    absente du parc) ou 'unknown' (OS présent, version GLPI inconnue) ; None si
    la ligne n'est pas un OS géré ici."""
    rows = inv.os_rows()
    comp = inv.computers()
    live = [r for r in rows if not _excluded(comp.get(r["computer_id"]) or {})]
    m = _WIN_SERVER.search(line)
    if m:
        year, r2 = m.group(1), bool(m.group(2))
        hit = [r for r in live if re.search(rf"server\s*(®)?\s*{year}(\s+r2)?", r["os"], re.I)
               and bool(re.search(r"\br2\b", r["os"], re.I)) == r2]
        return ("hosts", hit, "") if hit else ("none", [], f"Windows Server {year}{' R2' if r2 else ''}")
    m = _WIN_CLIENT.search(line)
    if m:
        fam, branch = m.group(1), (m.group(2) or "")
        hit = [r for r in live if re.search(rf"windows\s*{fam}\b", r["os"], re.I)
               and (not branch or r["version"].lower() == branch.lower())]
        return ("hosts", hit, "") if hit else ("none", [], f"Windows {fam} {branch}".strip())
    for name, rx in _DISTROS:
        m = rx.search(line)
        if not m:
            continue
        ver = m.group(1).lower()
        ver = _DEB_CODENAME.get(ver, ver)
        same = [r for r in live if name.replace(" ", "") in r["os"].lower().replace(" ", "")]
        if not same:
            return ("none", [], f"{name} (aucun poste)")
        hit = [r for r in same if r["version"].startswith(ver) or re.search(rf"\b{re.escape(ver)}", r["os"])]
        if hit:
            return ("hosts", hit, "")
        unk = [r for r in same if r["version"] in ("0", "") and not re.search(r"\d", r["os"])]
        if unk and name in ASSUMED_VERSION:  # règle projet : Debian du parc = Bookworm
            if ver == ASSUMED_VERSION[name]:
                return ("hosts", unk, "")
            unk = []
        if unk:
            return ("unknown", unk, f"{name} : version non renseignée dans GLPI")
        return ("none", [], f"{name} {ver}")
    return None


def analyze_lines(bulletin: dict, text: str, inv: Inventory, result):
    """Avis SANS déclaration « versions antérieures à » : on rapproche chaque
    ligne de « Systèmes affectés » avec l'inventaire."""
    lines = affected_lines(text)
    if not lines:
        return None
    hosts, notes, absent, present, unk_rows = [], [], [], [], []
    seen = set()
    for ln in lines:
        os_m = match_os(inv, ln, "voir bulletin éditeur")
        if os_m:
            state, rows, note = os_m
            if state == "hosts":
                for h in _hosts(inv, rows, "mise à jour de l'éditeur"):
                    if h["name"] not in seen:
                        seen.add(h["name"])
                        hosts.append(h)
            elif state == "unknown":
                present.append(note)
                unk_rows.extend(rows)
            else:
                absent.append(ln)
            continue
        near = near_names(inv, ln)
        if near == []:
            absent.append(ln)
        else:
            present.append(ln + (f" (≈ {near[0]})" if near else ""))
    if hosts:
        hosts.sort(key=lambda h: (h["site"], h["name"]))
        return result(
            "concerne",
            f"Croisement déterministe : {len(hosts)} poste(s) sur une version/branche visée par l'avis. "
            "Le niveau de correctif exact n'est pas disponible dans GLPI : appliquer la mise à jour de l'éditeur."
            + (f" Autres lignes à vérifier : {'; '.join(present[:4])}." if present else ""),
            hosts, count=f"{len(hosts)} postes", installed="", target="voir bulletin",
        )
    if present:
        return result(
            "a_verifier",
            "Produit(s) potentiellement présent(s) dans GLPI mais non comparables sans version : "
            + " ; ".join(present[:6]) + ".",
            _hosts(inv, unk_rows, "version de l'OS à renseigner dans GLPI")[:500],
        )
    return result("non_concerne",
                  "Aucun produit ou système visé n'existe dans l'inventaire GLPI : " + " ; ".join(absent[:6]) + ".")
