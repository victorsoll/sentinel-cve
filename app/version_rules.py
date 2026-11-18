"""Règles de version DÉTERMINISTES (aucune IA, aucun réseau).

Deux briques pures, entièrement testées :
- parse_statements(texte) : lit la section « Systèmes affectés » d'un bulletin
  CERT-FR ("Zabbix versions 7.0.x antérieures à 7.0.29") et en sort des
  déclarations structurées ;
- is_affected(version, déclarations) : compare une version installée à ces
  déclarations. Renvoie True / False / None (None = on ne sait pas : jamais
  traduit en « non concerné »).
"""
import re
from dataclasses import dataclass

_TOKEN = re.compile(r"\d+|[A-Za-z]+")


def tokenize(version: str) -> list:
    """'1.1.1zj' -> [1, 1, 1, 'zj'] ; '9.5.4+build2026' -> [9, 5, 4, 'build', 2026]."""
    out = []
    for t in _TOKEN.findall(version or ""):
        out.append(int(t) if t.isdigit() else t.lower())
    return out


def compare(a: str, b: str) -> int:
    """-1 / 0 / 1. Un suffixe lettre (1.0.2zs) est plus récent que la base (1.0.2).
    Un nombre est plus petit qu'une lettre à la même position."""
    ta, tb = tokenize(a), tokenize(b)
    for x, y in zip(ta, tb):
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        if isinstance(x, str) and isinstance(y, str):
            return -1 if x < y else 1
        return -1 if isinstance(x, int) else 1
    if len(ta) == len(tb):
        return 0
    return -1 if len(ta) < len(tb) else 1


@dataclass(frozen=True)
class Statement:
    product: str          # "Zabbix", "Elastic Agent", "Agent2"...
    fixed: str            # première version NON affectée ("7.0.29")
    branch_from: str = ""  # "7.0" (préfixe de branche) ou ""
    branch_to: str = ""    # fin de plage de branches ("2.5") ou ""
    label: str = ""        # texte lisible de la version cible

    def covers(self, version: str) -> bool:
        """La version appartient-elle à la branche visée par la déclaration ?"""
        if not self.branch_from:
            return True
        v = tokenize(version)
        lo = tokenize(self.branch_from)
        if not self.branch_to:
            return v[: len(lo)] == lo
        hi = tokenize(self.branch_to)
        return v[: len(lo)] >= lo and v[: len(hi)] <= hi


# "<produit> versions [<branche>[ à <branche>]] antérieures à <fixed>[ (build X)]"
_STMT = re.compile(
    r"^(?P<product>.+?)\s+versions?\s+"
    r"(?:(?P<b1>\d+(?:\.\d+)*(?:\.x)?)(?:\s+à\s+(?P<b2>\d+(?:\.\d+)*(?:\.x)?))?\s+)?"
    r"(?:antérieures?|inférieures?)\s+à\s+(?P<fixed>.+?)\s*\.?$",
    re.IGNORECASE,
)
_BUILD = re.compile(r"\(\s*build\s+(?P<b>[\w.\-]+)\s*\)", re.IGNORECASE)


def _branch(b: str) -> str:
    return re.sub(r"\.x$", "", b or "", flags=re.IGNORECASE)


def parse_statements(text: str) -> list[Statement]:
    out: list[Statement] = []
    for raw in (text or "").splitlines():
        line = raw.strip().lstrip("-•*· ").strip()
        m = _STMT.match(line)
        if not m:
            continue
        fixed_raw = m.group("fixed").strip()
        bm = _BUILD.search(fixed_raw)
        fixed = bm.group("b") if bm else fixed_raw
        if not bm and re.search(r"\s", fixed):
            fixed = ""  # ex. '12.3.2 P4' sans build : comparaison impossible
        out.append(Statement(
            product=m.group("product").strip(),
            fixed=fixed,
            branch_from=_branch(m.group("b1")),
            branch_to=_branch(m.group("b2")),
            label=fixed_raw,
        ))
    return out


def normalize_installed(version: str, strip_after: str = "", keep_parts: int = 0) -> str:
    """Prépare la version GLPI à la comparaison.
    strip_after : coupe au premier de ces caractères ('+-~' pour 9.5.4+build…).
    keep_parts  : ne garde que N composantes numériques (7.0.11.2400 -> 7.0.11)."""
    v = (version or "").strip()
    if ":" in v and v.split(":", 1)[0].isdigit():  # epoch Debian
        v = v.split(":", 1)[1]
    for ch in strip_after:
        v = v.split(ch, 1)[0]
    if keep_parts:
        parts = re.findall(r"\d+", v)
        if parts:
            v = ".".join(parts[:keep_parts])
    return v.strip()


def is_affected(installed: str, statements: list[Statement]) -> bool | None:
    """True = affecté, False = corrigé / hors branche visée, None = indéterminé."""
    if not installed or not tokenize(installed):
        return None
    if not statements:
        return None
    covered = [s for s in statements if s.covers(installed)]
    if not covered:
        # Aucune déclaration ne vise cette branche : non affecté seulement si
        # une déclaration SANS branche n'existe pas (sinon elle l'aurait couverte).
        return False
    if any(not s.fixed for s in covered):
        return None
    return any(compare(installed, s.fixed) < 0 for s in covered)
