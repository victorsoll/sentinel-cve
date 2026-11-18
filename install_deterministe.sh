#!/usr/bin/env bash
# =====================================================================
# Sentinel CVE — moteur DÉTERMINISTE (croisement 100 % fiable, sans IA)
# À lancer depuis ~/sentinel-cve (V2 déjà installée) :  bash install_deterministe.sh
#  1. sauvegarde app/ et tests/ dans backup-deterministe-<date>/
#  2. écrit 3 modules + 1 fichier de tests
#  3. patche config.py et agent_pipeline.py (ancres vérifiées, sinon arrêt)
# Ne touche NI au .env, NI à output/.  GLPI : uniquement des requêtes GET.
# =====================================================================
set -euo pipefail
cd "$(dirname "$0")"
[ -f docker-compose.yml ] && [ -d app ] && [ -f app/agent_pipeline.py ] || { echo "Lancer depuis ~/sentinel-cve (V2 installée)"; exit 1; }
BK="backup-deterministe-$(date +%Y%m%d-%H%M%S)"; mkdir -p "$BK"; cp -a app tests "$BK"/; echo "Sauvegarde : $BK/"
mkdir -p tests
cat > app/version_rules.py << 'SENTINEL_DET_EOF'
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
SENTINEL_DET_EOF
echo '  écrit : app/version_rules.py'
cat > app/glpi_inventory.py << 'SENTINEL_DET_EOF'
"""Inventaire GLPI exhaustif et déterministe — LECTURE SEULE (uniquement des GET).

Problème résolu : l'API de recherche GLPI ne sait pas dire « quel poste a quelle
version de quel logiciel ». Ici on suit la chaîne exacte de la base :

    Software ──> SoftwareVersion ──> Item_SoftwareVersion ──> Computer

et on RÉCONCILIE le résultat avec le compteur d'installations que GLPI donne
lui-même pour chaque logiciel (champ de recherche 72). Si les deux chiffres
diffèrent, la liste est marquée « non réconciliée » et le verdict ne peut pas
être « non concerné ».

Aucune écriture : seules des requêtes GET sont émises.
"""
import logging
import re
import time

import requests

import config

log = logging.getLogger(__name__)

PAGE = 1000
_TTL = 600  # secondes : l'index des postes est réutilisé entre bulletins d'un même cycle


class InventoryError(Exception):
    pass


class Inventory:
    def __init__(self, glpi):
        self.base = glpi.base_url
        self._headers = glpi._headers
        self._computers: dict[int, dict] | None = None
        self._computers_at = 0.0

    # ------------------------------------------------------------ HTTP (GET)
    def _get(self, path: str, params: dict | None = None):
        r = requests.get(f"{self.base}/{path.lstrip('/')}", headers=self._headers(),
                         params=params or {}, timeout=60)
        if r.status_code == 206:  # contenu partiel : normal avec « range »
            return r.json()
        r.raise_for_status()
        return r.json() if r.text else []

    def _paged(self, path: str, params: dict | None = None, limit: int = 200_000):
        out, start = [], 0
        while start < limit:
            p = dict(params or {})
            p["range"] = f"{start}-{start + PAGE - 1}"
            try:
                chunk = self._get(path, p)
            except requests.HTTPError as exc:
                if exc.response is not None and exc.response.status_code in (400, 404) and start:
                    break  # fin de pagination
                raise
            if not isinstance(chunk, list) or not chunk:
                break
            out.extend(chunk)
            if len(chunk) < PAGE:
                break
            start += PAGE
        return out

    # ------------------------------------------------------------- logiciels
    def find_softwares(self, include: str, exclude: list[str] | None = None) -> list[dict]:
        """Fiches Software dont le nom correspond à la regex `include`.
        Retourne [{id, name, expected_installs}]."""
        inc = re.compile(include, re.IGNORECASE)
        exc = [re.compile(e, re.IGNORECASE) for e in (exclude or [])]
        # Pré-filtre côté serveur sur le premier mot « sûr » de la regex.
        seed = re.sub(r"^[\^\(\?:]+", "", include).split("|")[0]
        seed = re.split(r"[^A-Za-z0-9 ._-]", seed)[0].strip() or include
        found = []
        start = 0
        while True:
            params = {
                "criteria[0][field]": 1, "criteria[0][searchtype]": "contains",
                "criteria[0][value]": seed,
                "forcedisplay[0]": 1, "forcedisplay[1]": 2,
                "forcedisplay[2]": config.GLPI_FIELD_SOFTWARE_INSTALL_COUNT,
                "range": f"{start}-{start + PAGE - 1}",
            }
            res = self._get("search/Software", params)
            rows = res.get("data", []) if isinstance(res, dict) else []
            for row in rows:
                name = str(row.get("1", ""))
                if inc.search(name) and not any(e.search(name) for e in exc):
                    found.append({
                        "id": int(row["2"]), "name": name,
                        "expected_installs": int(row.get(str(config.GLPI_FIELD_SOFTWARE_INSTALL_COUNT)) or 0),
                    })
            total = int(res.get("totalcount", 0)) if isinstance(res, dict) else 0
            start += PAGE
            if start >= total or not rows:
                break
        return found

    def count_by_name(self, keyword: str) -> int:
        res = self._get("search/Software", {
            "criteria[0][field]": 1, "criteria[0][searchtype]": "contains",
            "criteria[0][value]": keyword, "forcedisplay[0]": 2, "range": "0-0",
        })
        return int(res.get("totalcount", 0)) if isinstance(res, dict) else 0

    def versions_of(self, software_id: int) -> list[dict]:
        return self._paged(f"Software/{software_id}/SoftwareVersion")

    def installs_of_version(self, version_id: int) -> list[dict]:
        """Lignes Item_SoftwareVersion d'une version (match exact garanti)."""
        try:
            rows = self._paged(f"SoftwareVersion/{version_id}/Item_SoftwareVersion")
        except requests.HTTPError:
            rows = self._paged("Item_SoftwareVersion",
                               {"searchText[softwareversions_id]": version_id})
        return [r for r in rows if int(r.get("softwareversions_id", 0)) == int(version_id)
                and not int(r.get("is_deleted", 0) or 0)]

    # ---------------------------------------------------------------- postes
    def computers(self) -> dict[int, dict]:
        if self._computers is not None and time.time() - self._computers_at < _TTL:
            return self._computers
        rows = self._paged("Computer", {"expand_dropdowns": "true"})
        idx = {}
        for r in rows:
            try:
                idx[int(r["id"])] = r
            except (KeyError, ValueError, TypeError):
                continue
        self._computers, self._computers_at = idx, time.time()
        log.info("Index GLPI : %d postes chargés.", len(idx))
        return idx

    # ------------------------------------------------------- produit complet
    def product_installs(self, include: str, exclude: list[str] | None = None) -> dict:
        """Toutes les installations d'un produit, avec réconciliation.

        Retour : {softwares:[…], rows:[{host,site,entity,type,state,version,software,
        software_id,itemtype,items_id}], expected:int, resolved:int, reconciled:bool}"""
        softwares = self.find_softwares(include, exclude)
        rows, expected, resolved = [], 0, 0
        comp = self.computers() if softwares else {}
        for sw in softwares:
            expected += sw["expected_installs"]
            for v in self.versions_of(sw["id"]):
                for inst in self.installs_of_version(int(v["id"])):
                    resolved += 1
                    itemtype = inst.get("itemtype", "Computer")
                    items_id = int(inst.get("items_id", 0))
                    c = comp.get(items_id) if itemtype == "Computer" else None
                    rows.append({
                        "host": (c or {}).get("name") or f"{itemtype} #{items_id}",
                        "site": (c or {}).get("locations_id") or "",
                        "entity": (c or {}).get("entities_id") or "",
                        "type": (c or {}).get("computertypes_id") or itemtype,
                        "state": (c or {}).get("states_id") or "",
                        "known": c is not None,
                        "version": v.get("name", ""),
                        "software": sw["name"], "software_id": sw["id"],
                        "itemtype": itemtype, "items_id": items_id,
                    })
        return {
            "softwares": softwares, "rows": rows,
            "expected": expected, "resolved": resolved,
            "reconciled": expected == resolved,
        }


def selftest(keyword_regex: str) -> None:
    """python -m glpi_inventory 'Veeam Backup & Replication'  → affiche la réconciliation."""
    from glpi_client import GLPIClient
    with GLPIClient() as glpi:
        res = Inventory(glpi).product_installs(keyword_regex)
    print(f"Fiches Software : {len(res['softwares'])}")
    for s in res["softwares"]:
        print(f"  #{s['id']:<7} {s['name']}  (GLPI annonce {s['expected_installs']} installations)")
    print(f"Installations attendues (GLPI) : {res['expected']}")
    print(f"Installations résolues (chaîne complète) : {res['resolved']}")
    print("RÉCONCILIÉ ✅" if res["reconciled"] else "NON RÉCONCILIÉ ⚠️  (verdict « non concerné » interdit)")
    for r in res["rows"][:15]:
        print(f"  {r['host']:<24} {r['site']:<14} {r['version']}")


if __name__ == "__main__":
    import sys
    selftest(sys.argv[1] if len(sys.argv) > 1 else "Veeam Backup & Replication$")
SENTINEL_DET_EOF
echo '  écrit : app/glpi_inventory.py'
cat > app/deterministic.py << 'SENTINEL_DET_EOF'
"""Moteur d'analyse DÉTERMINISTE d'un bulletin CERT-FR (ADR-001 : filtre
déterministe d'abord, IA seulement pour ce qui n'est pas tranchable).

Principe, sans aucune IA :
 1. Lire dans l'avis les déclarations « <produit> versions … antérieures à X ».
 2. Associer chaque produit à une règle (product_rules.json) → expression de
    nom GLPI à inclure/exclure.
 3. Lister TOUTES les installations via la chaîne GLPI complète et les
    comparer à X.
 4. Verdict :
      concerne      ≥ 1 installation en version affectée (liste complète des postes)
      non_concerne  produit absent de GLPI, OU toutes les installations
                    réconciliées sont en version corrigée
      None          indécidable → laissé à l'agent IA (ou « à vérifier »)
 Règle d'or : en cas de doute, on renvoie None / a_verifier. Jamais l'inverse.
"""
import json
import logging
import os
import re

import config
import version_rules as vr

log = logging.getLogger(__name__)

# Règles livrées par défaut. Surchargées / complétées par product_rules.json
# (config.PRODUCT_RULES_FILE) : une règle de même "id" remplace la règle livrée.
DEFAULT_RULES = [
    {"id": "veeam-br", "cert": r"veeam", "type": "Application (sauvegarde)",
     "glpi": r"^Veeam Backup (&|and) Replication$", "exclude": [],
     "strip_after": "", "keep_parts": 0},
    {"id": "zabbix-agent2", "cert": r"zabbix.*agent ?2|agent ?2", "type": "Agent de supervision",
     "glpi": r"^Zabbix Agent 2", "exclude": [], "strip_after": "", "keep_parts": 3},
    {"id": "zabbix-agent", "cert": r"zabbix.*agent(?! ?2)", "type": "Agent de supervision",
     "glpi": r"^Zabbix Agent(?! 2)", "exclude": [], "strip_after": "", "keep_parts": 3},
    {"id": "elastic-agent", "cert": r"elastic agent", "type": "Agent (Elastic)",
     "glpi": r"^Elastic Agent", "exclude": [], "strip_after": "+-", "keep_parts": 0},
    {"id": "elasticsearch", "cert": r"elasticsearch", "type": "Application (Elasticsearch)",
     "glpi": r"^elasticsearch$", "exclude": [], "strip_after": "+-", "keep_parts": 0},
    {"id": "wireshark", "cert": r"wireshark", "type": "Application",
     "glpi": r"^Wireshark", "exclude": [], "strip_after": "", "keep_parts": 3},
    {"id": "firefox", "cert": r"firefox", "type": "Navigateur",
     "glpi": r"^Mozilla Firefox", "exclude": [r"maintenance"], "strip_after": "", "keep_parts": 0},
    {"id": "thunderbird", "cert": r"thunderbird", "type": "Messagerie",
     "glpi": r"^Mozilla Thunderbird", "exclude": [], "strip_after": "", "keep_parts": 0},
    {"id": "chrome", "cert": r"chrome", "type": "Navigateur",
     "glpi": r"^(Google )?Chrome$", "exclude": [], "strip_after": "", "keep_parts": 0},
    {"id": "edge", "cert": r"edge", "type": "Navigateur",
     "glpi": r"^Microsoft Edge$", "exclude": [], "strip_after": "", "keep_parts": 0},
]

# Distributions : versions rétroportées (9.2p1-2+deb12u7 « corrige » du code
# 10.x sans changer de numéro). Comparer les numéros serait FAUX → à vérifier.
DISTRO_VERSION = re.compile(r"(deb\d+u\d+|ubuntu|\+deb|~deb|el\d|\.fc\d)", re.IGNORECASE)


def load_rules() -> list[dict]:
    rules = {r["id"]: dict(r) for r in DEFAULT_RULES}
    path = getattr(config, "PRODUCT_RULES_FILE", "")
    try:
        if path and os.path.isfile(path):
            with open(path, encoding="utf-8") as f:
                for r in json.load(f):
                    rules[r["id"]] = r
    except (OSError, ValueError, KeyError) as exc:
        log.warning("product_rules.json illisible (%s) : règles livrées seules.", exc)
    return list(rules.values())


def _rule_for(title: str, product: str, rules: list[dict]) -> dict | None:
    hay = f"{title} {product}".lower()
    for r in rules:
        if re.search(r["cert"], hay, re.IGNORECASE):
            return r
    return None


def _group(statements):
    groups: dict[str, list] = {}
    for s in statements:
        groups.setdefault(s.product, []).append(s)
    return groups


def _result(status, note, hosts=None, count="", installed="", target="", type_label=""):
    return {
        "status": status, "hosts": hosts or [], "count_label": count,
        "installed_summary": installed, "target_version": target,
        "type_label": type_label, "limit_note": note, "pending_ai": False,
        "engine": "deterministe",
    }


def analyze(bulletin: dict, text: str, inventory, rules: list[dict] | None = None) -> dict | None:
    """Renvoie un verdict complet, ou None si le bulletin n'est pas tranchable
    sans IA (déclarations introuvables, produit sans règle présent dans GLPI...)."""
    rules = rules if rules is not None else load_rules()
    statements = vr.parse_statements(text)
    if not statements:
        return None
    title = bulletin.get("title", "")
    max_hosts = getattr(config, "DETERMINISTIC_MAX_HOSTS", 5000)

    concerned_hosts, unknown_notes, absent, fixed_notes = [], [], [], []
    installed_versions, targets, types = set(), [], []
    total_installs = 0
    undecidable = False
    out_of_park = 0

    for product, stmts in _group(statements).items():
        rule = _rule_for(title, product, rules)
        if rule is None:
            # Pas de règle : produit absent de GLPI (0 fiche) → non concerné ;
            # présent → on ne devine pas, l'IA ou l'humain tranche.
            keyword = product.split()[0] if len(product) > 3 else product
            try:
                n = inventory.count_by_name(product) or inventory.count_by_name(keyword)
            except Exception as exc:  # noqa: BLE001
                log.warning("Sonde GLPI impossible pour %s : %s", product, exc)
                return None
            if n == 0:
                absent.append(product)
                continue
            return None
        res = inventory.product_installs(rule["glpi"], rule.get("exclude"))
        types.append(rule.get("type", ""))
        if not res["softwares"]:
            absent.append(product)
            continue
        total_installs += res["resolved"]
        if not res["reconciled"]:
            undecidable = True
            unknown_notes.append(
                f"{product} : liste non réconciliée avec GLPI ({res['resolved']} installations "
                f"retrouvées pour {res['expected']} annoncées)"
            )
        excluded_state = re.compile(getattr(config, "GLPI_EXCLUDED_STATES_REGEX", "Out of Park"), re.IGNORECASE)
        for row in res["rows"]:
            if row["state"] and excluded_state.search(str(row["state"])):
                out_of_park += 1
                continue
            ver = row["version"]
            if DISTRO_VERSION.search(ver):
                undecidable = True
                unknown_notes.append(f"{row['software']} {ver} : version de distribution (correctifs rétroportés)")
                continue
            norm = vr.normalize_installed(ver, rule.get("strip_after", ""), rule.get("keep_parts", 0))
            verdict = vr.is_affected(norm, stmts)
            installed_versions.add(f"{row['software']} {ver}")
            if verdict is True:
                tgt = next((s.label for s in stmts if s.covers(norm) and vr.compare(norm, s.fixed or "0") < 0), "")
                targets.append(tgt)
                concerned_hosts.append({
                    "name": row["host"], "site": row["site"] or "non renseigné",
                    "installed": ver, "target": tgt or "voir bulletin",
                })
            elif verdict is None:
                undecidable = True
                unknown_notes.append(f"{row['host']} : version « {ver} » non comparable")
            else:
                fixed_notes.append(row["host"])

    if concerned_hosts:
        concerned_hosts.sort(key=lambda h: (h["site"], h["name"]))
        shown = concerned_hosts[:max_hosts]
        uniq_targets = sorted({t for t in targets if t})
        note = (f"Croisement déterministe (GLPI REST, chaîne logiciel→version→poste, comparée aux "
                f"déclarations « antérieures à » du bulletin) : {len(concerned_hosts)} installation(s) "
                f"en version affectée sur {total_installs} résolue(s).")
        if unknown_notes:
            note += " Points à vérifier : " + " ; ".join(sorted(set(unknown_notes))[:5]) + "."
        return _result(
            "concerne", note, shown,
            count=f"{len({h['name'] for h in concerned_hosts})} postes / {total_installs} installs",
            installed=", ".join(sorted(installed_versions))[:300],
            target=" / ".join(uniq_targets) or "voir bulletin",
            type_label=next((t for t in types if t), ""),
        )

    if undecidable:
        return _result(
            "a_verifier",
            "Aucune installation affectée trouvée avec certitude, mais : "
            + " ; ".join(sorted(set(unknown_notes))[:6]) + ".",
            count=f"{total_installs} installs", type_label=next((t for t in types if t), ""),
        )

    if out_of_park and not fixed_notes and not absent:
        return _result(
            "non_concerne",
            f"Seules {out_of_park} installation(s) existent, sur des équipements hors parc "
            f"(état GLPI « {config.GLPI_EXCLUDED_STATES_REGEX} »).",
        )
    if absent and not fixed_notes:
        return _result(
            "non_concerne",
            "Produit(s) absent(s) de l'inventaire GLPI : " + ", ".join(absent) + ".",
            type_label="",
        )
    if fixed_notes:
        return _result(
            "non_concerne",
            f"Toutes les installations GLPI réconciliées ({total_installs}) sont déjà en version "
            f"corrigée ou hors des branches visées par le bulletin.",
            count=f"0 / {total_installs} installs", installed=", ".join(sorted(installed_versions))[:300],
            type_label=next((t for t in types if t), ""),
        )
    return None
SENTINEL_DET_EOF
echo '  écrit : app/deterministic.py'
cat > tests/test_deterministic.py << 'SENTINEL_DET_EOF'
"""Tests du moteur déterministe — cas RÉELS du 08/10/2026 (avis CERT-FR + GLPI)."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
import pytest
import version_rules as vr
import deterministic as det


class FakeInv:
    def __init__(self, products=None, names=None):
        self.products = products or {}   # regex glpi -> résultat product_installs
        self.names = names or {}
    def product_installs(self, include, exclude=None):
        return self.products.get(include, {"softwares": [], "rows": [], "expected": 0, "resolved": 0, "reconciled": True})
    def count_by_name(self, kw):
        return self.names.get(kw, 0)


def rows(sw, items, state=""):
    r = [{"host": h, "site": s, "entity": "", "type": "Server", "state": state, "known": True,
          "version": v, "software": sw, "software_id": 1, "itemtype": "Computer", "items_id": i}
         for i, (h, s, v) in enumerate(items)]
    return {"softwares": [{"id": 1, "name": sw, "expected_installs": len(r)}], "rows": r,
            "expected": len(r), "resolved": len(r), "reconciled": True}


# ---------------------------------------------------------------- parsing
def test_parse_zabbix_branches():
    t = "Zabbix versions 6.0.x antérieures à 6.0.48\nZabbix versions 7.0.x antérieures à 7.0.29"
    s = vr.parse_statements(t)
    assert [(x.branch_from, x.fixed) for x in s] == [("6.0", "6.0.48"), ("7.0", "7.0.29")]

def test_parse_veeam_build():
    s = vr.parse_statements("Veeam Backup & Replication versions antérieures à 12.3.2 P4 (build 12.3.2.4934)")
    assert s[0].fixed == "12.3.2.4934"

def test_parse_sans_build_est_indetermine():
    s = vr.parse_statements("Produit X versions antérieures à 12.3.2 P4")
    assert s[0].fixed == "" and vr.is_affected("12.3.2.1", s) is None

def test_parse_plage_de_branches():
    s = vr.parse_statements("MongoDB versions 2.2.x à 2.5.x antérieures à 2.5.3")[0]
    assert s.covers("2.4.1") and not s.covers("2.1.9") and not s.covers("2.6.0")

def test_ligne_sans_motif_ignoree():
    assert vr.parse_statements("Multiples vulnérabilités dans X\nCVE-2026-1") == []

# ---------------------------------------------------------------- comparaison
@pytest.mark.parametrize("a,b,exp", [
    ("7.0.11", "7.0.31", -1), ("7.0.31", "7.0.31", 0), ("7.0.100", "7.0.31", 1),
    ("1.0.2zr", "1.0.2zs", -1), ("1.0.2", "1.0.2zs", -1), ("3.6.1", "3.6.5", -1),
    ("12.3.2.3617", "12.3.2.4934", -1), ("12.3.2.4934", "12.3.2.4934", 0),
])
def test_compare(a, b, exp):
    assert vr.compare(a, b) == exp

def test_normalize():
    assert vr.normalize_installed("7.0.11.2400", keep_parts=3) == "7.0.11"
    assert vr.normalize_installed("9.5.4+build202609161310", "+-") == "9.5.4"
    assert vr.normalize_installed("1:10.11.14-0+deb12u2", "") .startswith("10.11.14")

# ---------------------------------------------------------------- Elastic (branches)
ELASTIC = ("Elastic Agent versions 9.5.x antérieures à 9.5.5\nElastic Agent versions 9.x antérieures à 9.4.8\n"
           "Elastic Agent versions antérieures à 8.19.22")

def test_elastic_branches():
    s = vr.parse_statements(ELASTIC)
    assert vr.is_affected("9.5.4", s) is True
    assert vr.is_affected("9.5.5", s) is False
    assert vr.is_affected("9.4.4", s) is True
    assert vr.is_affected("9.0.7", s) is True
    assert vr.is_affected("9.4.8", s) is False

# ---------------------------------------------------------------- moteur
B = {"title": "Multiples vulnérabilités dans les produits Elastic", "link": "x", "ref": "AVI-1276"}

def test_concerne_liste_tous_les_postes():
    inv = FakeInv({r"^Elastic Agent": rows("Elastic Agent", [("PC-1", "GIV", "9.5.4+build2026"), ("PC-2", "NTE", "9.5.5"),
                                                              ("PC-3", "", "9.4.4")])})
    r = det.analyze(B, ELASTIC, inv)
    assert r["status"] == "concerne"
    assert [h["name"] for h in r["hosts"]] == ["PC-1", "PC-3"] or {h["name"] for h in r["hosts"]} == {"PC-1", "PC-3"}
    assert next(h for h in r["hosts"] if h["name"] == "PC-3")["site"] == "non renseigné"
    assert r["engine"] == "deterministe"

def test_tout_corrige_est_non_concerne():
    inv = FakeInv({r"^Elastic Agent": rows("Elastic Agent", [("PC-2", "NTE", "9.5.5")])})
    assert det.analyze(B, ELASTIC, inv)["status"] == "non_concerne"

def test_non_reconcilie_jamais_non_concerne():
    res = rows("Elastic Agent", [("PC-2", "NTE", "9.5.5")]); res["expected"] = 3; res["reconciled"] = False
    r = det.analyze(B, ELASTIC, FakeInv({r"^Elastic Agent": res}))
    assert r["status"] == "a_verifier"

def test_version_distribution_a_verifier():
    t = "OpenSSH versions antérieures à 10.6"
    rule = [{"id": "ossh", "cert": "openssh", "glpi": "^openssh-server$", "exclude": [], "strip_after": "", "keep_parts": 0}]
    inv = FakeInv({"^openssh-server$": rows("openssh-server", [("SRV-1", "GIV", "1:9.2p1-2+deb12u7")])})
    r = det.analyze({"title": "OpenSSH", "ref": "x"}, t, inv, rule)
    assert r["status"] == "a_verifier" and "rétroportés" in r["limit_note"]

def test_veeam_build_comparaison():
    t = "Veeam Backup & Replication versions antérieures à 12.3.2 P4 (build 12.3.2.4934)"
    inv = FakeInv({r"^Veeam Backup (&|and) Replication$": rows("Veeam Backup & Replication", [("VBR-1", "GIV", "12.3.2.4854"), ("VBR-2", "NTE", "12.3.2.4934")])})
    r = det.analyze({"title": "Multiples vulnérabilités dans les produits Veeam", "ref": "x"}, t, inv)
    assert r["status"] == "concerne" and [h["name"] for h in r["hosts"]] == ["VBR-1"]

def test_zabbix_agent2_build_msi():
    t = "Agent2 versions antérieures à 7.0.31"
    inv = FakeInv({r"^Zabbix Agent 2": rows("Zabbix Agent 2 (64-bit)", [("A", "GIV", "7.0.11.2400"), ("B", "GIV", "7.0.31.2400")])})
    r = det.analyze({"title": "Multiples vulnérabilités dans Zabbix Agent", "ref": "x"}, t, inv)
    assert r["status"] == "concerne" and [h["name"] for h in r["hosts"]] == ["A"]

def test_wireshark_deja_corrige():
    t = "Wireshark versions 4.4.x antérieures à 4.4.19\nWireshark versions 4.6.x antérieures à 4.6.9"
    inv = FakeInv({r"^Wireshark": rows("Wireshark", [("W1", "GIV", "4.6.9 x64")])})
    assert det.analyze({"title": "Wireshark", "ref": "x"}, t, inv)["status"] == "non_concerne"

def test_produit_absent_de_glpi_non_concerne():
    t = "Traefik versions 3.x antérieures à 3.5.3"
    r = det.analyze({"title": "Multiples vulnérabilités dans Traefik", "ref": "x"}, t, FakeInv())
    assert r["status"] == "non_concerne" and "absent" in r["limit_note"]

def test_produit_sans_regle_mais_present_laisse_a_l_ia():
    t = "Redmine versions antérieures à 6.0.1"
    assert det.analyze({"title": "Redmine", "ref": "x"}, t, FakeInv(names={"Redmine": 2})) is None

def test_poste_hors_parc_exclu():
    inv = FakeInv({r"^Elastic Agent": rows("Elastic Agent", [("OLD", "GIV", "9.4.4")], state="Out of Park > Scrapped")})
    assert det.analyze(B, ELASTIC, inv)["status"] == "non_concerne"

def test_sans_declaration_laisse_a_l_ia():
    assert det.analyze(B, "Une vulnérabilité a été découverte.", FakeInv()) is None
SENTINEL_DET_EOF
echo '  écrit : tests/test_deterministic.py'
cat > patch_app.py << 'SENTINEL_DET_EOF'
import re, sys
def patch(path, old, new, marker):
    s = open(path, encoding="utf-8").read()
    if marker in s:
        print(f"  déjà patché : {path}"); return
    if old not in s:
        sys.exit(f"ERREUR : ancre introuvable dans {path} — fichier différent de la V2 attendue")
    open(path, "w", encoding="utf-8").write(s.replace(old, new, 1))
    print(f"  patché : {path}")

patch("app/config.py",
 "# ---------- CERT-FR ----------",
 '''# ---------- Moteur déterministe ----------
DETERMINISTIC_ENABLED = _bool("DETERMINISTIC_ENABLED", True)
PRODUCT_RULES_FILE = os.getenv("PRODUCT_RULES_FILE", "/app/output/product_rules.json")
GLPI_EXCLUDED_STATES_REGEX = os.getenv("GLPI_EXCLUDED_STATES_REGEX", "Out of Park")
DETERMINISTIC_MAX_HOSTS = int(os.getenv("DETERMINISTIC_MAX_HOSTS", "5000"))

# ---------- CERT-FR ----------''',
 "DETERMINISTIC_ENABLED")

patch("app/agent_pipeline.py",
 "    client = _client()\n    if client is None:\n        return _fallback(\"Analyse IA désactivée",
 '''    det = _try_deterministic(glpi, bulletin)
    if det is not None and det["status"] in ("concerne", "non_concerne"):
        return det

    client = _client()
    if client is None:
        if det is not None:  # verdict déterministe « à vérifier » et motivé
            return det
        return _fallback("Analyse IA désactivée''',
 "_try_deterministic(glpi, bulletin)")

patch("app/agent_pipeline.py",
 "def analyze_bulletin(glpi: GLPIClient, bulletin: dict) -> dict:",
 '''def _try_deterministic(glpi: GLPIClient, bulletin: dict) -> dict | None:
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
        return None


def analyze_bulletin(glpi: GLPIClient, bulletin: dict) -> dict:''',
 "def _try_deterministic")
SENTINEL_DET_EOF
echo '  écrit : patch_app.py'
python3 patch_app.py
rm -f patch_app.py
python3 -m py_compile app/*.py && echo "Syntaxe Python OK"
cat >> .env.example << 'ENVEOF'

# --- Moteur déterministe ---
DETERMINISTIC_ENABLED=true
PRODUCT_RULES_FILE=/app/output/product_rules.json
GLPI_EXCLUDED_STATES_REGEX=Out of Park
DETERMINISTIC_MAX_HOSTS=5000
ENVEOF
echo
echo "Étapes suivantes :"
echo "  1) docker compose build app && docker compose up -d"
echo "  2) VALIDER la chaîne GLPI (réconciliation) :"
echo "     docker compose exec app sh -c 'cd \$(dirname \$(find / -name glpi_inventory.py -not -path \"/proc/*\" 2>/dev/null | head -1)) && python glpi_inventory.py \"^Veeam Backup (&|and) Replication\$\"'"
echo "     => doit afficher RÉCONCILIÉ ✅ (installations résolues = installations GLPI)"
