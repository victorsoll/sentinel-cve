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
import scope
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
        if hasattr(inventory, "name_index"):
            return scope.analyze_lines(bulletin, text, inventory, _result)
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
        if rule is None and hasattr(inventory, "os_rows"):
            os_m = scope.match_os(inventory, product)
            if os_m:
                state, rows, note = os_m
                if state == "hosts":
                    tgt = next((s.label for s in stmts if s.label), "mise à jour de l'éditeur")
                    targets.append(tgt)
                    for h in scope._hosts(inventory, rows, tgt):
                        concerned_hosts.append(h)
                    total_installs += len(rows)
                    unknown_notes.append(f"{product} : niveau de correctif non lisible dans GLPI (branche visée par l'avis)")
                elif state == "unknown":
                    undecidable = True
                    unknown_notes.append(note)
                else:
                    absent.append(product)
                continue
        if rule is None and hasattr(inventory, "name_index"):
            auto = scope.auto_rule(product)
            if auto and inventory.find_softwares(auto["glpi"], None, auto["seed"]):
                rule = auto  # fiche logicielle exacte trouvée : comparaison de versions
        if rule is None:
            # Pas de règle : absent du parc (aucun nom GLPI ne contient tous les
            # mots distinctifs) → non concerné ; sinon on ne devine pas.
            try:
                near = scope.near_names(inventory, product) if hasattr(inventory, "name_index") else None
                if near is None and not hasattr(inventory, "name_index"):
                    n = inventory.count_by_name(product) or inventory.count_by_name(
                        product.split()[0] if len(product) > 3 else product)
                    near = [] if n == 0 else ["?"]
            except Exception as exc:  # noqa: BLE001
                log.warning("Sonde GLPI impossible pour %s : %s", product, exc)
                return None
            if near == []:
                absent.append(product)
            else:
                undecidable = True
                unknown_notes.append(
                    f"{product} : présent dans GLPI"
                    + (f" (≈ {near[0]})" if near else "") + " sans fiche logicielle exacte à comparer")
            continue
        res = inventory.product_installs(rule["glpi"], rule.get("exclude"), rule.get("seed"))
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
