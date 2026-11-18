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
import threading
import time

import requests

import config

log = logging.getLogger(__name__)

PAGE = 1000
# Connexions persistantes : une résolution DNS / un handshake TLS par appel
# saturait le résolveur du serveur (échecs « Temporary failure in name resolution »).
_HTTP = requests.Session()
_HTTP.mount("https://", requests.adapters.HTTPAdapter(pool_connections=4, pool_maxsize=16))
_TTL = 3600  # secondes : l'index des postes est réutilisé entre bulletins d'un même cycle


class InventoryError(Exception):
    pass


class Inventory:
    # Cache partagé entre instances : une Inventory est recréée par bulletin,
    # l'index des postes ne doit être chargé qu'une fois par TTL.
    _computers: dict[int, dict] | None = None
    _computers_at = 0.0
    _products: dict = {}
    _lock = threading.RLock()
    _key_locks: dict = {}

    def __init__(self, glpi):
        self.base = glpi.base_url
        self._headers = glpi._headers

    # ------------------------------------------------------------ HTTP (GET)
    def _get(self, path: str, params: dict | None = None):
        r = None
        for attempt in range(4):  # GLPI par intermittence : lent, timeouts, 5xx
            try:
                r = _HTTP.get(f"{self.base}/{path.lstrip('/')}", headers=self._headers(),
                                 params=params or {}, timeout=120)
                if r.status_code < 500:
                    break
                err = f"HTTP {r.status_code}"
            except (requests.Timeout, requests.ConnectionError) as exc:
                err = type(exc).__name__
                if attempt == 3:
                    raise
            log.warning("GLPI %s (%s), nouvel essai %d/3", path, err, attempt + 1)
            time.sleep(5 * (attempt + 1))
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
    def find_softwares(self, include: str, exclude: list[str] | None = None, seed: str | None = None) -> list[dict]:
        """Fiches Software dont le nom correspond à la regex `include`.
        Retourne [{id, name, expected_installs}]."""
        inc = re.compile(include, re.IGNORECASE)
        exc = [re.compile(e, re.IGNORECASE) for e in (exclude or [])]
        # Pré-filtre côté serveur sur le premier mot « sûr » de la regex.
        if not seed:
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
        try:
            res = self._get("search/Software", {
                "criteria[0][field]": 1, "criteria[0][searchtype]": "contains",
                "criteria[0][value]": keyword, "forcedisplay[0]": 2, "range": "0-0",
            })
        except requests.HTTPError as exc:  # 404 = aucune ligne pour cette recherche
            if exc.response is not None and exc.response.status_code == 404:
                return 0
            raise
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
        with Inventory._lock:
            return self._computers_locked()

    def _computers_locked(self) -> dict[int, dict]:
        if Inventory._computers is not None and time.time() - Inventory._computers_at < _TTL:
            return Inventory._computers
        rows = self._paged("Computer", {"expand_dropdowns": "true"})
        idx = {}
        for r in rows:
            try:
                idx[int(r["id"])] = r
            except (KeyError, ValueError, TypeError):
                continue
        Inventory._computers, Inventory._computers_at = idx, time.time()
        log.info("Index GLPI : %d postes chargés.", len(idx))
        return idx

    # ------------------------------------------------------- produit complet
    def product_installs(self, include: str, exclude: list[str] | None = None, seed: str | None = None) -> dict:
        """Avec cache (TTL) : Edge/Chrome/Firefox reviennent dans des dizaines
        d'avis et pèsent des milliers d'installations."""
        key = (include, tuple(exclude or ()), seed)
        with Inventory._lock:
            klock = Inventory._key_locks.setdefault(key, threading.Lock())
        with klock:
            hit = Inventory._products.get(key)
            if hit and time.time() - hit[0] < _TTL:
                return hit[1]
            res = self._product_installs(include, exclude, seed)
            Inventory._products[key] = (time.time(), res)
            return res

    def _product_installs(self, include: str, exclude: list[str] | None = None, seed: str | None = None) -> dict:
        """Toutes les installations d'un produit, avec réconciliation.

        Retour : {softwares:[…], rows:[{host,site,entity,type,state,version,software,
        software_id,itemtype,items_id}], expected:int, resolved:int, reconciled:bool}"""
        softwares = self.find_softwares(include, exclude, seed)
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


# ------------------------------------------------- index de présence (GLPI)
def _tokens(text: str) -> set[str]:
    return {t for t in re.findall(r"[a-z0-9]+", (text or "").lower()) if len(t) >= 3}


def _name_index(inv: "Inventory") -> list[tuple[str, frozenset]]:
    """[(nom, mots)] de tous les référentiels GLPI : logiciels, systèmes,
    fabricants, modèles. Sert à décider qu'un produit est ABSENT du parc."""
    with Inventory._lock:
        c = Inventory._tok_cache
        if c and time.time() - c[0] < _TTL:
            return c[1]
        names: list[tuple[str, frozenset]] = []
        for ep in ("Software", "OperatingSystem", "NetworkEquipmentModel",
                   "ComputerModel", "PeripheralModel", "PhoneModel"):
            try:
                for r in inv._paged(ep):
                    n = str(r.get("name", ""))
                    names.append((n, frozenset(_tokens(n))))
            except Exception as exc:  # noqa: BLE001 — un référentiel illisible => on ne conclut pas
                log.warning("Index de présence : %s illisible (%s)", ep, exc)
                raise InventoryError(f"référentiel {ep} illisible") from exc
        Inventory._tok_cache = (time.time(), names)
        log.info("Index de présence GLPI : %d noms.", len(names))
        return names


def _os_rows(inv: "Inventory") -> list[dict]:
    """Système d'exploitation de chaque poste : [{computer_id, os, version}]."""
    with Inventory._lock:
        c = Inventory._os_cache
        if c and time.time() - c[0] < _TTL:
            return c[1]
        out = []
        for r in inv._paged("Item_OperatingSystem", {"expand_dropdowns": "true"}):
            if r.get("itemtype") != "Computer" or int(r.get("is_deleted", 0) or 0):
                continue
            cid = next((int(l["href"].rstrip("/").rsplit("/", 1)[1]) for l in r.get("links", [])
                        if l.get("rel") == "Computer"), None)
            if cid is None:
                continue
            out.append({"computer_id": cid, "os": str(r.get("operatingsystems_id") or ""),
                        "version": str(r.get("operatingsystemversions_id") or "0")})
        Inventory._os_cache = (time.time(), out)
        return out


Inventory._tok_cache = None
Inventory._os_cache = None
Inventory.name_index = _name_index
Inventory.os_rows = _os_rows
