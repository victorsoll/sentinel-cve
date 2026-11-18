"""Client GLPI REST — LECTURE SEULE (seules les requêtes GET sont émises,
plus l'ouverture/fermeture de session qui ne modifie aucune donnée GLPI).

GLPI_BASE_URL doit se terminer par /apirest.php (ou /api.php/v1 selon la version)."""
import logging

import requests

import config

log = logging.getLogger(__name__)
PAGE = 1000


class GLPIError(Exception):
    pass


class GLPIClient:
    def __init__(self):
        self.base_url = config.GLPI_BASE_URL
        self.session_token = ""

    # ------------------------------------------------------------ session
    def __enter__(self):
        if not (self.base_url and config.GLPI_APP_TOKEN and config.GLPI_USER_TOKEN):
            raise GLPIError("GLPI_BASE_URL / GLPI_APP_TOKEN / GLPI_USER_TOKEN non renseignés dans .env")
        try:
            r = requests.get(f"{self.base_url}/initSession", timeout=30, headers={
                "App-Token": config.GLPI_APP_TOKEN,
                "Authorization": f"user_token {config.GLPI_USER_TOKEN}",
            })
            r.raise_for_status()
            self.session_token = r.json()["session_token"]
        except (requests.RequestException, KeyError, ValueError) as exc:
            raise GLPIError(f"Ouverture de session GLPI impossible : {exc}") from exc
        return self

    def __exit__(self, *exc):
        try:
            requests.get(f"{self.base_url}/killSession", headers=self._headers(), timeout=15)
        except requests.RequestException:
            pass
        return False

    def _headers(self) -> dict:
        return {"App-Token": config.GLPI_APP_TOKEN, "Session-Token": self.session_token,
                "Content-Type": "application/json"}

    # ------------------------------------------------------------- recherche
    @staticmethod
    def _criteria_params(criteria, forcedisplay=None) -> dict:
        p = {}
        for i, c in enumerate(criteria or []):
            p[f"criteria[{i}][field]"] = c["field"]
            p[f"criteria[{i}][searchtype]"] = c.get("searchtype", "contains")
            p[f"criteria[{i}][value]"] = c.get("value", "")
            if i and c.get("link"):
                p[f"criteria[{i}][link]"] = c["link"]
        for j, f in enumerate(forcedisplay or []):
            p[f"forcedisplay[{j}]"] = f
        p["expand_dropdowns"] = "true"
        return p

    def _search(self, itemtype, params, start, end):
        p = dict(params)
        p["range"] = f"{start}-{end}"
        try:
            r = requests.get(f"{self.base_url}/search/{itemtype}", headers=self._headers(), params=p, timeout=90)
            r.raise_for_status()
            return r.json()
        except (requests.RequestException, ValueError) as exc:
            raise GLPIError(f"Recherche GLPI {itemtype} échouée : {exc}") from exc

    def search_all(self, itemtype, criteria, forcedisplay=None, limit=50_000) -> list[dict]:
        params = self._criteria_params(criteria, forcedisplay)
        out, start = [], 0
        while start < limit:
            res = self._search(itemtype, params, start, start + PAGE - 1)
            rows = res.get("data", []) if isinstance(res, dict) else []
            out.extend(rows)
            total = int(res.get("totalcount", 0)) if isinstance(res, dict) else 0
            start += PAGE
            if not rows or start >= total:
                break
        return out

    def count(self, itemtype, criteria) -> int:
        res = self._search(itemtype, self._criteria_params(criteria, [2]), 0, 0)
        return int(res.get("totalcount", 0)) if isinstance(res, dict) else 0

    # ------------------------------------------------------------- raccourcis
    def software_install_count(self, software_id: int, version_contains: str | None = None) -> int:
        if not version_contains:
            rows = self.search_all("Software", [{"field": 2, "searchtype": "equals", "value": software_id}],
                                   [2, config.GLPI_FIELD_SOFTWARE_INSTALL_COUNT])
            return int(rows[0].get(str(config.GLPI_FIELD_SOFTWARE_INSTALL_COUNT)) or 0) if rows else 0
        from glpi_inventory import Inventory
        inv = Inventory(self)
        needle = version_contains.lower()
        return sum(len(inv.installs_of_version(int(v["id"])))
                   for v in inv.versions_of(int(software_id)) if needle in str(v.get("name", "")).lower())

    def hosts_with_kernel(self, kernel_contains: str) -> list[dict]:
        rows = self.search_all(
            "Computer", [{"field": config.GLPI_FIELD_KERNEL_VERSION, "searchtype": "contains", "value": kernel_contains}],
            [1, config.GLPI_FIELD_LOCATION, config.GLPI_FIELD_KERNEL_VERSION])
        return [{"name": r.get("1"), "site": r.get(str(config.GLPI_FIELD_LOCATION)),
                 "kernel": r.get(str(config.GLPI_FIELD_KERNEL_VERSION))} for r in rows]

    def network_equipment_by_manufacturer(self, manufacturer_contains: str) -> list[dict]:
        rows = self.search_all(
            "NetworkEquipment", [{"field": 23, "searchtype": "contains", "value": manufacturer_contains}],
            [1, config.GLPI_FIELD_LOCATION, 23])
        return [{"name": r.get("1"), "site": r.get(str(config.GLPI_FIELD_LOCATION)),
                 "manufacturer": r.get("23")} for r in rows]
