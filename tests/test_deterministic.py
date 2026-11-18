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
