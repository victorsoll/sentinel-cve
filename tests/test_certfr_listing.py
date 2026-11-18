"""Tests de la collecte exhaustive CERT-FR (pages HTML paginées) — V2.

Aucun appel réseau : les pages sont des extraits HTML construits à la main
dans deux mises en page différentes, pour vérifier que le parseur ne dépend
pas des classes CSS du site."""
from datetime import date, timedelta

import pytest
import requests

import certfr_client
import config

FR = ["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août",
      "septembre", "octobre", "novembre", "décembre"]


def fr(d: date) -> str:
    return f"{d.day:02d} {FR[d.month - 1]} {d.year}"


def page_articles(items, section="avis"):
    """Mise en page 1 : <article> avec h3 > a, ligne réf + date, résumé."""
    blocks = []
    for ref, title, d, extra in items:
        blocks.append(f"""
        <article class="item">
          <h3><a href="/{section}/{ref}/">{title}</a></h3>
          <div class="meta"><span>{ref}</span> <span>Publié le {fr(d)}</span> {extra}</div>
          <p>Résumé de {title}.</p>
        </article>""")
    return "<html><body><main>" + "".join(blocks) + "</main></body></html>"


def page_list(items, section="avis"):
    """Mise en page 2 : <ul><li> sans classes, lien absolu, date « 1er »."""
    lis = []
    for ref, title, d, extra in items:
        day = "1er" if d.day == 1 else str(d.day)
        lis.append(f"""<li><div><a href="https://www.cert.ssi.gouv.fr/{section}/{ref}/">{title}</a></div>
          <div>{ref} Publié le {day} {FR[d.month - 1]} {d.year}</div><div>Résumé {ref}</div>{extra}</li>""")
    return "<html><body><ul>" + "".join(lis) + "</ul></body></html>"


class TestParseFrDate:
    def test_date_simple(self):
        assert certfr_client.parse_fr_date("CERTFR-2026-AVI-1 Publié le 07 octobre 2026") == date(2026, 10, 7)

    def test_premier_du_mois(self):
        assert certfr_client.parse_fr_date("Publié le 1er mars 2026") == date(2026, 3, 1)

    def test_accents(self):
        assert certfr_client.parse_fr_date("Publié le 3 décembre 2025") == date(2025, 12, 3)
        assert certfr_client.parse_fr_date("Publié le 15 août 2026") == date(2026, 8, 15)

    def test_absente_ou_invalide(self):
        assert certfr_client.parse_fr_date("pas de date") is None
        assert certfr_client.parse_fr_date("Publié le 31 février 2026") is None


class TestParseListing:
    TODAY = date(2026, 10, 7)
    ITEMS = [
        ("CERTFR-2026-AVI-1279", "Multiples vulnérabilités dans SPIP", date(2026, 10, 7), ""),
        ("CERTFR-2026-AVI-1278", "Multiples vulnérabilités dans les produits Veeam", date(2026, 10, 1), ""),
    ]

    @pytest.mark.parametrize("builder", [page_articles, page_list])
    def test_extrait_ref_titre_date_lien(self, builder):
        items = certfr_client.parse_listing_html(builder(self.ITEMS), "avis")
        assert [i["ref"] for i in items] == ["CERTFR-2026-AVI-1279", "CERTFR-2026-AVI-1278"]
        assert items[0]["title"] == "Multiples vulnérabilités dans SPIP"
        assert items[0]["date"] == "2026-10-07"
        assert items[1]["date"] == "2026-10-01"
        assert items[0]["link"] == "https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1279/"
        assert items[0]["kind"] == "avis"
        assert "SPIP" in items[0]["summary"] or "CERTFR-2026-AVI-1279" in items[0]["summary"]

    def test_ignore_les_liens_d_une_autre_rubrique(self):
        html = page_articles(self.ITEMS) + '<a href="/alerte/CERTFR-2026-ALE-011/">Alerte</a>'
        refs = [i["ref"] for i in certfr_client.parse_listing_html(html, "avis")]
        assert "CERTFR-2026-ALE-011" not in refs

    def test_statut_d_alerte(self):
        html = page_articles([
            ("CERTFR-2026-ALE-011", "Vulnérabilités Citrix", date(2026, 9, 28), "<span>Alerte en cours</span>"),
            ("CERTFR-2026-ALE-005", "Vulnérabilité Ivanti", date(2026, 5, 2), "<span>Alerte close</span>"),
        ], section="alerte")
        items = certfr_client.parse_listing_html(html, "alerte")
        assert items[0]["alert_status"] == "Alerte en cours"
        assert items[1]["alert_status"] == "Alerte close"

    def test_titre_prefixe_par_la_reference_est_nettoye(self):
        assert certfr_client._clean_title("CERTFR-2026-AVI-1 : Vuln X", "CERTFR-2026-AVI-1") == "Vuln X"


class _FakeResp:
    def __init__(self, text="", status=200):
        self.text = text
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(str(self.status_code))


class _FakeSession:
    def __init__(self, pages):
        self.pages = pages  # url -> html
        self.headers = {}
        self.calls = []

    def get(self, url, timeout=None):
        self.calls.append(url)
        if url not in self.pages:
            return _FakeResp(status=404)
        return _FakeResp(self.pages[url])


@pytest.fixture(autouse=True)
def no_delay(monkeypatch):
    monkeypatch.setattr(config, "CERTFR_PAGE_DELAY_S", 0)


def _d(days_ago):
    return date.today() - timedelta(days=days_ago)


class TestFetchSection:
    BASE = "https://www.cert.ssi.gouv.fr"

    def test_pagine_jusqu_a_sortir_de_la_fenetre(self):
        pages = {
            f"{self.BASE}/avis/": page_articles([("CERTFR-2026-AVI-3", "A", _d(1), ""), ("CERTFR-2026-AVI-2", "B", _d(10), "")]),
            f"{self.BASE}/avis/page/2/": page_articles([("CERTFR-2026-AVI-1", "C", _d(60), ""), ("CERTFR-2025-AVI-9", "D", _d(120), "")]),
            f"{self.BASE}/avis/page/3/": page_articles([("CERTFR-2025-AVI-8", "E", _d(130), "")]),
            f"{self.BASE}/avis/page/4/": page_articles([("CERTFR-2025-AVI-7", "F", _d(140), "")]),
        }
        s = _FakeSession(pages)
        items, meta = certfr_client.fetch_section("avis", lookback_days=90, max_pages=50, session=s)
        assert [i["ref"] for i in items] == ["CERTFR-2026-AVI-3", "CERTFR-2026-AVI-2", "CERTFR-2026-AVI-1"]
        assert meta["stopped_because"] == "hors_fenetre"
        assert f"{self.BASE}/avis/page/4/" not in s.calls  # arrêt dès la page 3, entièrement hors fenêtre

    def test_s_arrete_sur_404(self):
        s = _FakeSession({f"{self.BASE}/avis/": page_articles([("CERTFR-2026-AVI-3", "A", _d(1), "")])})
        items, meta = certfr_client.fetch_section("avis", lookback_days=90, max_pages=50, session=s)
        assert len(items) == 1 and meta["stopped_because"] == "fin_des_pages"

    def test_respecte_max_pages(self):
        pages = {f"{self.BASE}/avis/" + (f"page/{n}/" if n > 1 else ""): page_articles([(f"CERTFR-2026-AVI-{n}", "x", _d(1), "")]) for n in range(1, 10)}
        items, meta = certfr_client.fetch_section("avis", lookback_days=90, max_pages=3, session=_FakeSession(pages))
        assert len(items) == 3 and meta["stopped_because"] == "max_pages"

    def test_alerte_ancienne_mais_en_cours_est_gardee(self):
        pages = {f"{self.BASE}/alerte/": page_articles([
            ("CERTFR-2026-ALE-011", "Récente", _d(5), "<span>Alerte close</span>"),
            ("CERTFR-2025-ALE-002", "Ancienne en cours", _d(300), "<span>Alerte en cours</span>"),
            ("CERTFR-2025-ALE-001", "Ancienne close", _d(310), "<span>Alerte close</span>"),
        ], section="alerte")}
        items, _ = certfr_client.fetch_section("alerte", lookback_days=90, max_pages=5, session=_FakeSession(pages))
        refs = [i["ref"] for i in items]
        assert "CERTFR-2025-ALE-002" in refs and "CERTFR-2025-ALE-001" not in refs

    def test_structure_inconnue_leve_une_erreur(self):
        html = '<a href="/avis/CERTFR-2026-AVI-1/">x</a><a href="/avis/CERTFR-2026-AVI-2/">y</a>'
        with pytest.raises(certfr_client.ListingStructureError):
            certfr_client.fetch_section("avis", 90, 5, session=_FakeSession({f"{self.BASE}/avis/": html}))


class TestCollectSection:
    def test_repli_rss_si_les_pages_echouent(self, monkeypatch):
        def boom(*a, **k):
            raise requests.ConnectionError("site injoignable")
        monkeypatch.setattr(certfr_client, "fetch_section", boom)
        monkeypatch.setattr(certfr_client, "fetch_feed", lambda url, d=None: [{
            "ref": "CERTFR-2026-AVI-5", "title": "CERTFR-2026-AVI-5 : Vuln RSS", "link": "l",
            "summary": "<p>résumé</p>", "date": "2026-10-01"}])
        items, health = certfr_client.collect_section("avis", 90)
        assert [i["title"] for i in items] == ["Vuln RSS"]
        assert items[0]["summary"] == "résumé"
        assert health["state"] == "degraded" and "injoignable" in health["error"]

    def test_down_si_rien_du_tout(self, monkeypatch):
        def boom(*a, **k):
            raise requests.ConnectionError("x")
        monkeypatch.setattr(certfr_client, "fetch_section", boom)
        monkeypatch.setattr(certfr_client, "fetch_feed", lambda url, d=None: [])
        items, health = certfr_client.collect_section("avis", 90)
        assert items == [] and health["state"] == "down" and health["ok"] is False

    def test_fusion_html_et_rss_sans_doublon(self, monkeypatch):
        html_items = [{"ref": "CERTFR-2026-AVI-2", "title": "B", "link": "l2", "date": "2026-10-02",
                       "summary": "court", "kind": "avis", "alert_status": ""}]
        monkeypatch.setattr(certfr_client, "fetch_section", lambda s, d=None: (html_items, {"pages": 1, "stopped_because": "hors_fenetre"}))
        monkeypatch.setattr(certfr_client, "fetch_feed", lambda url, d=None: [
            {"ref": "CERTFR-2026-AVI-2", "title": "CERTFR-2026-AVI-2 : B", "link": "l2", "summary": "résumé RSS bien plus long", "date": "2026-10-02"},
            {"ref": "CERTFR-2026-AVI-3", "title": "CERTFR-2026-AVI-3 : C", "link": "l3", "summary": "", "date": "2026-10-03"},
        ])
        items, health = certfr_client.collect_section("avis", 90)
        assert [i["ref"] for i in items] == ["CERTFR-2026-AVI-3", "CERTFR-2026-AVI-2"]  # tri date décroissante
        assert items[1]["summary"] == "résumé RSS bien plus long"
        assert health["state"] == "ok" and "+ 1 via RSS" in health["mode"]
