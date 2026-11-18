"""Tests des données de graphiques, de la migration SQLite V1 -> V2, du
prompt personnalisable et du rendu complet du dashboard."""
import os
import sqlite3
from datetime import date, datetime
from zoneinfo import ZoneInfo

import pytest

import agent_pipeline
import config
import db
import main
import stats


def B(ref, status, kind="avis", d="2026-10-05", title="Vulnérabilité dans GLPI"):
    return {"ref": ref, "status": status, "status_label": main.STATUS_LABELS[status], "kind": kind,
            "date": d, "title": title, "link": "https://x", "hosts": []}


class TestStats:
    @pytest.mark.parametrize("title,expected", [
        ("Multiples vulnérabilités dans les produits Veeam", "Veeam"),
        ("Vulnérabilité dans Metabase", "Metabase"),
        ("Multiples vulnérabilités dans le noyau Linux de Debian", "Linux (noyau)"),
        ("Multiples vulnérabilités dans Microsoft Windows", "Microsoft"),
        ("Vulnérabilité dans l'interface de gestion", "Interface"),
        ("Titre sans motif", "Titre"),
        ("", "Autre"),
    ])
    def test_product_of(self, title, expected):
        assert stats.product_of(title) == expected

    def test_taux(self):
        assert stats.concerned_rate({"concerne": 1, "a_verifier": 1, "non_concerne": 2, "total": 4}) == 25.0
        assert stats.concerned_rate({"concerne": 0, "total": 0}) == 0.0

    def test_top_products_classe_par_concernes(self):
        bs = [B("1", "concerne", title="Vuln dans Veeam"), B("2", "a_verifier", title="Vuln dans GLPI"),
              B("3", "a_verifier", title="Vuln dans GLPI"), B("4", "non_concerne", title="Vuln dans Zimbra")]
        rows = stats.top_products(bs)
        assert [r["label"] for r in rows] == ["Veeam", "GLPI"]
        assert rows[1]["total"] == 2

    def test_weekly(self):
        bs = [B("1", "concerne", d="2026-10-05"), B("2", "ok" if False else "non_concerne", d="2026-10-07"),
              B("3", "concerne", d="2026-09-30"), B("4", "concerne", d="2020-01-01"), B("5", "concerne", d="")]
        w = stats.weekly(bs, weeks=3, today=date(2026, 10, 8))
        assert [x["start"] for x in w] == ["2026-09-21", "2026-09-28", "2026-10-05"]
        assert w[-1]["concerne"] == 1 and w[-1]["non_concerne"] == 1 and w[1]["concerne"] == 1

    def test_rate_history_ignore_les_cycles_v1(self):
        h = [{"ts": "a", "score": 50, "total": None}, {"ts": "b", "score": 60, "concerne": 2, "a_verifier": 0, "non_concerne": 8, "total": 10}]
        assert stats.rate_history(h) == [{"ts": "b", "rate": 20.0, "concerne": 2, "a_verifier": 0, "non_concerne": 8, "total": 10}]


class TestMigration:
    def test_base_v1_migree_sans_perte(self, tmp_path, monkeypatch):
        path = tmp_path / "v1.db"
        with sqlite3.connect(path) as c:
            c.execute("CREATE TABLE score_history (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, score INTEGER NOT NULL)")
            c.execute("INSERT INTO score_history (ts, score) VALUES ('2026-10-01T03:44:00', 55)")
        monkeypatch.setattr(db, "DB_PATH", str(path))
        db.init_db()
        db.insert_score(datetime(2026, 10, 2), 61, {"concerne": 3, "a_verifier": 2, "non_concerne": 5, "total": 10})
        h = db.get_history()
        assert h[0]["score"] == 55 and h[0]["total"] is None
        assert h[1]["concerne"] == 3 and h[1]["total"] == 10
        db.init_db()  # idempotent


class TestPrompt:
    def test_prompt_par_defaut(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "AI_SYSTEM_PROMPT_FILE", str(tmp_path / "absent.txt"))
        p = agent_pipeline.get_system_prompt()
        assert p == agent_pipeline.DEFAULT_SYSTEM_PROMPT
        assert "PLUSIEURS fiches Software" in p  # correctif MariaDB conservé en V2
        assert "Azure DevOps" not in p

    def test_prompt_personnalise(self, tmp_path, monkeypatch):
        f = tmp_path / "p.txt"
        f.write_text("Mon prompt maison", encoding="utf-8")
        monkeypatch.setattr(config, "AI_SYSTEM_PROMPT_FILE", str(f))
        assert agent_pipeline.get_system_prompt() == "Mon prompt maison"

    def test_fichier_vide_ignore(self, tmp_path, monkeypatch):
        f = tmp_path / "p.txt"
        f.write_text("  \n", encoding="utf-8")
        monkeypatch.setattr(config, "AI_SYSTEM_PROMPT_FILE", str(f))
        assert agent_pipeline.get_system_prompt() == agent_pipeline.DEFAULT_SYSTEM_PROMPT

    def test_plus_d_outil_ado(self):
        names = [t["name"] for t in agent_pipeline.TOOLS]
        assert "ado_get_comments" not in names and not hasattr(agent_pipeline, "match_ado_ticket")

    def test_ia_desactivee(self, monkeypatch):
        monkeypatch.setattr(config, "AI_ENABLED", False)
        r = agent_pipeline.analyze_bulletin(None, {"ref": "X"})
        assert r["status"] == "a_verifier" and r["pending_ai"] is False


class TestCycle:
    def test_tri_alertes_d_abord_puis_recents(self):
        bs = [B("a1", "concerne", d="2026-10-01"), B("al", "concerne", kind="alerte", d="2026-01-01"), B("a2", "concerne", d="2026-10-05")]
        assert [b["ref"] for b in main.sort_bulletins(bs)] == ["al", "a2", "a1"]

    def test_glpi_injoignable_rien_en_non_concerne(self, monkeypatch):
        class Boom:
            def __enter__(self):
                raise ConnectionError("GLPI down")

            def __exit__(self, *a):
                return False
        monkeypatch.setattr(main, "GLPIClient", Boom)
        bs, counts, health = main.analyze_all([{"ref": "1", "title": "t"}, {"ref": "2", "title": "u"}])
        assert health["state"] == "down"
        assert counts == {"concerne": 0, "a_verifier": 2, "non_concerne": 0, "total": 2}

    def test_cycle_complet_et_rendu(self, tmp_path, monkeypatch):
        """Cycle de bout en bout avec CERT-FR et GLPI simulés : vérifie la page produite."""
        monkeypatch.setattr(config, "OUTPUT_DIR", str(tmp_path))
        monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "s.db"))
        monkeypatch.setattr(config, "AI_ENABLED", False)
        monkeypatch.setattr(config, "ACTION_TOKEN", "Zq9-jeton-unique")
        monkeypatch.setattr(config, "ADO_WRITE_ENABLED", True)
        monkeypatch.setattr(main.certfr_client, "collect_all", lambda: {
            "bulletins": [
                {"ref": "CERTFR-2026-AVI-1", "title": "Vuln dans </script><b>GLPI", "kind": "avis", "date": "2026-10-05", "link": "l", "summary": "s", "alert_status": ""},
                {"ref": "CERTFR-2026-ALE-1", "title": "Vuln dans Citrix", "kind": "alerte", "date": "2026-10-04", "link": "l", "summary": "", "alert_status": "Alerte en cours"},
            ],
            "info": [{"ref": "CERTFR-2026-ACT-40", "title": "Bulletin d'actualité", "kind": "actualite", "date": "2026-10-06", "link": "l"}],
            "health": {"avis": {"state": "ok", "count": 1, "pages": 1, "mode": "pages HTML", "error": ""},
                       "alerte": {"state": "ok", "count": 1, "pages": 1, "mode": "pages HTML", "error": ""}},
        })

        class FakeGLPI:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        monkeypatch.setattr(main, "GLPIClient", FakeGLPI)
        db.insert_ado_creation("CERTFR-2026-AVI-1", 777, "Requirement", "t", "Alice", "https://ado/777", None)

        main.run_cycle("test")

        html = (tmp_path / "index.html").read_text(encoding="utf-8")
        assert "2026-ACT-40" in html  # publications d'information affichées
        assert "ADO #777" in html and "Créer un Requirement ADO" in html
        assert "</script><b>GLPI" not in html  # titre échappé partout (HTML et JSON)
        assert 'data-token' not in html and "Zq9-jeton-unique" not in html  # le jeton n'est jamais dans la page
        assert "Alerte en cours" in html and "Bulletin d&#39;actualité" in html
        assert db.get_cycle_bulletin("CERTFR-2026-ALE-1")["kind"] == "alerte"
        runs = db.get_cycle_runs()
        assert runs[-1]["trigger"] == "test" and runs[-1]["n_bulletins"] == 2
        assert db.get_history()[-1]["total"] == 2
        assert not os.path.exists(tmp_path / "index.html.tmp")
