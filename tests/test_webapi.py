"""Tests de l'API interne (Flask) : jeton d'action, prévisualisation et
création ADO. Base SQLite temporaire, faux client ADO."""
import pytest

import config
import db
import webapi
from ado_client import ADOError

TOKEN = "s3cret-token"
BULLETIN = {"ref": "CERTFR-2026-AVI-1", "title": "Vuln X", "kind": "avis", "status": "concerne",
            "status_label": "Concerné", "hosts": [], "date": "2026-10-01", "link": "l"}
PEOPLE = [{"display_name": "Alice Martin", "unique_name": "alice@corp.fr", "teams": ["Sécu"]},
          {"display_name": "Bob Durand", "unique_name": "bob@corp.fr", "teams": ["Infra"]}]


class FakeADO:
    existing = []
    validation_error = None
    created_calls = []

    def list_people(self):
        return PEOPLE

    def find_existing(self, ref):
        return list(self.existing)

    def create_from_bulletin(self, bulletin, assignees, validate_only=False):
        if validate_only:
            if self.validation_error:
                raise ADOError(self.validation_error)
            return {"created": [], "errors": [], "validated": True}
        FakeADO.created_calls.append((bulletin["ref"], [a["unique_name"] for a in assignees]))
        return {"created": [{"id": 9001, "type": "Requirement", "url": "u/9001", "assigned_to": assignees[0]["display_name"],
                             "title": "t", "parent_id": 12194}], "errors": []}


@pytest.fixture
def app(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setattr(config, "ACTION_TOKEN", TOKEN)
    monkeypatch.setattr(config, "ADO_WRITE_ENABLED", True)
    monkeypatch.setattr(config, "ADO_ORG", "o")
    monkeypatch.setattr(config, "ADO_PROJECT", "p")
    monkeypatch.setattr(config, "ADO_PAT", "x")
    monkeypatch.setattr(webapi, "ado_client_factory", FakeADO)
    monkeypatch.setattr(webapi.time, "sleep", lambda s: None)
    webapi._people_cache.update({"ts": 0.0, "data": None})
    FakeADO.existing, FakeADO.validation_error, FakeADO.created_calls = [], None, []
    db.replace_cycle_bulletins([BULLETIN])
    return webapi.create_app(lambda trigger: None).test_client()


H = {"X-Action-Token": TOKEN}


class TestJeton:
    def test_status_public(self, app):
        assert app.get("/api/status").status_code == 200

    def test_sans_jeton_refuse(self, app):
        assert app.post("/api/auth/check").status_code == 403
        assert app.get("/api/ado/people").status_code == 403
        assert app.post("/api/ado/create", json={}).status_code == 403

    def test_mauvais_jeton_refuse(self, app):
        assert app.post("/api/auth/check", headers={"X-Action-Token": "nope"}).status_code == 403

    def test_bon_jeton(self, app):
        r = app.post("/api/auth/check", headers=H)
        assert r.status_code == 200 and r.json["ado_enabled"] is True

    def test_ancien_en_tete_v1_accepte(self, app):
        assert app.post("/api/auth/check", headers={"X-Trigger-Token": TOKEN}).status_code == 200

    def test_actions_desactivees_sans_jeton_configure(self, app, monkeypatch):
        monkeypatch.setattr(config, "ACTION_TOKEN", "")
        r = app.post("/api/auth/check", headers={"X-Action-Token": ""})
        assert r.status_code == 403 and "désactivées" in r.json["error"]


class TestADO:
    def test_personnes(self, app):
        r = app.get("/api/ado/people", headers=H)
        assert r.status_code == 200 and len(r.json["people"]) == 2

    def test_ado_desactive(self, app, monkeypatch):
        monkeypatch.setattr(config, "ADO_WRITE_ENABLED", False)
        assert app.get("/api/ado/people", headers=H).status_code == 403

    def test_preview(self, app):
        r = app.post("/api/ado/preview", headers=H, json={"ref": BULLETIN["ref"], "assignees": ["alice@corp.fr", "bob@corp.fr"]})
        assert r.status_code == 200
        assert [p["role"] for p in r.json["plan"]] == ["requirement", "task", "task"]
        assert r.json["existing"] == [] and r.json["validation_error"] is None

    def test_preview_remonte_l_erreur_de_validation(self, app):
        FakeADO.validation_error = "Le champ Requirement Type est obligatoire"
        r = app.post("/api/ado/preview", headers=H, json={"ref": BULLETIN["ref"], "assignees": ["alice@corp.fr"]})
        assert r.status_code == 200 and "Requirement Type" in r.json["validation_error"]

    def test_personne_inconnue_refusee(self, app):
        r = app.post("/api/ado/create", headers=H, json={"ref": BULLETIN["ref"], "assignees": ["mallory@evil.com"]})
        assert r.status_code == 400 and "inconnue" in r.json["error"]
        assert FakeADO.created_calls == []

    def test_aucune_personne_refusee(self, app):
        r = app.post("/api/ado/create", headers=H, json={"ref": BULLETIN["ref"], "assignees": []})
        assert r.status_code == 400

    def test_bulletin_inconnu(self, app):
        r = app.post("/api/ado/create", headers=H, json={"ref": "CERTFR-1999-AVI-1", "assignees": ["alice@corp.fr"]})
        assert r.status_code == 404

    def test_creation_et_journal(self, app):
        r = app.post("/api/ado/create", headers=H, json={"ref": BULLETIN["ref"], "assignees": ["ALICE@corp.fr"]})
        assert r.status_code == 201 and r.json["created"][0]["id"] == 9001
        assert FakeADO.created_calls == [(BULLETIN["ref"], ["alice@corp.fr"])]
        log = db.get_ado_creations_by_ref()[BULLETIN["ref"]]
        assert log[0]["id"] == 9001 and log[0]["assigned_to"] == "Alice Martin"

    def test_doublon_bloque_sauf_confirmation(self, app):
        FakeADO.existing = [{"id": 42, "title": "déjà là", "state": "Active", "type": "Requirement", "assigned_to": "", "url": "u"}]
        body = {"ref": BULLETIN["ref"], "assignees": ["alice@corp.fr"]}
        r = app.post("/api/ado/create", headers=H, json=body)
        assert r.status_code == 409 and r.json["existing"][0]["id"] == 42
        assert FakeADO.created_calls == []
        r = app.post("/api/ado/create", headers=H, json=dict(body, allow_duplicate=True))
        assert r.status_code == 201

    def test_contenu_reconstruit_cote_serveur(self, app):
        # Un titre envoyé par le navigateur est ignoré : seule la base fait foi.
        app.post("/api/ado/create", headers=H, json={"ref": BULLETIN["ref"], "assignees": ["alice@corp.fr"], "title": "<img onerror>"})
        assert FakeADO.created_calls[0][0] == BULLETIN["ref"]


class TestCycle:
    def test_trigger(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config, "ACTION_TOKEN", TOKEN)
        seen = []
        app = webapi.create_app(lambda trigger: seen.append(trigger)).test_client()
        r = app.post("/api/trigger", headers=H)
        assert r.status_code == 202
        for _ in range(50):
            if seen:
                break
            webapi.time.sleep(0.01)
        assert seen == ["manuel"]
