"""Tests du client Azure DevOps (écriture) — V2.

Aucun appel réel : requests.request est remplacé par un faux qui enregistre
les requêtes et renvoie des réponses au format de l'API ADO 7.1."""
import json

import pytest

import ado_client
import config

BULLETIN = {
    "ref": "CERTFR-2026-AVI-1232",
    "title": "Vulnérabilité dans MariaDB",
    "kind": "avis",
    "date": "2026-10-01",
    "link": "https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1232/",
    "status": "concerne",
    "count_label": "4 postes",
    "installed_summary": "10.3.39",
    "target_version": "10.11.9",
    "type_label": "Base de données",
    "limit_note": "3 postes Windows et 1 serveur Linux.",
    "hosts": [{"name": "CN-CNSA", "site": "Cholet", "installed": "10.3.39"},
              {"name": "SRV-<script>", "site": "", "installed": ""}],
}
ALICE = {"display_name": "Alice Martin", "unique_name": "alice@corp.fr"}
BOB = {"display_name": "Bob Durand", "unique_name": "bob@corp.fr"}


class TestPure:
    def test_titre(self):
        assert ado_client.build_title(BULLETIN) == "[CERTFR-2026-AVI-1232] Vulnérabilité dans MariaDB"
        assert len(ado_client.build_title({"ref": "R", "title": "x" * 400})) == 255

    def test_priorite(self):
        assert ado_client.priority_for({"kind": "alerte", "status": "non_concerne"}) == 1
        assert ado_client.priority_for({"kind": "avis", "status": "concerne"}) == 2
        assert ado_client.priority_for({"kind": "avis", "status": "a_verifier"}) == 3

    def test_tags_avec_reference_sans_doublon_ni_point_virgule(self):
        tags = ado_client.build_tags(BULLETIN, ["sentinel-cve", "a;b", "sentinel-cve"])
        assert tags == "sentinel-cve; a b; CERTFR-2026-AVI-1232"

    def test_description_echappe_le_html(self):
        html = ado_client.build_description_html(BULLETIN, "08/10/2026 10:00")
        assert "SRV-&lt;script&gt;" in html and "<script>" not in html
        assert "CN-CNSA" in html and "10.11.9" in html and "Concerné" in html
        assert BULLETIN["link"] in html

    def test_description_tronque_les_postes(self):
        b = dict(BULLETIN, hosts=[{"name": f"PC{i}"} for i in range(80)])
        html = ado_client.build_description_html(b)
        assert "PC49" in html and "PC50" not in html and "30 autre(s)" in html

    def test_ops_requirement(self):
        ops = ado_client.build_requirement_ops(BULLETIN, ALICE, "https://x/_apis/wit/workItems/12194",
                                               "Infra\\Sécu", "Sprint 1", ["sentinel-cve"], True)
        paths = {o["path"]: o["value"] for o in ops}
        assert paths["/fields/System.AssignedTo"] == "alice@corp.fr"
        assert paths["/fields/Microsoft.VSTS.Common.Priority"] == 2
        assert paths["/fields/System.AreaPath"] == "Infra\\Sécu"
        assert paths["/relations/-"]["rel"] == "System.LinkTypes.Hierarchy-Reverse"
        assert all(o["op"] == "add" for o in ops)

    def test_ops_sans_parent_ni_zone(self):
        ops = ado_client.build_requirement_ops(BULLETIN, ALICE, None, "", "", [], False)
        paths = [o["path"] for o in ops]
        assert "/relations/-" not in paths and "/fields/System.AreaPath" not in paths
        assert "/fields/Microsoft.VSTS.Common.Priority" not in paths

    def test_plan_une_personne(self, monkeypatch):
        monkeypatch.setattr(config, "ADO_WORK_ITEM_TYPE", "Requirement")
        plan = ado_client.plan_items(BULLETIN, [ALICE])
        assert len(plan) == 1 and plan[0]["assigned_to"] == "Alice Martin"

    def test_plan_plusieurs_personnes(self, monkeypatch):
        monkeypatch.setattr(config, "ADO_TASK_TYPE", "Task")
        plan = ado_client.plan_items(BULLETIN, [ALICE, BOB])
        assert [p["role"] for p in plan] == ["requirement", "task", "task"]
        assert plan[0]["assigned_to"] == "Alice Martin"
        assert [p["assigned_to"] for p in plan[1:]] == ["Alice Martin", "Bob Durand"]

    def test_wiql_escape(self):
        assert ado_client.wiql_escape("a'b") == "a''b"


class FakeHTTP:
    """Simule l'API ADO : enregistre chaque requête, renvoie des ids croissants."""
    def __init__(self, fail_on_task_for=None):
        self.calls = []
        self.next_id = 5000
        self.fail_on_task_for = fail_on_task_for

    def __call__(self, method, url, params=None, auth=None, json=None, headers=None, timeout=None):
        self.calls.append({"method": method, "url": url, "params": params, "json": json, "headers": headers or {}})
        if "/teams/" in url and url.endswith("/members"):
            team = url.split("/teams/")[1].split("/")[0]
            members = {
                "t1": [{"identity": {"displayName": "Bob Durand", "uniqueName": "bob@corp.fr"}},
                       {"identity": {"displayName": "[Projet]\\Readers", "uniqueName": "grp", "isContainer": True}}],
                "t2": [{"identity": {"displayName": "Alice Martin", "uniqueName": "alice@corp.fr"}},
                       {"identity": {"displayName": "Bob Durand", "uniqueName": "BOB@corp.fr"}}],
            }[team]
            return _Resp(200, {"value": members})
        if url.endswith("/teams"):
            return _Resp(200, {"value": [{"id": "t1", "name": "Infra"}, {"id": "t2", "name": "Sécurité"}]})
        if url.endswith("/wit/wiql"):
            return _Resp(200, {"workItems": []})
        if "/wit/workitems/$" in url:
            if self.fail_on_task_for and json and any(
                    o["path"] == "/fields/System.AssignedTo" and o["value"] == self.fail_on_task_for for o in json) \
                    and "Task" in url:
                return _Resp(400, {"message": "TF401320: champ obligatoire manquant"})
            self.next_id += 1
            return _Resp(200, {"id": self.next_id})
        return _Resp(404, {"message": "inconnu"})


class _Resp:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body
        self.content = json.dumps(body).encode()
        self.text = json.dumps(body)

    def json(self):
        return self._body


@pytest.fixture
def fake(monkeypatch):
    f = FakeHTTP()
    monkeypatch.setattr(ado_client.requests, "request", f)
    monkeypatch.setattr(config, "ADO_PARENT_ID", 12194)
    monkeypatch.setattr(config, "ADO_WORK_ITEM_TYPE", "Requirement")
    monkeypatch.setattr(config, "ADO_TASK_TYPE", "Task")
    monkeypatch.setattr(config, "ADO_TEAMS", [])
    return f


def client():
    return ado_client.ADOClient("Beneteau-Group", "IT PROJECTS PORTFOLIO", "pat")


class TestHTTP:
    def test_url_de_creation_et_content_type(self, fake):
        client().create_from_bulletin(BULLETIN, [ALICE])
        c = [x for x in fake.calls if x["method"] == "POST" and "/workitems/" in x["url"]][0]
        assert c["url"] == "https://dev.azure.com/Beneteau-Group/IT%20PROJECTS%20PORTFOLIO/_apis/wit/workitems/$Requirement"
        assert c["headers"]["Content-Type"] == "application/json-patch+json"
        assert c["params"]["api-version"] == "7.1"
        parent = [o for o in c["json"] if o["path"] == "/relations/-"][0]
        assert parent["value"]["url"].endswith("/_apis/wit/workItems/12194")

    def test_une_personne_un_seul_work_item(self, fake):
        res = client().create_from_bulletin(BULLETIN, [ALICE])
        assert len(res["created"]) == 1 and res["errors"] == []
        assert res["created"][0]["url"].endswith("/_workitems/edit/5001")

    def test_plusieurs_personnes_requirement_plus_une_task_chacune(self, fake):
        res = client().create_from_bulletin(BULLETIN, [ALICE, BOB])
        types = [c["type"] for c in res["created"]]
        assert types == ["Requirement", "Task", "Task"]
        task_calls = [x for x in fake.calls if x["url"].endswith("$Task")]
        for t in task_calls:
            parent = [o for o in t["json"] if o["path"] == "/relations/-"][0]
            assert parent["value"]["url"].endswith("/workItems/5001")  # rattachées au requirement créé
        assert [c["assigned_to"] for c in res["created"]] == ["Alice Martin", "Alice Martin", "Bob Durand"]

    def test_echec_d_une_task_remonte_sans_annuler_le_reste(self, fake):
        fake.fail_on_task_for = "bob@corp.fr"
        res = client().create_from_bulletin(BULLETIN, [ALICE, BOB])
        assert len(res["created"]) == 2
        assert "Bob Durand" in res["errors"][0] and "TF401320" in res["errors"][0]

    def test_validate_only_ne_cree_rien(self, fake):
        res = client().create_from_bulletin(BULLETIN, [ALICE, BOB], validate_only=True)
        assert res["created"] == [] and res["validated"] is True
        posts = [x for x in fake.calls if "/workitems/" in x["url"]]
        assert len(posts) == 1 and posts[0]["params"]["validateOnly"] == "true"

    def test_personnes_dedoublonnees_sans_groupes(self, fake):
        people = client().list_people()
        assert [p["unique_name"].lower() for p in people] == ["alice@corp.fr", "bob@corp.fr"]
        bob = people[1]
        assert set(bob["teams"]) == {"Infra", "Sécurité"}

    def test_filtre_par_equipe(self, fake, monkeypatch):
        monkeypatch.setattr(config, "ADO_TEAMS", ["sécurité"])
        people = client().list_people()
        assert {p["display_name"] for p in people} == {"Alice Martin", "Bob Durand"}
        assert not any("/teams/t1/" in c["url"] for c in fake.calls)

    def test_erreur_lisible(self, monkeypatch):
        monkeypatch.setattr(ado_client.requests, "request", lambda *a, **k: _Resp(401, {}))
        with pytest.raises(ado_client.ADOError, match="PAT"):
            client().find_existing("X")
