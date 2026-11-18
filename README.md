# Sentinel CVE — V2

Dashboard self-hosted : publications CERT-FR croisées avec l'inventaire GLPI
par un agent IA (API Anthropic), score de conformité, graphiques, et création
de requirements Azure DevOps à la demande.

## Ce qui change en V2

- **CERT-FR exhaustif** : lecture des pages paginées du site (`/avis/page/N/`…)
  jusqu'à la fin de la fenêtre `CERTFR_LOOKBACK_DAYS`, et non plus seulement
  les ~dernières entrées du flux RSS. RSS en complément et en secours.
  Avis + alertes analysés ; actualités, CTI, durcissement, IOC affichés pour info.
- **ADO n'est plus une source** : plus de lecture de tickets ni d'association
  IA ticket↔bulletin. ADO sert à **créer** un requirement depuis un bulletin
  (aperçu `validateOnly`, anti-doublon par tag, une ou plusieurs personnes
  issues des équipes du projet ; plusieurs personnes = une Task chacune).
- **Graphiques** : taux de concernés par cycle, répartition, publications
  par semaine, éditeurs les plus exposés, avis/alertes, consommation IA.
- **Sécurité** : le jeton d'action n'est plus écrit dans la page ; il est
  saisi une fois dans le navigateur (`ACTION_TOKEN`, ou `TRIGGER_TOKEN` V1).
- **Réglages hors du code** : `AI_MAX_TOKENS_PER_CALL`, prompt personnalisable
  via `output/system_prompt.txt`.
- **Règle de sécurité des verdicts** : si GLPI ou CERT-FR est injoignable,
  aucun bulletin n'est déclaré « non concerné » et le score n'est pas enregistré.

## Structure

```
app/
  config.py         variables d'environnement
  certfr_client.py  collecte CERT-FR (pages HTML + RSS)
  glpi_client.py    client GLPI REST (lecture seule)
  agent_pipeline.py agent IA outillé (tool use), budget, cache
  ado_client.py     création de work items Azure DevOps
  stats.py          données des graphiques
  db.py             SQLite : historique, cache IA, cycles, audit ADO
  webapi.py         API interne (cycle manuel, création ADO)
  main.py           orchestrateur + scheduler
  templates/        dashboard.html.j2, _bulletin.html.j2
tests/              pytest (aucun appel réseau)
```

## Tests

```bash
sudo docker compose run --rm --no-deps \
  -v "$PWD/tests:/app/tests" -v "$PWD/requirements-dev.txt:/app/requirements-dev.txt" \
  app sh -c "pip install -q -r requirements-dev.txt && python -m pytest -q tests"
```

## À venir

Catalyst Center (versions IOS-XE) et FortiManager / FortiAnalyzer (versions
FortiOS) dès que les accès API sont disponibles.
