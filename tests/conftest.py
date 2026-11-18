"""Rend le dossier app/ importable (tests lancés depuis la racine, ou dans le
conteneur avec ./tests monté)."""
import os
import sys

for cand in (os.path.join(os.path.dirname(__file__), "..", "app"), "/app/app", "/app"):
    if os.path.isfile(os.path.join(cand, "config.py")):
        sys.path.insert(0, os.path.abspath(cand))
        break
