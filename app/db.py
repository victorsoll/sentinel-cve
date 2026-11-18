"""Persistance SQLite (output/sentinel.db), partagée entre les cycles.

Tables :
- score_history          : score + décompte par statut à chaque cycle (graphiques)
- changelog              : une phrase par cycle
- bulletin_analysis_cache: cache du verdict IA par bulletin (déduplication du coût)
- cycle_runs             : métriques de chaque cycle (durée, budget IA, santé des sources)
- cycle_bulletins        : bulletins du DERNIER cycle (lus par l'API de création ADO,
                           qui ne fait jamais confiance au contenu envoyé par le navigateur)
- ado_creations          : journal d'audit des work items créés dans Azure DevOps
"""
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

import config

DB_PATH = os.path.join(config.OUTPUT_DIR, "sentinel.db")


def _connect():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    return sqlite3.connect(DB_PATH)


def _columns(conn, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def init_db():
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS score_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                score INTEGER NOT NULL
            )
        """)
        # Migration V1 -> V2 : décompte par statut, pour le graphique du taux de concernés.
        existing = _columns(conn, "score_history")
        for col in ("n_concerne", "n_a_verifier", "n_non_concerne", "n_total"):
            if col not in existing:
                conn.execute(f"ALTER TABLE score_history ADD COLUMN {col} INTEGER")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS changelog (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                entry TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS bulletin_analysis_cache (
                ref TEXT PRIMARY KEY,
                content_hash TEXT NOT NULL,
                result_json TEXT NOT NULL,
                analyzed_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cycle_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                trigger TEXT,
                duration_s REAL,
                ai_calls INTEGER,
                ai_tokens INTEGER,
                ai_cached INTEGER,
                ai_pending INTEGER,
                n_bulletins INTEGER,
                sources_json TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cycle_bulletins (
                ref TEXT PRIMARY KEY,
                kind TEXT,
                title TEXT,
                link TEXT,
                date TEXT,
                status TEXT,
                data_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ado_creations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                ref TEXT NOT NULL,
                work_item_id INTEGER NOT NULL,
                work_item_type TEXT,
                title TEXT,
                assigned_to TEXT,
                url TEXT,
                parent_id INTEGER
            )
        """)
        conn.commit()


# ------------------------------------------------------------ cache IA
def get_cached_analysis(ref: str, content_hash: str, max_age_days: int) -> dict | None:
    if not ref:
        return None
    init_db()
    with _connect() as conn:
        row = conn.execute(
            "SELECT content_hash, result_json, analyzed_at FROM bulletin_analysis_cache WHERE ref = ?",
            (ref,),
        ).fetchone()
    if row is None:
        return None
    cached_hash, result_json, analyzed_at = row
    if cached_hash != content_hash:
        return None
    try:
        analyzed_dt = datetime.fromisoformat(analyzed_at)
    except ValueError:
        return None
    if datetime.now(timezone.utc) - analyzed_dt > timedelta(days=max_age_days):
        return None
    try:
        return json.loads(result_json)
    except json.JSONDecodeError:
        return None


def save_analysis(ref: str, content_hash: str, result: dict) -> None:
    if not ref:
        return
    init_db()
    now_iso = datetime.now(timezone.utc).isoformat()
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO bulletin_analysis_cache (ref, content_hash, result_json, analyzed_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ref) DO UPDATE SET
                content_hash = excluded.content_hash,
                result_json = excluded.result_json,
                analyzed_at = excluded.analyzed_at
            """,
            (ref, content_hash, json.dumps(result), now_iso),
        )
        conn.commit()


# ------------------------------------------------------------ score
def insert_score(ts: datetime, score: int, counts: dict | None = None):
    init_db()
    counts = counts or {}
    with _connect() as conn:
        conn.execute(
            "INSERT INTO score_history (ts, score, n_concerne, n_a_verifier, n_non_concerne, n_total) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ts.isoformat(), score, counts.get("concerne"), counts.get("a_verifier"),
             counts.get("non_concerne"), counts.get("total")),
        )
        conn.execute("""
            DELETE FROM score_history WHERE id NOT IN (
                SELECT id FROM score_history ORDER BY id DESC LIMIT 120
            )
        """)
        conn.commit()


def get_history() -> list[dict]:
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT ts, score, n_concerne, n_a_verifier, n_non_concerne, n_total "
            "FROM score_history ORDER BY id ASC"
        ).fetchall()
    return [
        {"ts": ts, "score": score, "concerne": c, "a_verifier": a, "non_concerne": n, "total": t}
        for ts, score, c, a, n, t in rows
    ]


def latest_score() -> int | None:
    hist = get_history()
    return hist[-1]["score"] if hist else None


# ------------------------------------------------------------ changelog
def insert_changelog_entry(ts: datetime, entry: str):
    init_db()
    with _connect() as conn:
        conn.execute("INSERT INTO changelog (ts, entry) VALUES (?, ?)", (ts.isoformat(), entry))
        conn.execute("""
            DELETE FROM changelog WHERE id NOT IN (
                SELECT id FROM changelog ORDER BY id DESC LIMIT 30
            )
        """)
        conn.commit()


def get_changelog(limit: int = 10) -> list[dict]:
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT ts, entry FROM changelog ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [{"ts": ts, "entry": entry} for ts, entry in rows]


# ------------------------------------------------------------ cycles
def insert_cycle_run(ts: datetime, trigger: str, duration_s: float, ai: dict,
                     n_bulletins: int, sources: dict) -> None:
    init_db()
    with _connect() as conn:
        conn.execute(
            "INSERT INTO cycle_runs (ts, trigger, duration_s, ai_calls, ai_tokens, ai_cached, ai_pending, "
            "n_bulletins, sources_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (ts.isoformat(), trigger, round(duration_s, 1), ai.get("calls", 0), ai.get("tokens", 0),
             ai.get("cached", 0), ai.get("pending", 0), n_bulletins, json.dumps(sources)),
        )
        conn.execute("""
            DELETE FROM cycle_runs WHERE id NOT IN (
                SELECT id FROM cycle_runs ORDER BY id DESC LIMIT 120
            )
        """)
        conn.commit()


def get_cycle_runs(limit: int = 60) -> list[dict]:
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT ts, trigger, duration_s, ai_calls, ai_tokens, ai_cached, ai_pending, n_bulletins "
            "FROM cycle_runs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    keys = ("ts", "trigger", "duration_s", "ai_calls", "ai_tokens", "ai_cached", "ai_pending", "n_bulletins")
    return [dict(zip(keys, r)) for r in reversed(rows)]


def replace_cycle_bulletins(bulletins: list[dict]) -> None:
    """Remplace d'un bloc les bulletins du dernier cycle."""
    init_db()
    now_iso = datetime.now(timezone.utc).isoformat()
    with _connect() as conn:
        conn.execute("DELETE FROM cycle_bulletins")
        conn.executemany(
            "INSERT OR REPLACE INTO cycle_bulletins (ref, kind, title, link, date, status, data_json, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (b.get("ref"), b.get("kind"), b.get("title"), b.get("link"), b.get("date"),
                 b.get("status"), json.dumps(b, default=str), now_iso)
                for b in bulletins if b.get("ref")
            ],
        )
        conn.commit()


def get_all_cycle_bulletins() -> list[dict]:
    """Bulletins du dernier cycle réussi (pour ne pas vider le dashboard
    quand une source est injoignable)."""
    init_db()
    with _connect() as conn:
        rows = conn.execute("SELECT data_json FROM cycle_bulletins").fetchall()
    out = []
    for (j,) in rows:
        try:
            out.append(json.loads(j))
        except ValueError:
            continue
    return out


def get_cycle_bulletin(ref: str) -> dict | None:
    init_db()
    with _connect() as conn:
        row = conn.execute("SELECT data_json FROM cycle_bulletins WHERE ref = ?", (ref,)).fetchone()
    return json.loads(row[0]) if row else None


# ------------------------------------------------------------ audit ADO
def insert_ado_creation(ref: str, work_item_id: int, work_item_type: str, title: str,
                        assigned_to: str, url: str, parent_id: int | None) -> None:
    init_db()
    with _connect() as conn:
        conn.execute(
            "INSERT INTO ado_creations (ts, ref, work_item_id, work_item_type, title, assigned_to, url, parent_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), ref, work_item_id, work_item_type, title,
             assigned_to, url, parent_id),
        )
        conn.commit()


def get_ado_creations_by_ref() -> dict[str, list[dict]]:
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT ts, ref, work_item_id, work_item_type, assigned_to, url FROM ado_creations ORDER BY id ASC"
        ).fetchall()
    out: dict[str, list[dict]] = {}
    for ts, ref, wid, wtype, who, url in rows:
        out.setdefault(ref, []).append(
            {"ts": ts, "id": wid, "type": wtype, "assigned_to": who, "url": url}
        )
    return out
