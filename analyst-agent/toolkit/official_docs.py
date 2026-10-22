from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import subprocess
from pathlib import Path

DOCS = {
    "kql": ("MicrosoftDocs/dataexplorer-docs", "main", ("data-explorer/kusto",)),
    "azure-monitor": ("MicrosoftDocs/azure-monitor-docs", "main", ("articles/azure-monitor",)),
    "sentinel": ("Azure/Azure-Sentinel", "master", ("Detections", "Hunting Queries", "Parsers", "ASIM")),
    "windows-server": (
        "MicrosoftDocs/windowsserverdocs", "main",
        ("WindowsServerDocs/identity", "WindowsServerDocs/security",
         "WindowsServerDocs/administration/windows-commands", "includes")),
    "sysinternals": (
        "MicrosoftDocs/sysinternals", "main",
        ("sysinternals/downloads", "sysinternals/resources")),
}

OPTIONAL_COLLECTIONS = {"sysinternals"}
OPTIONAL_SUBTREES = {"includes", "WindowsServerDocs/security",
                     "WindowsServerDocs/administration/windows-commands",
                     "sysinternals/resources"}
INDEX_NAME = "official_docs.sqlite3"


def default_folder() -> Path:
    return Path(os.environ.get("TOOLKIT_DOCS_DIR") or os.environ.get("SOC_DOCS_DIR")
                or str(Path(__file__).resolve().parent.parent / "knowledge")).resolve()


def _open_index(folder: Path) -> sqlite3.Connection:
    target = folder / INDEX_NAME
    if not target.is_file():
        raise FileNotFoundError(
            f"Documentation index not found: {target}. Sync mirrors and run "
            "python -c 'from toolkit.official_docs import build_index; print(build_index())'.")
    connection = sqlite3.connect(target.as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def availability(folder: Path | None = None) -> dict[str, int]:
    try:
        with _open_index(folder or default_folder()) as db:
            rows = db.execute(
                "SELECT collection, count(*) AS count FROM docs GROUP BY collection"
            ).fetchall()
        return {row["collection"]: row["count"] for row in rows}
    except (sqlite3.DatabaseError, FileNotFoundError, OSError):
        return {}


def _title(body: str, fallback: str) -> str:
    for line in body.splitlines()[:100]:
        if line.startswith("# "):
            return line[2:].strip()[:240] or fallback
    match = re.search(r'(?m)^title:\s*[\'\"]?([^\r\n]+)', body[:10000])
    return match.group(1).strip().strip("'\"")[:240] if match else fallback


def build_index(folder: Path | None = None) -> dict[str, int]:
    folder = (folder or default_folder()).resolve()
    folder.mkdir(parents=True, exist_ok=True)
    sources = folder / "sources"
    temp = folder / "official_docs.building.sqlite3"
    dst = folder / INDEX_NAME
    temp.unlink(missing_ok=True)
    db = sqlite3.connect(temp)
    try:
        db.execute("""CREATE TABLE docs (
            id TEXT PRIMARY KEY, collection TEXT NOT NULL, title TEXT NOT NULL,
            body TEXT NOT NULL, sha256 TEXT NOT NULL, source_url TEXT NOT NULL)""")
        db.execute("""CREATE VIRTUAL TABLE docs_fts USING fts5(
            id UNINDEXED, title, body, path, tokenize='unicode61')""")
        counts: dict[str, int] = {}
        for key, (repo, branch, subtrees) in DOCS.items():
            root = sources / key
            if not (root / ".git").exists():
                if key in OPTIONAL_COLLECTIONS:
                    counts[key] = 0
                    continue
                raise FileNotFoundError(f"Missing Git mirror for {key}: {root}")
            completed = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                capture_output=True, text=True, timeout=25, check=False)
            if completed.returncode != 0:
                raise RuntimeError(f"Git mirror is invalid: {root}: {completed.stderr[:250]}")
            revision = completed.stdout.strip() or branch
            count = 0
            for subtree in subtrees:
                base = root / subtree
                if not base.is_dir():
                    if subtree in OPTIONAL_SUBTREES:
                        continue
                    raise FileNotFoundError(f"Missing documentation subtree: {key}/{subtree}")
                for path in base.rglob("*"):
                    if not path.is_file() or path.suffix.lower() not in {".md", ".yml", ".yaml"}:
                        continue
                    content = path.read_bytes()
                    try:
                        body = content.decode("utf-8-sig")
                    except UnicodeError as exc:
                        raise ValueError(f"Non-UTF8 source document: {path}") from exc
                    relative = path.relative_to(root).as_posix()
                    doc_id = f"{key}:{relative}"
                    title = _title(body, path.stem)
                    url = f"https://github.com/{repo}/blob/{revision}/{relative}"
                    digest = hashlib.sha256(content).hexdigest()
                    db.execute("INSERT INTO docs VALUES (?,?,?,?,?,?)",
                               (doc_id, key, title, body, digest, url))
                    db.execute("INSERT INTO docs_fts (id,title,body,path) VALUES (?,?,?,?)",
                               (doc_id, title, body, relative))
                    count += 1
                    if count % 400 == 0:
                        db.commit()
            if count < 1:
                raise ValueError(f"No source documents indexed from {key}; check mirror paths")
            counts[key] = count
            db.commit()
        db.execute("CREATE INDEX docs_collection_idx ON docs(collection)")
        db.execute("INSERT INTO docs_fts(docs_fts) VALUES('optimize')")
        db.commit()
    except BaseException:
        db.close()
        temp.unlink(missing_ok=True)
        raise
    db.close()
    temp.replace(dst)
    return counts


def _terms(query: str) -> list[str]:
    tokens = re.findall(r"[^\W_]+", query, flags=re.UNICODE)
    return list(dict.fromkeys(t.casefold() for t in tokens if len(t) >= 2 or t.isdecimal()))[:12]


def _has_fts_path(db: sqlite3.Connection) -> bool:
    return any(row[1] == "path" for row in db.execute("PRAGMA table_info(docs_fts)"))


def search_docs(query: str, *, collection: str = "all", limit: int = 8,
                folder: Path | None = None) -> dict:
    if not isinstance(query, str) or not 0 < len(query.strip()) <= 240:
        raise ValueError("query must be 1..240 characters")
    if collection not in ("all", *DOCS):
        raise ValueError("Unknown Microsoft documentation collection")
    if type(limit) is not int or not 1 <= limit <= 15:
        raise ValueError("limit must be 1..15")
    terms = _terms(query)
    if not terms:
        raise ValueError("Query contains no searchable words")
    words = ['"' + t.replace('"', '') + '"' for t in terms]
    strategies = [("all_terms", " AND ".join(words))]
    if len(words) > 1:
        strategies.append(("any_term", " OR ".join(words)))

    results: list[dict] = []
    strategy = "no_matches"
    with _open_index(folder or default_folder()) as db:
        indexed = {row[0] for row in db.execute("SELECT DISTINCT collection FROM docs")}
        if collection != "all" and collection not in indexed:
            return {"results": [], "verbatim": True,
                    "match_strategy": "collection_not_indexed",
                    "note": f"The '{collection}' source mirror has not been indexed. Sync it and rebuild the documentation index."}
        has_path = _has_fts_path(db)
        rank = "bm25(docs_fts, 0.0, 9.0, 1.0, 5.0)" if has_path else "bm25(docs_fts, 0.0, 9.0, 1.0)"
        sql = """SELECT d.id, d.collection, d.title, d.source_url, d.sha256,
                 snippet(docs_fts, 2, '', '', '…', 32) AS excerpt
                 FROM docs_fts JOIN docs d ON docs_fts.id=d.id
                 WHERE docs_fts MATCH ?"""
        if collection != "all":
            sql += " AND d.collection = ?"
        sql += f" ORDER BY {rank} LIMIT ?"
        for label, expression in strategies:
            params = [expression]
            if collection != "all":
                params.append(collection)
            params.append(limit)
            results = [dict(row) for row in db.execute(sql, params)]
            if results:
                strategy = label
                break
    return {"results": results, "verbatim": True, "match_strategy": strategy,
            "note": "These are excerpts of indexed official source files. "
                    "Use read_official_doc with a returned ID for fuller text. "
                    "Documentation describes products, not your workspace's actual schema; "
                    "check get_table_schema and query telemetry independently."}


def read_doc(doc_id: str, *, offset: int = 0, max_chars: int = 6500,
             focus: str | None = None, folder: Path | None = None) -> dict:
    if (not isinstance(doc_id, str) or len(doc_id) > 1200 or
            ":" not in doc_id or doc_id.split(":", 1)[0] not in DOCS or "\x00" in doc_id):
        raise ValueError("Invalid documentation identifier")
    if type(offset) is not int or offset < 0 or type(max_chars) is not int or not 500 <= max_chars <= 24000:
        raise ValueError("Invalid reading window")
    with _open_index(folder or default_folder()) as db:
        row = db.execute("SELECT * FROM docs WHERE id = ?", (doc_id,)).fetchone()
        if row is None:
            raise ValueError("No matching official document ID. Use search_official_docs.")
        body = row["body"]
        if focus is not None:
            if not isinstance(focus, str) or not 2 <= len(focus) <= 100:
                raise ValueError("focus must be 2..100 characters")
            match = re.search(re.escape(focus), body, flags=re.I)
            if match:
                offset = max(0, match.start() - min(450, max_chars // 6))
        fragment = body[offset:offset + max_chars]
        return {"id": row["id"], "collection": row["collection"],
                "title": row["title"], "source_url": row["source_url"],
                "original_file_sha256": row["sha256"], "offset": offset,
                "total_chars": len(body), "next_offset": min(len(body), offset + max_chars),
                "has_more": offset + max_chars < len(body),
                "content_verbatim": fragment}


def _source_window(body: str, chars: int, topic: str) -> dict:
    patterns = [r"(?im)^#{1,4}\s*syntax\b",
                r"(?im)^#{1,4}\s*(examples?|usage|parameters)\b",
                rf"(?i)\b{re.escape(topic)}\s*\(",
                rf"(?i)\b{re.escape(topic)}\b"]
    start = 0
    for pattern in patterns:
        match = re.search(pattern, body)
        if match:
            start = max(0, match.start() - 100)
            break
    return {"content_verbatim": body[start:start + chars],
            "excerpt_offset": start, "total_chars": len(body),
            "truncated_for_context": len(body) > start + chars}


def source_reference_excerpts(topics, *, collection: str = "kql", limit: int = 3,
                              chars_per_doc: int = 1700, folder=None):
    """Find exact original pages for KQL-repair provenance (legacy API)."""
    if collection not in DOCS or not isinstance(topics, (list, tuple)):
        raise ValueError("Unsupported reference collection/topics")
    limit = min(max(int(limit), 1), 6)
    chars_per_doc = min(max(int(chars_per_doc), 300), 4000)
    found, used = [], set()
    with _open_index(folder or default_folder()) as db:
        for raw in topics[:12]:
            topic = re.sub(r"[^a-z0-9_-]", "", str(raw).lower())[:60]
            if len(topic) < 2:
                continue
            patterns = (f"%/{topic}-operator.md", f"%/{topic}-function.md",
                        f"%/{topic}.md", f"%/{topic}%.md")
            for pattern in patterns:
                rows = db.execute(
                    "SELECT id,title,source_url,sha256,body FROM docs "
                    "WHERE collection=? AND lower(id) LIKE ? "
                    "ORDER BY length(id) ASC LIMIT 6", (collection, pattern))
                matched = False
                for row in rows:
                    if row["id"] in used:
                        continue
                    used.add(row["id"])
                    found.append({"id": row["id"], "title": row["title"],
                                  "source_url": row["source_url"],
                                  "original_file_sha256": row["sha256"],
                                  **_source_window(row["body"], chars_per_doc, topic)})
                    matched = True
                    break
                if matched:
                    break
            if len(found) >= limit:
                break
    return found[:limit]


def kql_reference_topics(query: str, error: str = "") -> list[str]:
    content = (str(query) + " " + str(error)).lower()
    keywords = ("between", "where", "project", "datetime", "parse_xml",
                "summarize", "join", "union", "extend", "mv-expand",
                "extract", "parse", "tostring", "tolower", "bin", "count", "take")
    topics = [name for name in keywords if re.search(
        r"(?<![a-z0-9_-])" + re.escape(name) + r"(?![a-z0-9_-])", content)]
    if "syntaxerror" in content and "between" not in topics and ")" in content:
        topics.insert(0, "between")
    return topics[:6] or ["where", "project"]
