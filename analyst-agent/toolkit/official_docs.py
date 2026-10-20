from __future__ import annotations

import hashlib
import re
import sqlite3
import subprocess
from pathlib import Path

DOCS = {
    "kql": ("MicrosoftDocs/dataexplorer-docs", "main", ("data-explorer/kusto",)),
    "azure-monitor": ("MicrosoftDocs/azure-monitor-docs", "main", ("articles/azure-monitor",)),
    "sentinel": ("Azure/Azure-Sentinel", "master", ("Detections", "Hunting Queries", "Parsers", "ASIM")),
    "windows-server": ("MicrosoftDocs/windowsserverdocs", "main", ("WindowsServerDocs/identity", "WindowsServerDocs/security", "includes")),
}


def default_folder() -> Path:
    import os
    return Path(os.environ.get("TOOLKIT_DOCS_DIR") or os.environ.get("SOC_DOCS_DIR") or str(Path(__file__).resolve().parent.parent / "knowledge")).resolve()


def _open_index(folder: Path) -> sqlite3.Connection:
    target = folder / "official_docs.sqlite3"
    if not target.is_file():
        raise FileNotFoundError(
            "Documentation index not found. Run sync-official-docs.ps1 "
            "and build-docs-index.py."
        )
    connection = sqlite3.connect(f"file:{target.as_posix()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def availability(folder: Path | None = None):
    folder = folder or default_folder()
    try:
        with _open_index(folder) as db:
            rows = db.execute("SELECT collection, count(*) as count FROM docs GROUP BY collection").fetchall()
        return {row["collection"]: row["count"] for row in rows}
    except (sqlite3.DatabaseError, FileNotFoundError, OSError):
        return {}


def build_index(folder: Path | None = None):
    folder = (folder or default_folder()).resolve()
    folder.mkdir(parents=True, exist_ok=True)
    sources = folder / "sources"
    temp = folder / "official_docs.building.sqlite3"
    dst = folder / "official_docs.sqlite3"
    if temp.exists():
        temp.unlink()
    db = sqlite3.connect(temp)
    try:
        db.execute("CREATE TABLE docs (id TEXT PRIMARY KEY, collection TEXT NOT NULL, title TEXT NOT NULL, body TEXT NOT NULL, sha256 TEXT NOT NULL, source_url TEXT NOT NULL)")
        db.execute("CREATE VIRTUAL TABLE docs_fts USING fts5(id UNINDEXED, title, body, tokenize='unicode61')")
        total = {}
        for key, (repo, branch, paths) in DOCS.items():
            root = sources / key
            if not (root / ".git").exists():
                raise FileNotFoundError(f"Missing complete Git mirror for {key}: {root}")
            completed = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                                       capture_output=True, text=True, timeout=20, check=False)
            revision = completed.stdout.strip() if completed.returncode == 0 else branch
            count = 0
            for subfolder in paths:
                base = root / subfolder
                if not base.is_dir():

                    if subfolder not in {"includes", "WindowsServerDocs/security"}:
                        raise FileNotFoundError(f"Missing documentation subtree {key}/{subfolder}")
                    continue
                for path in base.rglob("*"):
                    if not path.is_file() or path.suffix.lower() not in {".md", ".yml", ".yaml"}:
                        continue
                    try:
                        body = path.read_bytes().decode("utf-8")
                    except UnicodeError as exc:

                        raise ValueError(f"Non-UTF8 original documentation cannot be indexed losslessly: {path}") from exc
                    relative = path.relative_to(root).as_posix()
                    docid = f"{key}:{relative}"
                    title = next((line.lstrip("# ").strip() for line in body.splitlines()
                                  if line.startswith("# ") and len(line) < 220), path.stem)
                    url = f"https://github.com/{repo}/blob/{revision}/{relative}"
                    sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
                    db.execute("INSERT INTO docs VALUES (?,?,?,?,?,?)",
                               (docid, key, title, body, sha256, url))
                    db.execute("INSERT INTO docs_fts (id,title,body) VALUES (?,?,?)",
                               (docid, title, body))
                    count += 1
                    if count % 300 == 0:
                        db.commit()
            if count < 10:
                raise ValueError(f"Documentation mirror {key} contains only {count} indexed pages")
            total[key] = count
            db.commit()
        db.execute("CREATE INDEX docs_collection_idx ON docs(collection)")
        db.commit()
    except BaseException:
        db.close()
        temp.unlink(missing_ok=True)
        raise
    db.close()
    temp.replace(dst)
    return total


def search_docs(query: str, *, collection: str = "all", limit: int = 8, folder: Path | None = None):


    if not isinstance(query, str) or len(query) > 240 or not query.strip():
        raise ValueError("query must be 1..240 characters")
    if collection not in ("all", *DOCS):
        raise ValueError("Unknown Microsoft documentation collection")
    if type(limit) is not int or not 1 <= limit <= 15:
        raise ValueError("limit must be 1..15")
    tokens = re.findall(r"[^\W_]{2,}", query, flags=re.UNICODE)[:10]
    if not tokens:
        raise ValueError("Query contains no searchable words")


    words = ['"' + t.replace('"', '') + '"' for t in tokens]
    expressions = [("all_terms", " AND ".join(words))]
    if len(words) > 1:
        expressions.append(("any_term", " OR ".join(words)))
    results, strategy = [], "all_terms"
    with _open_index(folder or default_folder()) as db:
        sql = """SELECT d.id, d.collection, d.title, d.source_url, d.sha256,
                 snippet(docs_fts, 2, '', '', '…', 32) AS excerpt
                 FROM docs_fts JOIN docs AS d ON docs_fts.id=d.id
                 WHERE docs_fts MATCH ?"""
        for label, expression in expressions:
            params = [expression]
            query_sql = sql
            if collection != "all":
                query_sql += " AND d.collection = ?"
                params.append(collection)
            query_sql += " ORDER BY bm25(docs_fts, 0.0, 8.0, 1.0) LIMIT ?"
            params.append(limit)
            results = [dict(row) for row in db.execute(query_sql, params).fetchall()]
            strategy = label
            if results:
                break
    return {"results": results, "verbatim": True, "match_strategy": strategy,
            "note": "Source excerpts; read_official_doc returns a document section."}


def read_doc(doc_id: str, *, offset: int = 0, max_chars: int = 6500,
             focus: str | None = None, folder: Path | None = None):
    if (not isinstance(doc_id, str) or len(doc_id) > 1200 or
            ':' not in doc_id or doc_id.split(':', 1)[0] not in DOCS or '\x00' in doc_id):
        raise ValueError("Invalid documentation identifier")
    if type(offset) is not int or offset < 0 or type(max_chars) is not int or not 500 <= max_chars <= 24000:
        raise ValueError("Invalid reading window")
    with _open_index(folder or default_folder()) as db:
        row = db.execute("SELECT * FROM docs WHERE id = ?", (doc_id,)).fetchone()
        if row is None:
            raise ValueError("No matching official document ID. Use search_official_docs.")
        body = row["body"]


        if focus:
            if not isinstance(focus, str) or not 2 <= len(focus) <= 100:
                raise ValueError("focus must be 2..100 characters")
            match = re.search(re.escape(focus), body, flags=re.I)
            if match:
                offset = max(0, match.start() - min(450, max_chars // 6))
        return {"id": row["id"], "collection": row["collection"],
                "title": row["title"], "source_url": row["source_url"],
                "original_file_sha256": row["sha256"], "offset": offset,
                "total_chars": len(body), "next_offset": min(len(body), offset + max_chars),
                "has_more": offset + max_chars < len(body),
                "content_verbatim": body[offset:offset + max_chars]}


def _source_window(body, chars, topic):


    markers = [r"(?im)^#{1,4}\s*syntax\b",
               r"(?im)^#{1,4}\s*(examples?|usage|parameters)\b",
               rf"(?i)\b{re.escape(topic)}\s*\(",
               rf"(?i)\b{re.escape(topic)}\b"]
    start = 0
    for marker in markers:
        match = re.search(marker, body)
        if match:
            start = max(0, match.start() - 100)
            break
    return {"content_verbatim": body[start:start + chars],
            "excerpt_offset": start, "total_chars": len(body),
            "truncated_for_context": len(body) > chars}


def source_reference_excerpts(topics, *, collection="kql", limit=3, chars_per_doc=1700, folder=None):


    if collection not in DOCS or not isinstance(topics, (list, tuple)):
        raise ValueError("Unsupported reference collection/topics")
    limit = min(max(int(limit), 1), 6)
    chars_per_doc = min(max(int(chars_per_doc), 300), 4000)
    found = []
    used = set()
    with _open_index(folder or default_folder()) as db:
        for raw in topics[:12]:
            topic = re.sub(r"[^a-z0-9_-]", "", str(raw).lower())[:60]
            if len(topic) < 2:
                continue
            patterns = (f"%/{topic}-operator.md", f"%/{topic}-function.md",
                        f"%/{topic}.md", f"%/{topic}%.md")
            for pattern in patterns:
                rows = db.execute(
                    "SELECT id, title, source_url, sha256, body FROM docs "
                    "WHERE collection=? AND lower(id) LIKE ? "
                    "ORDER BY length(id) ASC LIMIT 6", (collection, pattern)).fetchall()
                for row in rows:
                    if row["id"] in used:
                        continue
                    used.add(row["id"])
                    found.append({"id": row["id"], "title": row["title"],
                                  "source_url": row["source_url"],
                                  "original_file_sha256": row["sha256"],
                                  **_source_window(row["body"], chars_per_doc, topic)})
                    break
                if len(found) >= limit or any(r["id"] in used for r in rows):
                    break
            if len(found) >= limit:
                break
    return found


def kql_reference_topics(query: str, error: str = ""):

    content = (str(query) + " " + str(error)).lower()
    keywords = ("between", "where", "project", "datetime", "parse_xml",
                "summarize", "join", "union", "extend", "mv-expand",
                "extract", "parse", "tostring", "tolower", "bin", "count", "take")
    topics = [name for name in keywords if re.search(
        r"(?<![a-z0-9_-])" + re.escape(name) + r"(?![a-z0-9_-])", content)]
    if "syntaxerror" in content and "between" not in topics and ")" in content:
        topics.insert(0, "between")
    return topics[:6] or ["where", "project"]
