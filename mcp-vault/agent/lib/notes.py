"""
Read/write of SOC vault notes - runs server-side (on the VM), invoked by
bin/vault-agent.py. Holds no identity/audit state of its own (that lives in
lib/audit.py); this module only knows how to manipulate Markdown files with
YAML frontmatter.

VAULT_ROOT defaults to <deployment root>/data/vault, derived from the location
of this file (lib/notes.py -> .. -> root), so the same code works unchanged
whether the root is /data/vault or any other path. It can be overridden with
VAULT_ROOT if needed.
"""

import json
import os
import re
from datetime import date, datetime
from pathlib import Path

import yaml

BASE_DIR = Path(__file__).resolve().parent.parent
VAULT_ROOT = Path(os.environ.get("VAULT_ROOT") or (BASE_DIR / "data" / "vault")).resolve()

ENTITY_FOLDERS = {
    "user": "02-Entities/Users",
    "host": "02-Entities/Hosts",
    "ioc": "02-Entities/IOCs",
    "actor": "02-Entities/Actors",
}


def today() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def now_time() -> str:
    return datetime.now().strftime("%H:%M")


def slugify(text: str) -> str:
    text = text.strip().lower()
    text = re.sub(r"[^a-z0-9\u00e1\u00e9\u00ed\u00f3\u00fa\u00f1\u00fc\s-]", "", text)
    text = re.sub(r"[\s_]+", "-", text)
    return re.sub(r"-+", "-", text).strip("-") or "note"


def json_safe(value):
    """yaml.safe_load turns unquoted dates (created: 2026-08-05) into
    date/datetime objects, which json.dumps cannot serialize. Normalize to str."""
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [json_safe(v) for v in value]
    return value


def resolve(rel_path: str) -> Path:
    rel_path = rel_path.replace("\\", "/").strip().lstrip("/")
    if not rel_path:
        raise ValueError("empty path")
    if not rel_path.lower().endswith(".md"):
        rel_path += ".md"
    parts = [p for p in rel_path.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise ValueError(f"invalid path (cannot escape the vault): {rel_path}")
    full = (VAULT_ROOT / Path(*parts)).resolve()
    if VAULT_ROOT not in full.parents and full != VAULT_ROOT:
        raise ValueError(f"invalid path (outside the vault): {rel_path}")
    return full


def resolve_folder(prefix: str) -> Path:
    prefix = prefix.replace("\\", "/").strip().strip("/")
    parts = [p for p in prefix.split("/") if p not in ("", ".", "..")]
    return VAULT_ROOT.joinpath(*parts)


def rel(full: Path) -> str:
    return str(full.relative_to(VAULT_ROOT)).replace("\\", "/")


def split_frontmatter(text: str):
    if text.startswith("---\n"):
        end = text.find("\n---", 4)
        if end != -1:
            fm_raw = text[4:end]
            body = text[end + 4:].lstrip("\n")
            try:
                fm = yaml.safe_load(fm_raw) or {}
            except yaml.YAMLError:
                fm = {}
            return json_safe(fm), body
    return {}, text


def join_frontmatter(fm: dict, body: str) -> str:
    fm_yaml = yaml.safe_dump(fm, allow_unicode=True, sort_keys=False).strip()
    return f"---\n{fm_yaml}\n---\n\n{body.strip()}\n"


def read(full: Path):
    if not full.exists():
        return None, None
    return split_frontmatter(full.read_text(encoding="utf-8"))


def write(full: Path, fm: dict, body: str):
    full.parent.mkdir(parents=True, exist_ok=True)
    full.write_text(join_frontmatter(fm, body), encoding="utf-8")


def append_section(body: str, heading: str, line: str) -> str:
    marker = f"## {heading}"
    lines = body.split("\n")
    for i, l in enumerate(lines):
        if l.strip() == marker:
            j = i + 1
            while j < len(lines) and not lines[j].startswith("## "):
                j += 1
            insert_at = j
            while insert_at > i + 1 and lines[insert_at - 1].strip() == "":
                insert_at -= 1
            lines[insert_at:insert_at] = [line]
            return "\n".join(lines)
    return body.rstrip("\n") + f"\n\n{marker}\n\n{line}\n"


# ---------------------------------------------------------------------------
# tool dispatch
# ---------------------------------------------------------------------------

def dispatch(analyst: str, tool: str, arguments: dict):
    if tool == "create_note":
        full = resolve(arguments["path"])
        if full.exists() and not arguments.get("overwrite", False):
            raise FileExistsError(f"{rel(full)} already exists - use append_note or overwrite=true")
        fm = {"title": arguments["title"], "created": today(), "tags": arguments.get("tags", [])}
        fm.update(arguments.get("frontmatter") or {})
        write(full, fm, arguments.get("content", ""))
        return {"path": rel(full), "created": True}

    elif tool == "append_note":
        full = resolve(arguments["path"])
        fm, body = read(full)
        if fm is None:
            if not arguments.get("create_if_missing", True):
                raise FileNotFoundError(f"{rel(full)} does not exist")
            fm = {"title": arguments.get("title", full.stem), "created": today(), "tags": arguments.get("tags", [])}
            body = ""
        content = arguments["content"]
        heading = arguments.get("heading")
        if heading:
            body = append_section(body, heading, f"- {content}")
        else:
            body = body.rstrip("\n") + f"\n- {now_time()} — {content}\n"
        write(full, fm, body)
        return {"path": rel(full), "updated": True}

    elif tool == "read_note":
        full = resolve(arguments["path"])
        fm, body = read(full)
        if fm is None:
            raise FileNotFoundError(f"{rel(full)} does not exist")
        return {"path": rel(full), "frontmatter": fm, "content": body}

    elif tool == "search_vault":
        query = arguments["query"].lower()
        prefix = arguments.get("path_prefix")
        tag = arguments.get("tag")
        limit = arguments.get("limit", 20)
        base = resolve_folder(prefix) if prefix else VAULT_ROOT
        matches = []
        for f in sorted(base.rglob("*.md")):
            if ".obsidian" in f.parts or ".git" in f.parts:
                continue
            fm, body = split_frontmatter(f.read_text(encoding="utf-8"))
            if tag and tag not in (fm.get("tags") or []):
                continue
            if query not in body.lower() and query not in json.dumps(fm, ensure_ascii=False).lower():
                continue
            snippet = next((l.strip() for l in body.split("\n") if query in l.lower()), "")
            matches.append({"path": rel(f), "title": fm.get("title", f.stem), "snippet": snippet})
            if len(matches) >= limit:
                break
        return {"count": len(matches), "matches": matches}

    elif tool == "list_notes":
        prefix = arguments.get("path_prefix")
        tag = arguments.get("tag")
        base = resolve_folder(prefix) if prefix else VAULT_ROOT
        notes = []
        for f in sorted(base.rglob("*.md")):
            if ".obsidian" in f.parts or ".git" in f.parts:
                continue
            fm, _ = split_frontmatter(f.read_text(encoding="utf-8"))
            if tag and tag not in (fm.get("tags") or []):
                continue
            notes.append({
                "path": rel(f),
                "title": fm.get("title", f.stem),
                "tags": fm.get("tags", []),
                "modified": datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M"),
            })
        return {"count": len(notes), "notes": notes}

    elif tool == "upsert_entity":
        entity_type = arguments["entity_type"]
        folder = ENTITY_FOLDERS[entity_type]
        name_arg = arguments["name"]
        slug = slugify(name_arg)
        full = resolve(f"{folder}/{slug}.md")
        sighting_ref = arguments.get("sighting_ref")
        sighting_line = f"- {today()} — {arguments['sighting_note']}"
        if sighting_ref:
            sighting_line += f" ([[{sighting_ref}]])"

        fm, body = read(full)
        created = fm is None
        if created:
            fm = {"type": "entity", "entity_type": entity_type, "title": name_arg, "created": today(), "tags": [entity_type]}
            body = f"# {name_arg}\n\n## Attributes\n\n## Sightings\n\n{sighting_line}\n"
        else:
            body = append_section(body, "Sightings", sighting_line)

        fm.update(arguments.get("attributes") or {})
        write(full, fm, body)
        return {"path": rel(full), "created": created, "updated": not created}

    elif tool == "daily_log":
        full = resolve(f"06-Daily/{today()}.md")
        fm, body = read(full)
        if fm is None:
            fm = {"type": "daily", "title": today(), "tags": arguments.get("tags", [])}
            body = ""
        body = body.rstrip("\n") + f"\n- {now_time()} [{analyst}] — {arguments['entry']}\n"
        write(full, fm, body)
        return {"path": rel(full), "updated": True}

    raise ValueError(f"Unknown tool: {tool}")
