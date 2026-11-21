from __future__ import annotations

import json
import os
import re
from pathlib import Path

SCANNABLE_SUFFIXES = {".json", ".jsonl", ".ndjson"}

MODEL_KEYS = ("model", "model_id", "modelId")
CONTEXT_KEYS = (
    "messages",
    "systemPrompt",
    "system_prompt",
    "prompt",
    "input",
    "conversation",
    "history",
    "contents",
)
ENDPOINT_KEYS = ("baseURL", "base_url", "baseUrl", "endpoint", "url", "apiUrl", "api_url")

URL_RE = re.compile(r"(?i)\b(?:https?|wss?)://([a-z0-9.-]{3,90})")


def _candidate_line(line: str) -> bool:
    """Cheap pre-filter so large transcript files are not parsed line by line."""
    lowered = line.lower()
    if '"model"' not in lowered and '"max_tokens"' not in lowered:
        return False
    return (
        '"messages"' in lowered
        or '"systemprompt"' in lowered
        or '"system"' in lowered
        or '"prompt"' in lowered
        or '"input"' in lowered
    )


def _candidate_text(text: str) -> bool:
    lowered = text.lower()
    if '"model"' not in lowered and '"max_tokens"' not in lowered:
        return False
    return (
        '"messages"' in lowered
        or '"systemprompt"' in lowered
        or '"system"' in lowered
        or '"prompt"' in lowered
        or '"input"' in lowered
    )


def _looks_like_request_record(data: object) -> bool:
    if not isinstance(data, dict):
        return False
    keys = {str(k).lower() for k in data.keys()}
    has_model = any(key.lower() in ("model", "model_id", "modelid") for key in keys)
    has_context = any(
        key.lower() in ("messages", "systemprompt", "system_prompt", "prompt", "input") for key in keys
    )
    has_limit = any(key.lower() in ("max_tokens", "maxtokens", "maxoutputtokens") for key in keys)
    return (has_model and has_context) or (has_context and has_limit)


def _extract(data: dict) -> dict:
    model = ""
    endpoint = ""
    api = ""
    max_tokens = None
    user_text = False
    context_bytes = 0
    tools = 0

    for key, value in data.items():
        lowered = str(key).lower()
        if lowered in MODEL_KEYS and isinstance(value, str):
            model = value
        elif lowered in ("api", "api_type", "apiType") and isinstance(value, str):
            api = value
        elif lowered in ENDPOINT_KEYS and isinstance(value, str):
            endpoint = value
        elif lowered in ("max_tokens", "maxtokens") and isinstance(value, int):
            max_tokens = value
        elif lowered == "tools" and isinstance(value, list):
            tools = len(value)
        elif lowered in ("messages", "systemprompt", "system_prompt", "prompt", "input"):
            user_text = True
            context_bytes += len(json.dumps(value, default=str))

    if not endpoint:
        for _key, value in data.items():
            if isinstance(value, str):
                match = URL_RE.search(value)
                if match:
                    endpoint = value
                    break

    return {
        "model": model,
        "api": api,
        "endpoint": endpoint,
        "endpoint_host": (URL_RE.search(endpoint).group(1).lower() if endpoint and URL_RE.search(endpoint) else ""),
        "max_tokens": max_tokens,
        "tool_count": tools,
        "carries_user_text": user_text,
        "context_bytes": context_bytes,
    }


def scan_request_records(
    paths: list[Path],
    max_file_bytes: int = 8 * 1024 * 1024,
    max_files: int = 4000,
) -> tuple[list[dict], dict]:
    """Find locally persisted outbound request payloads.

    Many harnesses serialize the exact request they send (model, system prompt,
    tool schemas, conversation). Those artefacts are the most direct evidence of
    what leaves the machine, and they are readable without intercepting TLS.
    """
    records: list[dict] = []
    stats = {"files_seen": 0, "files_scanned": 0, "records": 0, "skipped_large": 0, "errors": 0}

    for root in paths:
        root = Path(root)
        candidates: list[Path] = []
        if root.is_file():
            candidates = [root]
        elif root.is_dir():
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames[:] = [
                    d for d in dirnames if d not in {"node_modules", ".git", "__pycache__"}
                ]
                for filename in filenames:
                    candidates.append(Path(dirpath) / filename)
                    if len(candidates) >= max_files:
                        break
                if len(candidates) >= max_files:
                    break

        for path in candidates:
            if stats["files_seen"] >= max_files:
                break
            stats["files_seen"] += 1
            if path.suffix.lower() not in SCANNABLE_SUFFIXES:
                continue
            try:
                size = path.stat().st_size
                if size > max_file_bytes:
                    stats["skipped_large"] += 1
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                stats["errors"] += 1
                continue
            stats["files_scanned"] += 1

            documents: list[object] = []
            if path.suffix.lower() == ".jsonl":
                for line in text.splitlines():
                    line = line.strip()
                    if not line or not _candidate_line(line):
                        continue
                    try:
                        documents.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            else:
                if not _candidate_text(text):
                    continue
                try:
                    documents.append(json.loads(text))
                except json.JSONDecodeError:
                    continue

            for document in documents:
                if not _looks_like_request_record(document):
                    continue
                summary = _extract(document)
                if not summary["model"] and not summary["context_bytes"]:
                    continue
                summary.update(
                    {
                        "path": str(path),
                        "file_bytes": size,
                        "record_bytes": len(json.dumps(document, default=str)),
                    }
                )
                records.append(summary)

    stats["records"] = len(records)
    return records, stats
