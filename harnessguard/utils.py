from __future__ import annotations

import ipaddress
import os
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

TEXT_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".css",
    ".go",
    ".h",
    ".hpp",
    ".html",
    ".java",
    ".js",
    ".jsx",
    ".json",
    ".jsonc",
    ".kt",
    ".kts",
    ".lua",
    ".md",
    ".mjs",
    ".mts",
    ".php",
    ".pl",
    ".ps1",
    ".py",
    ".rb",
    ".rs",
    ".sh",
    ".sql",
    ".swift",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".vue",
    ".xml",
    ".yaml",
    ".yml",
    ".ini",
    ".conf",
    ".cfg",
    ".properties",
    ".gradle",
    ".lock",
    ".env",
    ".gitignore",
    ".dockerignore",
}

TEXT_FILENAMES = {
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "cargo.toml",
    "cargo.lock",
    "go.mod",
    "go.sum",
    "dockerfile",
    "makefile",
    "settings.json",
    "product.json",
    "manifest.json",
    "notice.md",
}

SKIP_DIR_NAMES = {
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "build",
    "target",
    ".next",
    ".nuxt",
    ".gradle/caches",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def short_path(path: Path) -> str:
    try:
        return str(path.resolve())
    except Exception:
        return str(path)


def should_skip_dir(path: Path) -> bool:
    parts = [p.lower() for p in path.parts]
    joined = "/".join(parts)
    for item in SKIP_DIR_NAMES:
        item = item.lower()
        if "/" in item and item in joined:
            return True
        if "/" not in item and item in parts:
            return True
    return False


def iter_files(root: Path, max_files: int) -> Iterator[Path]:
    count = 0
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except (OSError, PermissionError):
            continue
        for entry in entries:
            path = Path(entry.path)
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if not should_skip_dir(path):
                        stack.append(path)
                elif entry.is_file(follow_symlinks=False):
                    count += 1
                    yield path
                    if count >= max_files:
                        return
            except OSError:
                continue


def looks_textual(path: Path, data: bytes) -> bool:
    if path.name.lower() in TEXT_FILENAMES or path.suffix.lower() in TEXT_EXTENSIONS:
        return True
    if not data:
        return True
    sample = data[:4096]
    if b"\x00" in sample:
        return False
    printable = sum(1 for byte in sample if byte in (9, 10, 13) or 32 <= byte <= 126 or byte >= 128)
    return printable / max(1, len(sample)) >= 0.85


def decode_text(data: bytes) -> str:
    for encoding in ("utf-8", "utf-8-sig", "utf-16", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            pass
    return data.decode("utf-8", errors="replace")


def is_public_ip(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
        return not (
            obj.is_private
            or obj.is_loopback
            or obj.is_link_local
            or obj.is_multicast
            or obj.is_reserved
            or obj.is_unspecified
        )
    except ValueError:
        return False
