from __future__ import annotations

from enum import Enum
from pathlib import Path


class SourceClass(str, Enum):
    FIRST_PARTY = "first_party"
    THIRD_PARTY = "third_party"
    LOCALIZATION = "localization"
    BROWSER_CACHE = "browser_cache"
    USER_STATE = "user_state"
    BINARY = "binary"
    UNKNOWN = "unknown"


def _norm(path: Path) -> str:
    return "/" + str(path).replace("\\", "/").lower().lstrip("/")


def classify_path(path: Path) -> SourceClass:
    p = _norm(path)
    ext = path.suffix.lower()
    if ext in {".pak", ".mo", ".po"} or "/locales/" in p:
        return SourceClass.LOCALIZATION
    if any(
        x in p
        for x in (
            "/cache/cache_data/",
            "/code cache/",
            "/service worker/scriptcache/",
            "/cache_data/",
        )
    ):
        return SourceClass.BROWSER_CACHE
    if any(
        x in p for x in ("/node_modules/", "/.pnpm/", "/vendor/", "/third_party/", "/third-party/")
    ):
        return SourceClass.THIRD_PARTY
    if ext in {".exe", ".dll", ".so", ".dylib", ".bin"}:
        return SourceClass.BINARY
    if any(
        x in p
        for x in (
            "/appdata/roaming/",
            "/library/application support/",
            "/.config/",
            "/.local/share/",
        )
    ):
        return SourceClass.USER_STATE
    if ext in {
        ".py",
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".jsx",
        ".java",
        ".go",
        ".rs",
        ".rb",
        ".php",
        ".ps1",
        ".sh",
        ".cs",
        ".cpp",
        ".c",
        ".h",
        ".hpp",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
    }:
        return SourceClass.FIRST_PARTY
    return SourceClass.UNKNOWN


def component_id(path: Path, source_class: SourceClass) -> str:
    p = _norm(path)
    if source_class == SourceClass.THIRD_PARTY:
        for marker in ("/node_modules/", "/.pnpm/", "/vendor/", "/third_party/", "/third-party/"):
            if marker in p:
                prefix, suffix = p.split(marker, 1)
                package = suffix.split("/", 1)[0] if suffix else "unknown"
                return f"{source_class.value}:{prefix}{marker}{package}"
    if source_class == SourceClass.BROWSER_CACHE:
        return "browser_cache:browser-cache"
    if source_class == SourceClass.LOCALIZATION:
        return "localization:locales"
    return f"{source_class.value}:{str(path.parent).lower()}"
