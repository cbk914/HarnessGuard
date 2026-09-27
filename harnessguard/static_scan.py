from __future__ import annotations

import concurrent.futures
import fnmatch
import re
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path

from .classifier import SourceClass, classify_path, component_id
from .models import SEVERITY_ORDER, Finding, ScanStats
from .rules import (
    COMBINATION_RULES,
    COMPILED_RULES,
    SECRET_VALUE_PATTERNS,
    SENSITIVE_FILE_PATTERNS,
    SNAPSHOT_NEGATIVE_CONTEXT,
)
from .utils import decode_text, iter_files, looks_textual, short_path

MAX_CORRELATION_LINES = 80
MAX_CORRELATION_CHARS = 12000
BINARY_CORRELATION_WINDOW = 65536

DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:(?:https?|wss?)://)?"
    r"((?:[A-Za-z0-9-]+\.)+(?:com|net|org|io|ai|cn|dev|app|cloud|co|xyz|tech|site|me|us|eu|uk|de|fr|es|nl|sg|jp|kr))"
    r"(?::\d{2,5})?(?![A-Za-z0-9_-])",
    re.I,
)


def line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def sensitive_filename(path: Path) -> bool:
    lower = path.name.lower()
    return any(fnmatch.fnmatch(lower, p.lower()) for p in SENSITIVE_FILE_PATTERNS)


def extract_domains(text: str) -> set[str]:
    return {
        m.group(1).lower().rstrip(".")
        for m in DOMAIN_RE.finditer(text)
        if m.group(1).lower().rstrip(".") not in {"example.com", "localhost.localdomain"}
    }


def _auth_snapshot(text: str, start: int, end: int) -> bool:
    ctx = text[max(0, start - 300) : min(len(text), end + 300)]
    return any(p.search(ctx) for p in SNAPSHOT_NEGATIVE_CONTEXT)


def _collect_hits(text: str) -> dict[str, list[dict]]:
    matched = defaultdict(list)
    for category, patterns in COMPILED_RULES.items():
        for pattern, strength in patterns:
            for m in pattern.finditer(text):
                if (
                    category == "snapshot"
                    and strength == "weak"
                    and m.group(0).lower() == "snapshot"
                    and _auth_snapshot(text, m.start(), m.end())
                ):
                    continue
                matched[category].append(
                    {
                        "category": category,
                        "text": m.group(0)[:120],
                        "offset": m.start(),
                        "line": line_for_offset(text, m.start()),
                        "strength": strength,
                    }
                )
                if len(matched[category]) >= 32:
                    break
            if len(matched[category]) >= 32:
                break
    return matched


def _within(h: dict, anchor: dict, binary: bool) -> bool:
    if binary:
        return abs(h["offset"] - anchor["offset"]) <= BINARY_CORRELATION_WINDOW
    return (
        abs(h["line"] - anchor["line"]) <= MAX_CORRELATION_LINES
        and abs(h["offset"] - anchor["offset"]) <= MAX_CORRELATION_CHARS
    )


def _correlated(matched: dict[str, list[dict]], required: set[str], binary: bool):
    cats = sorted(required, key=lambda c: len(matched.get(c, [])))
    if any(not matched.get(c) for c in cats):
        return None, None
    best, best_score, best_span = None, None, None
    for anchor in matched[cats[0]]:
        combo = [anchor]
        for cat in cats[1:]:
            combo.append(
                min(
                    matched[cat],
                    key=lambda h: (
                        0 if (_within(h, anchor, binary) and h["strength"] == "strong") else 1,
                        abs(h["offset"] - anchor["offset"]),
                    ),
                )
            )
        if binary:
            span = max(h["offset"] for h in combo) - min(h["offset"] for h in combo)
            ok = span <= BINARY_CORRELATION_WINDOW
        else:
            lspan = max(h["line"] for h in combo) - min(h["line"] for h in combo)
            cspan = max(h["offset"] for h in combo) - min(h["offset"] for h in combo)
            span, ok = lspan, lspan <= MAX_CORRELATION_LINES and cspan <= MAX_CORRELATION_CHARS
        if ok:
            strong_count = sum(1 for h in combo if h["strength"] == "strong")
            score = (strong_count, -span)
            if best_score is None or score > best_score:
                best, best_span, best_score = combo, span, score
    return best, best_span


def _policy(severity: str, source: SourceClass, strong_count: int):
    if source in {SourceClass.LOCALIZATION, SourceClass.BROWSER_CACHE}:
        return None, "LOW"
    if source == SourceClass.THIRD_PARTY:
        if strong_count < 2:
            return None, "LOW"
        return "MEDIUM", "LOW"
    if source == SourceClass.BINARY:
        if strong_count < 2:
            return None, "LOW"
        return ("HIGH" if severity == "CRITICAL" else severity), "MEDIUM"
    confidence = "HIGH" if strong_count >= 3 else "MEDIUM" if strong_count >= 2 else "LOW"
    if severity in {"HIGH", "CRITICAL"} and strong_count < 2:
        return None, confidence
    return severity, confidence


def scan_one_file(path: Path, max_file_bytes: int) -> tuple[list[Finding], dict]:
    findings = []
    source = classify_path(path)
    comp = component_id(path, source)
    meta = {
        "scanned": False,
        "bytes": 0,
        "binary": False,
        "large": False,
        "source_class": source.value,
        "component_id": comp,
    }
    try:
        size = path.stat().st_size
        if size > max_file_bytes:
            meta["large"] = True
            if path.suffix.lower() in {".zip", ".tar", ".gz", ".tgz", ".7z", ".bin", ".enc"}:
                findings.append(
                    Finding(
                        "MEDIUM",
                        "staging",
                        "Large archive/encrypted blob in application data",
                        f"{size:,} bytes",
                        short_path(path),
                        recommendation="Identify the producer and verify whether the artifact contains workspace data and whether it is queued for upload.",
                        metadata={"source_class": source.value, "component_id": comp},
                        confidence="LOW",
                    )
                )
            return findings, meta

        data = path.read_bytes()
        meta["bytes"] = len(data)
        textual = looks_textual(path, data)
        if not textual:
            meta["binary"] = True
            text = data.decode("latin-1", errors="ignore")
            if not any(
                k in text.lower()
                for k in (
                    "upload",
                    "snapshot",
                    "checkpoint",
                    "telemetry",
                    "aliyun",
                    "amazonaws",
                    "googleapis",
                    "authorization",
                    "repo",
                )
            ):
                return findings, meta
        else:
            text = decode_text(data)
        meta["scanned"] = True
        matched = _collect_hits(text)
        present = {c for c, hits in matched.items() if hits}

        for required, severity, category, title, recommendation in COMBINATION_RULES:
            if not required.issubset(present):
                continue
            combo, span = _correlated(matched, required, binary=not textual)
            if not combo:
                continue
            strong = sum(1 for h in combo if h["strength"] == "strong")
            final, confidence = _policy(severity, source, strong)
            if final is None:
                continue
            bycat = {h["category"]: h for h in combo}
            first = min(combo, key=lambda h: h["offset"])
            findings.append(
                Finding(
                    final,
                    category,
                    title,
                    "; ".join(f"{cat}={bycat[cat]['text']!r}" for cat in sorted(required)),
                    short_path(path),
                    first["line"],
                    recommendation,
                    {
                        "matched_categories": sorted(required),
                        "source_class": source.value,
                        "component_id": comp,
                        "correlation_span": span,
                        "correlation_unit": "bytes" if not textual else "lines",
                        "strong_signal_count": strong,
                        "weak_signal_count": len(combo) - strong,
                    },
                    confidence=confidence,
                )
            )

        domains = sorted(extract_domains(text))
        cloud = [
            d
            for d in domains
            if any(
                x in d
                for x in (
                    "aliyuncs.com",
                    "amazonaws.com",
                    "googleapis.com",
                    "blob.core.windows.net",
                    "cloudflarestorage.com",
                    "backblazeb2.com",
                    "digitaloceanspaces.com",
                )
            )
        ]
        if cloud and ("upload" in present or "object_storage" in present):
            if source == SourceClass.BROWSER_CACHE:
                findings.append(
                    Finding(
                        "INFO",
                        "cached-endpoint",
                        "Cloud/object-storage endpoint observed in browser cache",
                        ", ".join(cloud[:12]),
                        short_path(path),
                        recommendation="Treat cached endpoint strings as historical context, not proof of workspace upload.",
                        metadata={"source_class": source.value, "component_id": comp},
                        confidence="LOW",
                    )
                )
            elif source != SourceClass.LOCALIZATION:
                findings.append(
                    Finding(
                        "MEDIUM",
                        "endpoint",
                        "Cloud/object-storage endpoint embedded in upload-capable content",
                        ", ".join(cloud[:12]),
                        short_path(path),
                        recommendation="Map each endpoint to a documented feature and verify the minimum data sent.",
                        metadata={"source_class": source.value, "component_id": comp},
                        confidence="LOW"
                        if source in {SourceClass.THIRD_PARTY, SourceClass.BINARY}
                        else "MEDIUM",
                    )
                )

        for label, pattern in SECRET_VALUE_PATTERNS:
            m = pattern.search(text)
            if not m:
                continue
            value = m.group(0)
            redacted = value[:6] + "…" + value[-4:] if len(value) > 14 else "<redacted>"
            if source == SourceClass.USER_STATE:
                findings.append(
                    Finding(
                        "INFO",
                        "stored-auth-secret",
                        f"Stored {label} detected in user application state",
                        redacted,
                        short_path(path),
                        line_for_offset(text, m.start()),
                        "This may be legitimate session state. Review storage permissions, expiry, and protection.",
                        {"source_class": source.value, "component_id": comp},
                        confidence="HIGH",
                    )
                )
            elif source not in {SourceClass.LOCALIZATION, SourceClass.BROWSER_CACHE}:
                sev = "HIGH" if source == SourceClass.FIRST_PARTY else "MEDIUM"
                findings.append(
                    Finding(
                        sev,
                        "embedded-secret",
                        f"Potential embedded {label}",
                        redacted,
                        short_path(path),
                        line_for_offset(text, m.start()),
                        "Remove hard-coded credentials/tokens and rotate any real secret that may have shipped.",
                        {"source_class": source.value, "component_id": comp},
                        confidence="MEDIUM",
                    )
                )
        return findings, meta
    except (OSError, PermissionError) as exc:
        meta["error"] = str(exc)
        return findings, meta


def dedupe_findings(findings: Sequence[Finding]) -> list[Finding]:
    seen = set()
    out = []
    for f in findings:
        comp = (f.metadata or {}).get("component_id")
        key = (f.severity, f.category, comp, f.title, f.path, f.line, f.evidence[:200])
        if key not in seen:
            seen.add(key)
            out.append(f)
    out.sort(
        key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.category, f.path or "", f.line or 0)
    )
    return out


def _cross_file(findings: list[Finding]) -> None:
    grouped = defaultdict(list)
    behavioral = {
        "snapshot-upload",
        "encrypted-upload",
        "retry-upload",
        "cloud-upload",
        "sensitive-upload",
        "archive-exfil",
        "telemetry-sensitive",
    }
    for f in findings:
        if f.category not in behavioral:
            continue
        m = f.metadata or {}
        comp = m.get("component_id")
        src = m.get("source_class")
        if comp and src in {SourceClass.FIRST_PARTY.value, SourceClass.BINARY.value}:
            grouped[comp].append(f)
    for comp, items in grouped.items():
        cats = {f.category for f in items}
        high = [f for f in items if f.confidence in {"HIGH", "CONFIRMED"}]
        if (
            ("snapshot-upload" in cats or "encrypted-upload" in cats)
            and ("retry-upload" in cats or "cloud-upload" in cats)
            and len(high) >= 2
        ):
            findings.append(
                Finding(
                    "CRITICAL",
                    "cross-file-chain",
                    "Multiple correlated components form a workspace-to-cloud transfer chain",
                    f"Component {comp} contains multiple high-confidence corroborating behaviors.",
                    recommendation="Validate dynamically with canaries and process/network tracing.",
                    metadata={
                        "component_id": comp,
                        "source_class": (items[0].metadata or {}).get("source_class"),
                        "corroborating_categories": sorted(cats),
                    },
                    confidence="HIGH",
                )
            )


def audit_paths(roots: Sequence[Path], max_file_bytes: int, max_files: int, workers: int):
    findings = []
    stats = ScanStats()
    paths = []
    for root in roots:
        if not root.exists():
            findings.append(
                Finding(
                    "MEDIUM",
                    "input",
                    "Scan root does not exist",
                    str(root),
                    recommendation="Verify the IDE/harness installation or application-data path.",
                    confidence="HIGH",
                )
            )
            continue
        if root.is_file():
            paths.append(root)
        else:
            for p in iter_files(root, max_files=max_files - len(paths)):
                paths.append(p)
                if len(paths) >= max_files:
                    break
        if len(paths) >= max_files:
            break
    stats.files_seen = len(paths)

    sensitive = [p for p in paths if sensitive_filename(p)]
    if sensitive:
        findings.append(
            Finding(
                "INFO",
                "sensitive-inventory",
                "Sensitive-looking files are present in scanned roots",
                f"{len(sensitive)} file(s). Sample: "
                + ", ".join(short_path(p) for p in sensitive[:12]),
                recommendation="Ensure these paths are excluded from indexing, snapshots, telemetry, logs, and uploads.",
                confidence="HIGH",
            )
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(scan_one_file, p, max_file_bytes) for p in paths]
        for fut in concurrent.futures.as_completed(futures):
            fs, meta = fut.result()
            findings.extend(fs)
            if meta.get("scanned"):
                stats.files_scanned += 1
                stats.bytes_scanned += int(meta.get("bytes", 0))
            if meta.get("large"):
                stats.skipped_large += 1
            if meta.get("binary"):
                stats.skipped_binary += 1
            if meta.get("error"):
                stats.errors += 1
    _cross_file(findings)
    return dedupe_findings(findings), stats
