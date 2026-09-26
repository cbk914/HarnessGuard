from __future__ import annotations

import concurrent.futures
import fnmatch
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Sequence, Set, Tuple

from .models import Finding, ScanStats, SEVERITY_ORDER
from .rules import COMBINATION_RULES, COMPILED_RULES, SECRET_VALUE_PATTERNS, SENSITIVE_FILE_PATTERNS
from .utils import decode_text, iter_files, looks_textual, short_path

DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:(?:https?|wss?)://)?"
    r"((?:[A-Za-z0-9-]+\.)+(?:com|net|org|io|ai|cn|dev|app|cloud|co|xyz|tech|site|me|us|eu|uk|de|fr|es|nl|sg|jp|kr))"
    r"(?::\d{2,5})?(?![A-Za-z0-9_-])",
    re.IGNORECASE,
)


def line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def sensitive_filename(path: Path) -> bool:
    lower = path.name.lower()
    return any(fnmatch.fnmatch(lower, p.lower()) for p in SENSITIVE_FILE_PATTERNS)


def extract_domains(text: str) -> Set[str]:
    out = set()
    for match in DOMAIN_RE.finditer(text):
        domain = match.group(1).lower().rstrip(".")
        if domain not in {"example.com", "localhost.localdomain"}:
            out.add(domain)
    return out


def scan_one_file(path: Path, max_file_bytes: int) -> Tuple[List[Finding], dict]:
    findings = []
    meta = {"scanned": False, "bytes": 0, "binary": False, "large": False}
    try:
        size = path.stat().st_size
        if size > max_file_bytes:
            meta["large"] = True
            if path.suffix.lower() in {".zip", ".tar", ".gz", ".tgz", ".7z", ".bin", ".enc"}:
                findings.append(Finding(
                    "MEDIUM", "staging", "Large archive/encrypted blob in application data",
                    f"{size:,} bytes", short_path(path),
                    recommendation="Identify the producer and verify whether the artifact contains workspace data and whether it is queued for upload."
                ))
            return findings, meta

        data = path.read_bytes()
        meta["bytes"] = len(data)

        if not looks_textual(path, data):
            meta["binary"] = True
            text = data.decode("latin-1", errors="ignore")
            if not any(k in text.lower() for k in (
                "upload", "snapshot", "checkpoint", "telemetry",
                "aliyun", "amazonaws", "googleapis", "authorization", "repo"
            )):
                return findings, meta
        else:
            text = decode_text(data)

        meta["scanned"] = True
        matched: Dict[str, List[Tuple[str, int]]] = defaultdict(list)

        for category, patterns in COMPILED_RULES.items():
            for pattern in patterns:
                for match in pattern.finditer(text):
                    matched[category].append((match.group(0)[:120], match.start()))
                    if len(matched[category]) >= 8:
                        break
                if len(matched[category]) >= 8:
                    break

        present = {category for category, hits in matched.items() if hits}

        for required, severity, category, title, recommendation in COMBINATION_RULES:
            if required.issubset(present):
                evidence_parts = []
                first_offset = None
                for requirement in sorted(required):
                    hit, offset = matched[requirement][0]
                    evidence_parts.append(f"{requirement}={hit!r}")
                    first_offset = offset if first_offset is None else min(first_offset, offset)

                findings.append(Finding(
                    severity, category, title, "; ".join(evidence_parts),
                    short_path(path), line_for_offset(text, first_offset or 0),
                    recommendation, {"matched_categories": sorted(required)}
                ))

        domains = sorted(extract_domains(text))
        cloud_domains = [
            d for d in domains
            if any(x in d for x in (
                "aliyuncs.com", "amazonaws.com", "googleapis.com",
                "blob.core.windows.net", "cloudflarestorage.com",
                "backblazeb2.com", "digitaloceanspaces.com"
            ))
        ]

        if cloud_domains and ("upload" in present or "object_storage" in present):
            findings.append(Finding(
                "MEDIUM", "endpoint",
                "Cloud/object-storage endpoint embedded in upload-capable code",
                ", ".join(cloud_domains[:12]), short_path(path),
                recommendation="Map each endpoint to a documented feature and verify the minimum data sent."
            ))

        for label, pattern in SECRET_VALUE_PATTERNS:
            match = pattern.search(text)
            if not match:
                continue
            value = match.group(0)
            redacted = value[:6] + "…" + value[-4:] if len(value) > 14 else "<redacted>"
            findings.append(Finding(
                "HIGH", "embedded-secret", f"Potential embedded {label}",
                redacted, short_path(path), line_for_offset(text, match.start()),
                "Remove hard-coded credentials/tokens and rotate any real secret that may have shipped."
            ))

        return findings, meta
    except (OSError, PermissionError) as exc:
        meta["error"] = str(exc)
        return findings, meta


def dedupe_findings(findings: Sequence[Finding]) -> List[Finding]:
    seen = set()
    out = []
    for finding in findings:
        key = (finding.severity, finding.category, finding.title, finding.path, finding.line, finding.evidence[:200])
        if key not in seen:
            seen.add(key)
            out.append(finding)
    out.sort(key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.category, f.path or "", f.line or 0))
    return out


def audit_paths(roots: Sequence[Path], max_file_bytes: int, max_files: int, workers: int):
    findings = []
    stats = ScanStats()
    paths = []

    for root in roots:
        if not root.exists():
            findings.append(Finding(
                "MEDIUM", "input", "Scan root does not exist", str(root),
                recommendation="Verify the IDE/harness installation or application-data path."
            ))
            continue
        if root.is_file():
            paths.append(root)
        else:
            for path in iter_files(root, max_files=max_files - len(paths)):
                paths.append(path)
                if len(paths) >= max_files:
                    break
        if len(paths) >= max_files:
            break

    stats.files_seen = len(paths)

    sensitive_inventory = [p for p in paths if sensitive_filename(p)]
    if sensitive_inventory:
        sample = ", ".join(short_path(p) for p in sensitive_inventory[:12])
        findings.append(Finding(
            "INFO", "sensitive-inventory",
            "Sensitive-looking files are present in scanned roots",
            f"{len(sensitive_inventory)} file(s). Sample: {sample}",
            recommendation="Ensure the tool explicitly excludes these paths from indexing, snapshots, telemetry, logs, and uploads."
        ))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = [pool.submit(scan_one_file, p, max_file_bytes) for p in paths]
        for future in concurrent.futures.as_completed(futures):
            file_findings, meta = future.result()
            findings.extend(file_findings)
            if meta.get("scanned"):
                stats.files_scanned += 1
                stats.bytes_scanned += int(meta.get("bytes", 0))
            if meta.get("large"):
                stats.skipped_large += 1
            if meta.get("binary"):
                stats.skipped_binary += 1
            if meta.get("error"):
                stats.errors += 1

    categories = {f.category for f in findings}
    if (
        ("snapshot-upload" in categories or "encrypted-upload" in categories)
        and ("retry-upload" in categories or "cloud-upload" in categories)
    ):
        findings.append(Finding(
            "CRITICAL", "cross-file-chain",
            "Multiple components form a credible workspace-to-cloud transfer chain",
            "Static evidence spans snapshot/encryption/upload and cloud/retry behavior.",
            recommendation="Do not use the tool on sensitive repositories until runtime traces and documentation prove intended, consented, minimal transfer."
        ))

    return dedupe_findings(findings), stats
