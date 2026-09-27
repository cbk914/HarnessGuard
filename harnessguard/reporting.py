from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Sequence
from pathlib import Path

from .models import SEVERITY_ORDER, Finding
from .utils import now_iso

CATEGORY_SCORE_CAP = {
    "snapshot-upload": 16,
    "sensitive-upload": 30,
    "archive-exfil": 30,
    "encrypted-upload": 16,
    "retry-upload": 12,
    "cloud-upload": 12,
    "telemetry-sensitive": 12,
    "endpoint": 6,
    "cached-endpoint": 1,
    "embedded-secret": 16,
    "stored-auth-secret": 2,
}
CONFIDENCE_MULTIPLIER = {"LOW": 0.35, "MEDIUM": 0.65, "HIGH": 1.0, "CONFIRMED": 1.25}


def severity_counts(findings: Sequence[Finding]) -> dict[str, int]:
    counts = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def score(findings: Sequence[Finding]) -> int:
    weights = {"INFO": 0, "LOW": 1, "MEDIUM": 3, "HIGH": 8, "CRITICAL": 15}
    totals = defaultdict(float)
    seen = set()
    for f in findings:
        m = f.metadata or {}
        comp = m.get("component_id", f.path or "<global>")
        key = (f.category, comp)
        if key in seen:
            continue
        seen.add(key)
        totals[f.category] += weights.get(f.severity, 0) * CONFIDENCE_MULTIPLIER.get(
            f.confidence, 0.65
        )
    total = sum(min(v, CATEGORY_SCORE_CAP.get(k, 20)) for k, v in totals.items())
    return min(100, round(total))


def risk_label(points: int) -> str:
    if points >= 60:
        return "SEVERE"
    if points >= 35:
        return "HIGH"
    if points >= 15:
        return "ELEVATED"
    if points >= 5:
        return "LOW"
    return "MINIMAL-EVIDENCE"


def print_report(findings: Sequence[Finding], metadata: dict, version: str) -> None:
    counts = severity_counts(findings)
    points = score(findings)
    print("\n=== HarnessGuard ===")
    print(f"Version: {version}")
    print(f"Time:    {now_iso()}")
    print(f"Risk:    {risk_label(points)} ({points}/100 heuristic)")
    print(
        "Findings:",
        " ".join(f"{s}={counts.get(s, 0)}" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")),
    )
    print()
    if not findings:
        print("No indicators found.")
    else:
        for i, f in enumerate(findings, 1):
            loc = ""
            if f.path:
                loc = f" [{f.path}" + (f":{f.line}" if f.line else "") + "]"
            print(f"{i:03d}. [{f.severity}] {f.title}{loc}")
            print(f"     Category:   {f.category}")
            print(f"     Confidence: {f.confidence}")
            print(f"     Evidence:   {f.evidence}")
            m = f.metadata or {}
            if m.get("source_class"):
                print(f"     Source:     {m['source_class']}")
            if m.get("correlation_span") is not None:
                print(
                    f"     Correlation: {m['correlation_span']} {m.get('correlation_unit', 'units')}"
                )
            if f.recommendation:
                print(f"     Action:     {f.recommendation}")
            print()
    print("Important limitations:")
    print("  - Static indicators are not proof that data was actually transmitted.")
    print("  - No runtime connection observed is not proof of no future/background egress.")
    print("  - TLS encryption prevents payload inspection without authorized interception.")
    print("  - Encrypted/compressed canary staging may evade plaintext hunting.")
    print("  - Domain geography alone is not treated as a security verdict.")
    print("  - Severity represents potential impact; confidence represents evidence quality.")
    if metadata:
        print("\nMetadata:")
        print(json.dumps(metadata, indent=2, default=str)[:20000])


def save_json(path: Path, findings: Sequence[Finding], metadata: dict, version: str) -> None:
    report = {
        "tool": "harnessguard",
        "version": version,
        "generated_at": now_iso(),
        "risk_score": score(findings),
        "risk_label": risk_label(score(findings)),
        "severity_counts": severity_counts(findings),
        "findings": [f.as_dict() for f in findings],
        "metadata": metadata,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")


def exit_code(findings: Sequence[Finding]) -> int:
    maximum = max((SEVERITY_ORDER.get(f.severity, 0) for f in findings), default=0)
    if maximum >= SEVERITY_ORDER["CRITICAL"]:
        return 2
    if maximum >= SEVERITY_ORDER["HIGH"]:
        return 1
    return 0
