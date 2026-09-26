from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Sequence

from .models import Finding, SEVERITY_ORDER
from .utils import now_iso


def severity_counts(findings: Sequence[Finding]) -> Dict[str, int]:
    counts = {k: 0 for k in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def score(findings: Sequence[Finding]) -> int:
    weights = {"INFO": 0, "LOW": 1, "MEDIUM": 3, "HIGH": 8, "CRITICAL": 15}
    return min(100, sum(weights.get(f.severity, 0) for f in findings))


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
    print("Findings:", " ".join(
        f"{s}={counts.get(s, 0)}"
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    ))
    print()

    if not findings:
        print("No indicators found.")
    else:
        for index, finding in enumerate(findings, 1):
            location = ""
            if finding.path:
                location = f" [{finding.path}"
                if finding.line:
                    location += f":{finding.line}"
                location += "]"
            print(f"{index:03d}. [{finding.severity}] {finding.title}{location}")
            print(f"     Category: {finding.category}")
            print(f"     Evidence: {finding.evidence}")
            if finding.recommendation:
                print(f"     Action:   {finding.recommendation}")
            print()

    print("Important limitations:")
    print("  - Static indicators are not proof that data was actually transmitted.")
    print("  - No runtime connection observed is not proof of no future/background egress.")
    print("  - TLS encryption prevents payload inspection without authorized interception.")
    print("  - Encrypted/compressed canary staging may evade plaintext hunting.")
    print("  - Domain geography alone is not treated as a security verdict.")

    if metadata:
        print("\nMetadata:")
        print(json.dumps(metadata, indent=2, default=str)[:20_000])


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
