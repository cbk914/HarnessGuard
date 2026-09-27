from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    evidence: str
    path: str | None = None
    line: int | None = None
    recommendation: str | None = None
    metadata: dict[str, Any] | None = None
    confidence: str = "MEDIUM"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanStats:
    files_seen: int = 0
    files_scanned: int = 0
    bytes_scanned: int = 0
    skipped_large: int = 0
    skipped_binary: int = 0
    errors: int = 0
