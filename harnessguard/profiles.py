from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class HarnessProfile:
    """Declarative description of a harness under audit.

    A profile records what the operator expects the harness to talk to. It is
    evidence for attribution, not a whitelist and not a trust decision.
    """

    name: str = "unnamed-harness"
    process_patterns: list[str] = field(default_factory=list)
    regex: bool = False
    declared_hosts: list[str] = field(default_factory=list)
    essential_hosts: list[str] = field(default_factory=list)
    declared_jurisdictions: list[str] = field(default_factory=list)
    app_data_paths: list[str] = field(default_factory=list)
    notes: str = ""

    def hosts(self) -> set[str]:
        return {h.strip().lower().lstrip(".") for h in self.declared_hosts if h.strip()}

    def essential(self) -> set[str]:
        return {h.strip().lower().lstrip(".") for h in self.essential_hosts if h.strip()}


def load_profile(path: Path) -> HarnessProfile:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"profile must be a JSON object: {path}")
    return HarnessProfile(
        name=str(data.get("name") or Path(path).stem),
        process_patterns=[str(p) for p in data.get("process_patterns") or []],
        regex=bool(data.get("regex", False)),
        declared_hosts=[str(h) for h in data.get("declared_hosts") or []],
        essential_hosts=[str(h) for h in data.get("essential_hosts") or []],
        declared_jurisdictions=[
            str(j).upper() for j in data.get("declared_jurisdictions") or []
        ],
        app_data_paths=[str(p) for p in data.get("app_data_paths") or []],
        notes=str(data.get("notes") or ""),
    )


def profiles_dir() -> Path:
    return Path.home() / ".harnessguard" / "profiles"


def list_profiles(directory: Path | None = None) -> list[Path]:
    base = Path(directory) if directory else profiles_dir()
    if not base.exists():
        return []
    return sorted(p for p in base.glob("*.json") if p.is_file())
