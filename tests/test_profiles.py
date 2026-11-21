from __future__ import annotations

import json
from pathlib import Path

from harnessguard.profiles import HarnessProfile, load_profile


def test_load_profile_reads_declarations(tmp_path: Path):
    path = tmp_path / "harness.json"
    path.write_text(
        json.dumps(
            {
                "name": "demo",
                "process_patterns": ["demo"],
                "declared_hosts": ["API.Example.com", "cdn.example.org"],
                "declared_jurisdictions": ["us"],
                "app_data_paths": ["/tmp/demo"],
            }
        ),
        encoding="utf-8",
    )
    profile = load_profile(path)
    assert profile.name == "demo"
    assert profile.declared_jurisdictions == ["US"]
    assert profile.hosts() == {"api.example.com", "cdn.example.org"}
    assert profile.app_data_paths == ["/tmp/demo"]


def test_default_profile_is_empty():
    profile = HarnessProfile()
    assert profile.hosts() == set()
    assert profile.process_patterns == []
