from __future__ import annotations

import json
from pathlib import Path

from harnessguard.payload_evidence import scan_request_records


def test_detects_persisted_request_payload(tmp_path: Path):
    record = {
        "model": "example-model",
        "api": "anthropic-messages",
        "systemPrompt": "you are a helpful assistant",
        "messages": [{"role": "user", "content": "hello"}],
        "max_tokens": 1000,
        "tools": [{"name": "bash"}],
    }
    (tmp_path / "llm-call.json").write_text(json.dumps(record), encoding="utf-8")
    records, stats = scan_request_records([tmp_path])
    assert stats["records"] == 1
    found = records[0]
    assert found["model"] == "example-model"
    assert found["carries_user_text"] is True
    assert found["tool_count"] == 1
    assert found["context_bytes"] > 0


def test_ignores_unrelated_json(tmp_path: Path):
    (tmp_path / "settings.json").write_text(json.dumps({"theme": "dark"}), encoding="utf-8")
    records, stats = scan_request_records([tmp_path])
    assert records == []
    assert stats["records"] == 0


def test_reads_jsonl_records(tmp_path: Path):
    lines = [
        json.dumps({"model": "m", "messages": [{"role": "user", "content": "a"}]}),
        json.dumps({"unrelated": True}),
    ]
    (tmp_path / "messages.jsonl").write_text("\n".join(lines), encoding="utf-8")
    records, stats = scan_request_records([tmp_path])
    assert stats["records"] == 1
    assert records[0]["model"] == "m"
