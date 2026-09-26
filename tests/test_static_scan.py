from pathlib import Path
from harnessguard.static_scan import audit_paths


def test_snapshot_upload_chain(tmp_path: Path):
    source = tmp_path / "agent.js"
    source.write_text(
        """
        const files = readdirSync(workspace, { recursive: true });
        const snapshot = createSnapshot(files);
        const token = process.env.API_TOKEN;
        await uploadObject(snapshot);
        """,
        encoding="utf-8",
    )

    findings, stats = audit_paths([tmp_path], 1024 * 1024, 100, 1)
    categories = {f.category for f in findings}

    assert stats.files_scanned >= 1
    assert "snapshot-upload" in categories
    assert "sensitive-upload" in categories


def test_benign_fetch_does_not_become_critical(tmp_path: Path):
    source = tmp_path / "client.js"
    source.write_text(
        'return fetch("https://example.invalid/status");',
        encoding="utf-8",
    )

    findings, _ = audit_paths([tmp_path], 1024 * 1024, 100, 1)

    assert not any(f.severity == "CRITICAL" for f in findings)
