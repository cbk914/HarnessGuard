from pathlib import Path

from harnessguard.canary import hunt_canaries, make_canary_workspace


def test_canary_generation(tmp_path: Path):
    workspace = tmp_path / "canary"
    manifest = make_canary_workspace(workspace)

    assert (workspace / ".env").exists()
    assert (workspace / ".privacy-canary.json").exists()
    assert manifest["canary_id"].startswith("PRIVACY_CANARY_")


def test_canary_hunt_finds_copy(tmp_path: Path):
    workspace = tmp_path / "canary"
    manifest = make_canary_workspace(workspace)

    target = tmp_path / "appdata"
    target.mkdir()
    (target / "staged.txt").write_text(manifest["canary_id"], encoding="utf-8")

    findings, metadata = hunt_canaries(
        workspace / ".privacy-canary.json",
        [target],
        1024 * 1024,
        100,
    )

    assert metadata["hits"] >= 1
    assert any(f.category == "canary-copy" for f in findings)
