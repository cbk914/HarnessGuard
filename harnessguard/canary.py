from __future__ import annotations

import json
import secrets
import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path

from .models import Finding
from .static_scan import dedupe_findings
from .utils import iter_files, now_iso, short_path


def make_canary_workspace(dest: Path) -> dict:
    dest.mkdir(parents=True, exist_ok=True)

    token = "PRIVACY_CANARY_" + secrets.token_hex(24)
    fake_api = "sk-" + secrets.token_urlsafe(32)
    fake_bearer = (
        "eyJ"
        + secrets.token_urlsafe(18)
        + "."
        + secrets.token_urlsafe(18)
        + "."
        + secrets.token_urlsafe(18)
    )

    generated_files = {
        "README.md": "# AI Harness Privacy Canary\n\nThis workspace contains ONLY synthetic test data.\n",
        "src/main.py": "def hello():\n    return 'privacy canary workspace'\n",
        ".env": f"CANARY_ID={token}\nFAKE_OPENAI_API_KEY={fake_api}\nFAKE_BEARER_TOKEN={fake_bearer}\n",
        "config/private-config.json": json.dumps(
            {
                "canary": token,
                "fake_token": fake_api,
                "purpose": "synthetic privacy checker data",
            },
            indent=2,
        )
        + "\n",
        "docs/internal-only.txt": f"SYNTHETIC INTERNAL MARKER: {token}\nThis is not real confidential data.\n",
    }

    for relative_path, content in generated_files.items():
        path = dest / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    git_status = "not-created"
    historic = None
    git = shutil.which("git")

    if git:
        try:
            subprocess.run(
                [git, "init"],
                cwd=dest,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                [git, "config", "user.email", "privacy-canary@example.invalid"],
                cwd=dest,
                check=True,
            )
            subprocess.run([git, "config", "user.name", "Privacy Canary"], cwd=dest, check=True)
            subprocess.run([git, "add", "."], cwd=dest, check=True)
            subprocess.run(
                [git, "commit", "-m", "privacy canary baseline"],
                cwd=dest,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            historic = "GIT_HISTORY_CANARY_" + secrets.token_hex(24)
            historic_file = dest / "historic-secret.txt"
            historic_file.write_text(historic + "\n", encoding="utf-8")
            subprocess.run([git, "add", "historic-secret.txt"], cwd=dest, check=True)
            subprocess.run(
                [git, "commit", "-m", "add synthetic historical secret"],
                cwd=dest,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            historic_file.unlink()
            subprocess.run([git, "add", "-u"], cwd=dest, check=True)
            subprocess.run(
                [git, "commit", "-m", "remove synthetic historical secret"],
                cwd=dest,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            git_status = "created-with-deleted-history-canary"
        except Exception as exc:
            git_status = f"git-error: {exc}"

    manifest = {
        "version": 1,
        "created_at": now_iso(),
        "workspace": short_path(dest),
        "canary_id": token,
        "fake_openai_key": fake_api,
        "fake_bearer_token": fake_bearer,
        "git_history_canary": historic,
        "git_status": git_status,
    }

    (dest / ".privacy-canary.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def hunt_canaries(
    token_file: Path, roots: Sequence[Path], max_file_bytes: int, max_files: int
) -> tuple[list[Finding], dict]:
    manifest = json.loads(token_file.read_text(encoding="utf-8"))
    needles = {
        "workspace_canary": manifest.get("canary_id"),
        "fake_openai_key": manifest.get("fake_openai_key"),
        "fake_bearer_token": manifest.get("fake_bearer_token"),
        "git_history_canary": manifest.get("git_history_canary"),
    }
    needles = {k: v for k, v in needles.items() if v}

    source_workspace = Path(manifest["workspace"]).resolve()
    findings = []
    scanned = 0
    hits = 0

    for root in roots:
        root = root.expanduser()
        if not root.exists():
            findings.append(Finding("LOW", "canary", "Hunt root does not exist", str(root)))
            continue

        for path in iter_files(root, max_files=max_files - scanned):
            scanned += 1
            if scanned > max_files:
                break
            try:
                resolved = path.resolve()
                if resolved == source_workspace or source_workspace in resolved.parents:
                    continue
                if path.stat().st_size > max_file_bytes:
                    continue

                data = path.read_bytes()
                for label, needle in needles.items():
                    if needle.encode("utf-8") not in data:
                        continue
                    hits += 1
                    severity = (
                        "CRITICAL"
                        if label in {"fake_openai_key", "fake_bearer_token", "git_history_canary"}
                        else "HIGH"
                    )
                    findings.append(
                        Finding(
                            severity,
                            "canary-copy",
                            f"Canary content copied outside test workspace ({label})",
                            f"Marker found in {short_path(path)}",
                            short_path(path),
                            recommendation="Identify the process or feature that created this file and determine whether it is staging, telemetry, indexing, or upload-related.",
                        )
                    )
            except (OSError, PermissionError):
                continue

    if hits == 0:
        findings.append(
            Finding(
                "INFO",
                "canary",
                "No plaintext canary copies found in selected roots",
                f"Scanned {scanned} file(s). Encrypted/compressed staging may not be detectable by plaintext hunt.",
                recommendation="Combine this test with runtime network inspection and OS-level tracing.",
            )
        )

    return dedupe_findings(findings), {
        "files_scanned": scanned,
        "hits": hits,
        "needles": list(needles),
    }
