# Contributing to HarnessGuard

HarnessGuard is intended to remain a practical, evidence-driven security research tool rather than a collection of noisy signatures.

## Development Setup

```bash
git clone https://github.com/YOUR_USERNAME/harnessguard.git
cd harnessguard
```

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev,runtime]"
```

### Windows

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev,runtime]"
```

Run tests:

```bash
pytest
```

Run linting:

```bash
ruff check .
```

## Contribution Principles

### Evidence over keyword matching

A single occurrence of `upload`, `snapshot`, `token`, or `fetch()` should rarely produce a severe finding.

Prefer correlated behavior:

```text
workspace enumeration
+
sensitive data access
+
staging
+
network upload
```

### Vendor neutrality

Rules must describe technical behavior, not vendor nationality, geography, or reputation.

### Explainability

Every finding should explain what was detected, why it matters, where it was detected, and what should be investigated next.

### False-positive awareness

New detection rules should document likely benign matches.

## Pull Requests

Include:

1. what changed;
2. why it changed;
3. security implications;
4. tests performed;
5. known limitations.

Do not commit real credentials, customer data, proprietary source code, or third-party secrets.
