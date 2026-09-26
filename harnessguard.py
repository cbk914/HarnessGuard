#!/usr/bin/env python3
"""Compatibility wrapper for running HarnessGuard directly from the repository."""

from harnessguard.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
