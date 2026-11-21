from __future__ import annotations

import argparse
import dataclasses
import json
import os
import platform
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .canary import hunt_canaries, make_canary_workspace
from .comms import comms_audit
from .net_scan import find_pids
from .profiles import HarnessProfile, load_profile
from .reporting import (
    exit_code,
    print_endpoint_table,
    print_report,
    save_json,
    write_markdown_report,
)
from .runtime_scan import find_pids_by_name, runtime_audit
from .static_scan import audit_paths
from .utils import short_path

DEFAULT_MAX_TOTAL_FILES = 120_000


def add_common_scan_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--max-file-mb", type=int, default=16)
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_TOTAL_FILES)
    parser.add_argument("--workers", type=int, default=min(16, (os.cpu_count() or 4) + 4))
    parser.add_argument("--json", type=Path)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="harnessguard",
        description="Audit AI IDEs, coding agents, extensions, and harnesses for code/secret staging and egress indicators.",
    )
    parser.add_argument("--version", action="version", version=f"HarnessGuard {__version__}")

    subcommands = parser.add_subparsers(dest="command", required=True)

    audit = subcommands.add_parser(
        "audit", help="Static scan of source, installations, and application data"
    )
    audit.add_argument("paths", nargs="+", type=Path)
    audit.add_argument("--app-data", action="append", default=[], type=Path)
    add_common_scan_args(audit)

    runtime = subcommands.add_parser(
        "runtime", help="Inspect outbound connections for a running process"
    )
    target = runtime.add_mutually_exclusive_group(required=True)
    target.add_argument("--pid", type=int)
    target.add_argument("--process-name")
    runtime.add_argument("--watch", type=int, default=0)
    runtime.add_argument("--json", type=Path)

    network = subcommands.add_parser(
        "network",
        help="Map, attribute and classify the outbound communications of a harness",
    )
    network.add_argument("--pid", action="append", type=int, default=[])
    network.add_argument("--process-name", action="append", default=[])
    network.add_argument("--profile", type=Path)
    network.add_argument("--watch", type=int, default=60)
    network.add_argument("--interval", type=float, default=1.0)
    network.add_argument("--declared-host", action="append", default=[])
    network.add_argument("--app-data", action="append", default=[], type=Path)
    network.add_argument("--max-file-mb", type=int, default=16)
    network.add_argument(
        "--geoip",
        action="store_true",
        help="Resolve jurisdiction and network owner for observed addresses (network call)",
    )
    network.add_argument("--geo-endpoint")
    network.add_argument("--geo-cache", type=Path)
    network.add_argument(
        "--tls-names",
        action="store_true",
        help="Read the TLS certificate of unattributed endpoints to improve attribution",
    )
    network.add_argument("--markdown", type=Path)
    network.add_argument("--json", type=Path)

    canary = subcommands.add_parser(
        "canary", help="Create a synthetic repository containing fake secrets and canaries"
    )
    canary.add_argument("destination", type=Path)
    canary.add_argument("--json", type=Path)

    hunt = subcommands.add_parser(
        "hunt", help="Hunt app-data/cache locations for copied canary markers"
    )
    hunt.add_argument("--token-file", required=True, type=Path)
    hunt.add_argument("--root", action="append", required=True, type=Path)
    add_common_scan_args(hunt)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "audit":
            roots = list(args.paths) + list(args.app_data)
            findings, stats = audit_paths(
                roots,
                max(1, args.max_file_mb) * 1024 * 1024,
                max(1, args.max_files),
                max(1, args.workers),
            )
            metadata = {
                "mode": "audit",
                "roots": [short_path(p) for p in roots],
                "stats": dataclasses.asdict(stats),
                "platform": platform.platform(),
                "python": sys.version,
            }
            print_report(findings, metadata, __version__)
            if args.json:
                save_json(args.json, findings, metadata, __version__)
            return exit_code(findings)

        if args.command == "runtime":
            if args.pid is not None:
                pid = args.pid
            else:
                pids = find_pids_by_name(args.process_name)
                if not pids:
                    print(f"No process matched: {args.process_name}", file=sys.stderr)
                    return 3
                pid = pids[0]

            findings, runtime_metadata = runtime_audit(pid, max(0, args.watch))
            metadata = {
                "mode": "runtime",
                "platform": platform.platform(),
                **runtime_metadata,
            }
            print_report(findings, metadata, __version__)
            if args.json:
                save_json(args.json, findings, metadata, __version__)
            return exit_code(findings)

        if args.command == "network":
            profile = load_profile(args.profile) if args.profile else HarnessProfile()

            pids: list[int] = list(args.pid)
            if args.process_name:
                pids.extend(find_pids(list(args.process_name), regex=False))
            if profile.process_patterns:
                pids.extend(find_pids(list(profile.process_patterns), regex=profile.regex))
            pids = sorted(set(pids))

            if not pids:
                print(
                    "No process matched. Use --pid, --process-name or --profile with "
                    "process_patterns.",
                    file=sys.stderr,
                )
                return 3

            declared = list(args.declared_host) + list(profile.declared_hosts)
            app_data = [Path(p) for p in args.app_data] + [
                Path(p) for p in profile.app_data_paths
            ]

            findings, comms_metadata = comms_audit(
                pids,
                watch=max(0, args.watch),
                interval=args.interval,
                declared_hosts=declared,
                app_data_paths=app_data,
                declared_jurisdictions=profile.declared_jurisdictions,
                geoip=args.geoip,
                geo_endpoint=args.geo_endpoint,
                geo_cache_path=args.geo_cache,
                probe_tls_names=args.tls_names,
                max_file_bytes=max(1, args.max_file_mb) * 1024 * 1024,
            )

            endpoints = comms_metadata.get("endpoints", [])
            metadata = {
                "mode": "network",
                "platform": platform.platform(),
                "profile": profile.name,
                **comms_metadata,
            }
            print_report(findings, metadata, __version__)
            print_endpoint_table(endpoints)
            if args.markdown:
                write_markdown_report(args.markdown, findings, metadata, endpoints, __version__)
            if args.json:
                save_json(args.json, findings, metadata, __version__)
            return exit_code(findings)

        if args.command == "canary":
            manifest = make_canary_workspace(args.destination.expanduser())
            print(json.dumps(manifest, indent=2))
            if args.json:
                args.json.parent.mkdir(parents=True, exist_ok=True)
                args.json.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            return 0

        if args.command == "hunt":
            findings, hunt_metadata = hunt_canaries(
                args.token_file.expanduser(),
                [p.expanduser() for p in args.root],
                max(1, args.max_file_mb) * 1024 * 1024,
                max(1, args.max_files),
            )
            metadata = {
                "mode": "hunt",
                "token_file": short_path(args.token_file),
                "roots": [short_path(p) for p in args.root],
                **hunt_metadata,
            }
            print_report(findings, metadata, __version__)
            if args.json:
                save_json(args.json, findings, metadata, __version__)
            return exit_code(findings)

        return 3

    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
