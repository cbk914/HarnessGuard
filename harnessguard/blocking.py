from __future__ import annotations

import os
import platform
from dataclasses import dataclass, field
from pathlib import Path

from .endpoint_roles import (
    CORE,
    FEATURE,
    OPTIONAL,
    ROLE_ANALYTICS,
    ROLE_AUTHENTICATION,
    ROLE_CDN,
    ROLE_EDGE,
    ROLE_MODEL_API,
    ROLE_ORDER,
    ROLE_PLATFORM,
    ROLE_PROFILE,
    ROLE_STORAGE,
    ROLE_STREAMING,
    ROLE_TELEMETRY,
    ROLE_UNKNOWN,
    ROLE_UPDATE,
    classify_endpoint,
    describe,
    is_edge_host,
)

DATA_RECEIVED = {
    ROLE_MODEL_API: "prompts, tool schemas and conversation content",
    ROLE_STREAMING: "the request context and the model answer",
    ROLE_AUTHENTICATION: "sign-in credentials and session tokens",
    ROLE_STORAGE: "uploaded files, attachments and generated artefacts",
    ROLE_UPDATE: "version, platform and update metadata",
    ROLE_PLATFORM: "harness configuration, entitlements and extension calls",
    ROLE_CDN: "requests only, no harness state",
    ROLE_EDGE: "requests to a shared address; the service behind it is not identified",
    ROLE_TELEMETRY: "session identifiers, error reports, stack traces, resource and timing data",
    ROLE_ANALYTICS: "navigation events, session identifiers, interaction names, page URLs",
    ROLE_UNKNOWN: "unknown payload",
}


@dataclass
class EndpointPlan:
    ip: str
    port: int
    protocol: str
    hosts: list[str]
    role: str
    necessity: str
    reason: str
    what_it_does: str
    data_received: str
    blockable: bool
    jurisdiction: str | None = None
    org: str | None = None
    notes: list[str] = field(default_factory=list)

    def label(self) -> str:
        base = f"{self.ip}:{self.port}/{self.protocol}"
        if self.hosts:
            return base + " (" + ", ".join(self.hosts[:2]) + ")"
        return base

    def service_hosts(self) -> list[str]:
        """Hostnames that identify a service.

        Shared edge names are excluded: they identify the operator of the
        edge rather than the service, so blocking one of them would be both
        meaningless and misleading.
        """
        names = []
        for host in self.hosts:
            if host not in names and not is_edge_host(host):
                names.append(host)
        return names

    def block_targets(self) -> list[str]:
        """Names that can be used to block this endpoint."""
        return self.service_hosts()


def build_plan(
    endpoints: list[dict],
    payload_records: list[dict] | None = None,
    essential_hosts: list[str] | None = None,
    declared_hosts: list[str] | None = None,
) -> list[EndpointPlan]:
    """Turn observed endpoints into an actionable plan."""
    model_hosts = []
    for record in payload_records or []:
        host = str(record.get("endpoint_host") or "")
        if host and host not in model_hosts:
            model_hosts.append(host)

    plans: list[EndpointPlan] = []
    for endpoint in endpoints:
        hosts = list(endpoint.get("hosts") or [])
        tls_names = list(endpoint.get("tls_names") or [])
        role, classified, reason = classify_endpoint(
            hosts,
            tls_names=tls_names,
            essential_hosts=essential_hosts or [],
            declared_hosts=declared_hosts or [],
            model_hosts=model_hosts,
        )

        necessity, _description, blockable_default = ROLE_PROFILE.get(
            role, ROLE_PROFILE[ROLE_UNKNOWN]
        )
        if classified == FEATURE and necessity == OPTIONAL:
            # The harness declares this destination, so it may be expected.
            necessity = FEATURE
        if role in (ROLE_MODEL_API, ROLE_STREAMING):
            necessity = CORE
            blockable_default = False

        plans.append(
            EndpointPlan(
                ip=str(endpoint.get("ip")),
                port=int(endpoint.get("port") or 0),
                protocol=str(endpoint.get("protocol") or "tcp"),
                hosts=hosts,
                role=role,
                necessity=necessity,
                reason=reason,
                what_it_does=describe(role),
                data_received=DATA_RECEIVED.get(role, DATA_RECEIVED[ROLE_UNKNOWN]),
                blockable=blockable_default and necessity != CORE,
                jurisdiction=endpoint.get("country_code"),
                org=endpoint.get("org"),
            )
        )

    order = {CORE: 0, FEATURE: 1, OPTIONAL: 2}
    plans.sort(
        key=lambda p: (
            order.get(p.necessity, 3),
            ROLE_ORDER.index(p.role) if p.role in ROLE_ORDER else 9,
            p.ip,
        )
    )
    return plans


def render_summary(plans: list[EndpointPlan]) -> str:
    """Human readable summary of what was detected and what it does."""
    lines = ["", "Communication summary", "=" * 21, ""]
    if not plans:
        lines.append("No external endpoint was observed during the sampling window.")
        return "\n".join(lines)

    counts = {"core": 0, "feature": 0, "optional": 0}
    for plan in plans:
        counts[plan.necessity] = counts.get(plan.necessity, 0) + 1

    lines.append(
        f"{len(plans)} external endpoint(s) detected: "
        f"{counts['core']} strictly necessary, {counts['feature']} needed only for one feature, "
        f"{counts['optional']} not needed for the harness to work."
    )
    lines.append("")

    groups = [
        (CORE, "STRICTLY NECESSARY", "the harness cannot work without it"),
        (
            FEATURE,
            "FEATURE-DEPENDENT",
            "only needed for one capability; blocking it disables that capability",
        ),
        (
            OPTIONAL,
            "NOT NECESSARY",
            "telemetry or analytics; blocking it does not remove any capability",
        ),
    ]
    for necessity, title, note in groups:
        selected = [p for p in plans if p.necessity == necessity]
        if not selected:
            continue
        lines.append(f"{title} - {note}")
        lines.append("-" * len(title))
        for plan in selected:
            lines.append(f"  {plan.label()}")
            lines.append(f"      role         : {plan.role}")
            lines.append(f"      what it does : {plan.what_it_does}")
            lines.append(f"      it receives  : {plan.data_received}")
            if plan.jurisdiction or plan.org:
                owner = plan.org or "unknown owner"
                place = plan.jurisdiction or "unknown"
                lines.append(f"      network      : {owner} ({place})")
            lines.append(f"      why          : {plan.reason}")
            if plan.blockable:
                targets = ", ".join(plan.block_targets()) or plan.ip
                lines.append(f"      blockable    : yes ({targets})")
            else:
                lines.append("      blockable    : no")
            lines.append("")
    return "\n".join(lines)


def render_markdown(plans: list[EndpointPlan]) -> str:
    """Markdown summary for a report file."""
    lines = ["# Communication summary", ""]
    if not plans:
        lines.append("No external endpoint was observed during the sampling window.")
        return "\n".join(lines)

    lines.append("| Endpoint | Necessity | Role | What it does | It receives | Network |")
    lines.append("|---|---|---|---|---|---|")
    for plan in plans:
        owner = plan.org or "-"
        place = plan.jurisdiction or "-"
        lines.append(
            f"| {plan.label()} | {plan.necessity} | {plan.role} | {plan.what_it_does} | "
            f"{plan.data_received} | {owner} ({place}) |"
        )
    lines.append("")

    blockable = [p for p in plans if p.blockable]
    if blockable:
        lines.append("## Blockable destinations")
        lines.append("")
        for plan in blockable:
            lines.append(f"- {plan.label()} - {plan.what_it_does}")
            lines.append(f"  - reason: {plan.reason}")
            lines.append(f"  - receives: {plan.data_received}")
        lines.append("")
    return "\n".join(lines)


def _blockable_plans(plans: list[EndpointPlan]) -> list[EndpointPlan]:
    return [p for p in plans if p.blockable and p.block_targets()]


def blockable_hosts(plans: list[EndpointPlan], hosts: list[str] | None = None) -> list[str]:
    """Hostnames to block.

    When `hosts` is given, only those hostnames are used. This keeps an
    artifact limited to what the operator selected, instead of everything the
    tool could have blocked.
    """
    if hosts is not None:
        return [host for host in dict.fromkeys(hosts) if host]
    names: list[str] = []
    for plan in _blockable_plans(plans):
        for host in plan.block_targets():
            if host not in names:
                names.append(host)
    return names


def hosts_lines(plans: list[EndpointPlan], hosts: list[str] | None = None) -> list[str]:
    lines = []
    for host in blockable_hosts(plans, hosts):
        lines.append(f"0.0.0.0 {host}")
    return lines


def write_hosts_file(path: Path, plans: list[EndpointPlan], hosts: list[str] | None = None) -> int:
    """Write a hosts file with the blockable destinations."""
    path = Path(path)
    lines = hosts_lines(plans, hosts)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(lines)


def write_pihole_list(path: Path, plans: list[EndpointPlan], hosts: list[str] | None = None) -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    header = [
        "# Privacy blocklist for the harness under audit",
        "# Format: hosts entries, ready for /etc/pihole/hosts.d/",
        "# Destinations that are not strictly necessary for the harness to work.",
        "",
    ]
    body = hosts_lines(plans, hosts)
    path.write_text("\n".join(header + body) + "\n", encoding="utf-8")
    return len(body)


def write_unifi_list(path: Path, plans: list[EndpointPlan], hosts: list[str] | None = None) -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    body = blockable_hosts(plans, hosts)
    path.write_text("\n".join(body) + "\n", encoding="utf-8")
    return len(body)


def write_firewall_script(
    path: Path,
    plans: list[EndpointPlan],
    addresses: list[str] | None = None,
) -> int:
    """Write a ready to run firewall script for the observed addresses."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if addresses is not None:
        targets = sorted({str(address) for address in addresses if address})
    else:
        targets = sorted({plan.ip for plan in _blockable_plans(plans)})
    if platform.system() == "Windows":
        lines = [
            "# Outbound block for destinations that are not strictly necessary.",
            "# Run elevated in PowerShell. Review before running.",
            "",
        ]
        for address in targets:
            lines.append(
                'New-NetFirewallRule -DisplayName "Block egress '
                + address
                + '" -Direction Outbound -Action Block -Protocol TCP -RemoteAddress '
                + address
                + " -Profile Any"
            )
        lines += [
            "",
            "# Rollback:",
            "# Get-NetFirewallRule -DisplayName 'Block egress *' | Remove-NetFirewallRule",
        ]
    else:
        lines = [
            "#!/bin/sh",
            "# Outbound block for destinations that are not strictly necessary.",
            "# Review before running.",
            "",
        ]
        for address in targets:
            lines.append("iptables -A OUTPUT -d " + address + " -j REJECT")
        lines += ["", "# Rollback: iptables -D OUTPUT -d <address> -j REJECT"]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(targets)


def write_profile_skeleton(path: Path, plans: list[EndpointPlan]) -> int:
    """Write a harness profile skeleton derived from the observation."""
    import json

    path = Path(path)
    hosts = []
    for plan in plans:
        for host in plan.service_hosts():
            if host not in hosts:
                hosts.append(host)
    essential = [
        host for plan in plans if plan.necessity == CORE for host in plan.block_targets()
    ]
    profile = {
        "name": path.stem,
        "notes": "Generated from an observed run. Review before use.",
        "process_patterns": [],
        "regex": False,
        "declared_hosts": hosts,
        "essential_hosts": essential,
        "declared_jurisdictions": [],
        "app_data_paths": [],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    return len(hosts)


def default_hosts_path() -> Path:
    if platform.system() == "Windows":
        root = os.environ.get("SystemRoot", "C:\\Windows")
        return Path(root) / "System32" / "drivers" / "etc" / "hosts"
    return Path("/etc/hosts")


def apply_local_hosts(
    plans: list[EndpointPlan],
    hosts_path: Path | None = None,
    hosts: list[str] | None = None,
) -> dict:
    """Append the blockable destinations to the local hosts file.

    Returns a result dictionary instead of raising, so the caller can report
    what happened. A refused write leaves the file untouched and asks for an
    elevated run.
    """
    target = Path(hosts_path) if hosts_path else default_hosts_path()
    entries = hosts_lines(plans, hosts)
    if not entries:
        return {"written": False, "reason": "no blockable destination", "path": str(target)}

    marker = "# harnessguard privacy blocklist"
    try:
        existing = target.read_text(encoding="utf-8", errors="replace")
    except OSError:
        existing = ""

    if marker in existing:
        return {
            "written": False,
            "reason": "a harnessguard blocklist is already present",
            "path": str(target),
        }

    try:
        with target.open("a", encoding="utf-8") as handle:
            handle.write("\n" + marker + "\n")
            for entry in entries:
                handle.write(entry + "\n")
    except PermissionError:
        return {
            "written": False,
            "reason": "permission denied; run elevated or apply the generated script manually",
            "path": str(target),
            "entries": entries,
        }
    except OSError as exc:
        return {"written": False, "reason": str(exc), "path": str(target)}

    return {"written": True, "path": str(target), "entries": entries, "count": len(entries)}


SCOPE_SKIP = "skip"
SCOPE_LOCAL = "local"
SCOPE_DNS = "dns"
SCOPE_NETWORK = "network"


def prompt_plan(
    plans: list[EndpointPlan],
    read=None,
    write=None,
) -> dict:
    """Ask the operator, endpoint by endpoint, what should be blocked.

    The tool never blocks anything on its own: every destination is offered
    with its role, what it does and what it receives, and the operator chooses
    the scope. Returns a dictionary with the selected destinations per scope.
    """
    read = read or input
    write = write or print

    selection = {
        SCOPE_LOCAL: [],
        SCOPE_DNS: [],
        SCOPE_NETWORK: [],
        SCOPE_SKIP: [],
    }
    blockable = _blockable_plans(plans)
    if not blockable:
        write("No destination is offered for blocking.")
        return selection

    write("")
    write("Destinations offered for blocking (not strictly necessary for the harness):")
    write("")

    for plan in blockable:
        targets = ", ".join(plan.block_targets()) or plan.ip
        write(f"  {plan.label()}")
        write(f"    does    : {plan.what_it_does}")
        write(f"    receives: {plan.data_received}")
        write(f"    targets : {targets}")
        write(
            "    scope   : [l]ocal hosts file, [d]ns list, [n]etwork firewall, [s]kip"
        )
        try:
            answer = read("    choice: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = SCOPE_SKIP
        if answer in ("l", "local"):
            selection[SCOPE_LOCAL].extend(plan.block_targets() or [plan.ip])
        elif answer in ("d", "dns"):
            selection[SCOPE_DNS].extend(plan.block_targets() or [plan.ip])
        elif answer in ("n", "network"):
            selection[SCOPE_NETWORK].append(plan.ip)
        else:
            selection[SCOPE_SKIP].append(plan.ip)
        write("")

    return selection


def selection_counts(selection: dict) -> dict[str, int]:
    return {scope: len(values) for scope, values in selection.items()}
