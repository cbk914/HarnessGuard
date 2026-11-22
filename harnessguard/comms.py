from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from .geo import GeoRecord
from .geo import load_cache as load_geo_cache
from .geo import lookup as geo_lookup
from .geo import save_cache as save_geo_cache
from .models import Finding
from .net_scan import (
    build_host_index,
    harvest_hosts,
    public_endpoints,
    sample_connections,
    tls_certificate_names,
)
from .payload_evidence import scan_request_records
from .static_scan import dedupe_findings
from .utils import now_iso

SELF_DECLARED = "self_declared"
REFERENCED = "referenced"
UNATTRIBUTED = "unattributed"


def _classify_hosts(hosts: Sequence[str], declared: set[str], referenced: set[str]) -> str:
    """A destination is declared, referenced by the harness' own files, or unknown."""
    for host in hosts:
        if _host_matches(host, declared):
            return SELF_DECLARED
    for host in hosts:
        if _host_matches(host, referenced):
            return REFERENCED
    return UNATTRIBUTED


def _host_matches(host: str, declared: set[str]) -> bool:
    host = host.lower().strip(".")
    if host in declared:
        return True
    for candidate in declared:
        if host == candidate or host.endswith("." + candidate):
            return True
    return False


def attribute_endpoints(
    connections: Sequence[dict],
    declared_hosts: Sequence[str],
    harvested: dict[str, list[str]],
    geo_records: dict[str, GeoRecord] | None = None,
    tls_names: dict[str, list[str]] | None = None,
    root_pids: Sequence[int] = (),
) -> list[dict]:
    """Collapse sampled connections into one record per remote endpoint."""
    geo_records = geo_records or {}
    tls_names = tls_names or {}
    roots = {int(p) for p in root_pids}

    declared = {h.lower().strip(".") for h in declared_hosts if h and h.strip()}
    referenced = {h.lower().strip(".") for h in harvested if h and h.strip()}
    referenced -= declared

    ips = sorted({str(c.get("remote_ip") or "") for c in connections if c.get("remote_ip")})
    index = build_host_index(list(declared), ips)

    endpoints: dict[tuple, dict] = {}
    for connection in connections:
        ip = str(connection.get("remote_ip") or "")
        port = int(connection.get("remote_port") or 0)
        protocol = str(connection.get("protocol") or "tcp")
        key = (ip, port, protocol)

        record = endpoints.get(key)
        if record is None:
            hosts = list(index.get(ip, []))
            geo = geo_records.get(ip)
            record = {
                "ip": ip,
                "port": port,
                "protocol": protocol,
                "hosts": hosts,
                "tls_names": list(tls_names.get(ip, [])),
                "attribution": _classify_hosts(hosts, declared, referenced),
                "org": geo.org if geo else None,
                "asn": geo.asn if geo else None,
                "country_code": geo.country_code if geo else None,
                "country": geo.country if geo else None,
                "first_seen": connection.get("first_seen") or now_iso(),
                "last_seen": connection.get("last_seen") or now_iso(),
                "samples": 0,
                "pids": [],
                "scope": "harness" if int(connection.get("pid") or 0) in roots else "descendant",
                "status": connection.get("status"),
            }
            endpoints[key] = record

        record["samples"] = int(record.get("samples") or 0) + int(connection.get("samples") or 1)
        record["last_seen"] = connection.get("last_seen") or record["last_seen"]
        pid = connection.get("pid")
        if pid is not None and int(pid) not in record["pids"]:
            record["pids"].append(int(pid))
        if int(pid or 0) in roots:
            record["scope"] = "harness"
        for host in index.get(ip, []):
            if host not in record["hosts"]:
                record["hosts"].append(host)
            attribution = _classify_hosts(record["hosts"], declared, referenced)
            if attribution != UNATTRIBUTED:
                record["attribution"] = attribution
        if record["attribution"] == UNATTRIBUTED and geo_records.get(ip) is None:
            record["org"] = None

    return sorted(endpoints.values(), key=lambda e: (e["attribution"] != UNATTRIBUTED, e["ip"], e["port"]))


def comms_audit(
    pids: Sequence[int],
    watch: int = 60,
    interval: float = 1.0,
    declared_hosts: Sequence[str] = (),
    app_data_paths: Sequence[Path] = (),
    declared_jurisdictions: Sequence[str] = (),
    geoip: bool = False,
    geo_endpoint: str | None = None,
    geo_cache_path: Path | None = None,
    probe_tls_names: bool = False,
    max_file_bytes: int = 16 * 1024 * 1024,
) -> tuple[list[Finding], dict]:
    """Observe, attribute and classify the outbound traffic of a harness."""
    harvested: dict[str, list[str]] = {}
    if app_data_paths:
        harvested = harvest_hosts(list(app_data_paths), max_file_bytes=max_file_bytes)

    connections = sample_connections(pids, watch=watch, interval=interval)
    external = public_endpoints(connections)

    geo_records: dict[str, GeoRecord] = {}
    if geoip and external:
        cache = load_geo_cache(geo_cache_path) if geo_cache_path else {}
        kwargs = {"endpoint": geo_endpoint} if geo_endpoint else {}
        geo_records = geo_lookup(
            [str(c.get("remote_ip")) for c in external], cache=cache, **kwargs
        )
        if geo_cache_path:
            save_geo_cache(geo_cache_path, cache)

    endpoints = attribute_endpoints(
        external,
        declared_hosts=declared_hosts,
        harvested=harvested,
        geo_records=geo_records,
        root_pids=pids,
    )

    tls_names: dict[str, list[str]] = {}
    if probe_tls_names:
        for endpoint in endpoints:
            if endpoint["attribution"] == UNATTRIBUTED and endpoint["protocol"] == "tcp":
                names = tls_certificate_names(endpoint["ip"], endpoint["port"])
                if names:
                    tls_names[endpoint["ip"]] = names
                    endpoint["tls_names"] = names

    findings: list[Finding] = []
    declared_codes = {c.upper() for c in declared_jurisdictions if c}

    for endpoint in endpoints:
        label = f"{endpoint['ip']}:{endpoint['port']}/{endpoint['protocol']}"
        if endpoint["hosts"]:
            label += " (" + ", ".join(endpoint["hosts"][:3]) + ")"
        if endpoint["org"]:
            label += f" [{endpoint['org']}]"

        if endpoint["attribution"] == REFERENCED:
            findings.append(
                Finding(
                    "LOW",
                    "network-referenced-third-party",
                    "Destination referenced by the harness' own files is outside the declared endpoint set",
                    label,
                    confidence="LOW",
                    metadata={"component_id": f"endpoint:{endpoint['ip']}", "endpoint": endpoint},
                    recommendation=(
                        "The harness ships or references this destination even though it is not part "
                        "of the declared endpoint set. Confirm whether it is a bundled third-party "
                        "SDK and what it transmits."
                    ),
                )
            )

        if endpoint["attribution"] == UNATTRIBUTED:
            descendant = endpoint.get("scope") == "descendant"
            findings.append(
                Finding(
                    "LOW" if descendant else "MEDIUM",
                    "network-third-party-egress",
                    "Outbound connection to an endpoint not declared by the harness configuration"
                    + (" (from a descendant process)" if descendant else ""),
                    label,
                    confidence="LOW" if descendant else "MEDIUM",
                    metadata={"component_id": f"endpoint:{endpoint['ip']}", "endpoint": endpoint},
                    recommendation=(
                        "Identify the owner of this destination and confirm whether the harness documents "
                        "it. Check for a bundled telemetry or analytics SDK, and inspect whether the "
                        "destination carries session identifiers or request content."
                    ),
                )
            )

            if int(endpoint.get("samples") or 0) > 1:
                findings.append(
                    Finding(
                        "LOW",
                        "network-beacon-pattern",
                        "Recurring egress to the same endpoint during the sampling window",
                        f"{label}; observed {endpoint['samples']} samples between "
                        f"{endpoint['first_seen']} and {endpoint['last_seen']}",
                        confidence="LOW",
                        metadata={"component_id": f"endpoint:{endpoint['ip']}", "endpoint": endpoint},
                        recommendation=(
                            "Repeated short-lived connections to a non-declared host are consistent with a "
                            "heartbeat or telemetry beacon. Capture longer windows and compare the "
                            "interval against the harness' documented activity."
                        ),
                    )
                )

        country = endpoint.get("country_code")
        if country and declared_codes and country.upper() not in declared_codes:
            findings.append(
                Finding(
                    "MEDIUM",
                    "network-cross-jurisdiction-egress",
                    "Egress to an address registered outside the harness' declared operating jurisdictions",
                    f"{label}; registered in {country} ({endpoint.get('country')}), declared "
                    f"{', '.join(sorted(declared_codes))}",
                    confidence="LOW",
                    metadata={"component_id": f"endpoint:{endpoint['ip']}", "endpoint": endpoint},
                    recommendation=(
                        "Jurisdiction of the address is context, not a verdict: verify whether this "
                        "destination is documented for the harness and whether the data reaching it "
                        "would be acceptable under your data-handling policy."
                    ),
                )
            )

    payload_records, payload_stats = ([], {})
    if app_data_paths:
        payload_records, payload_stats = scan_request_records(
            list(app_data_paths), max_file_bytes=max_file_bytes
        )
        for record in payload_records:
            if not record.get("carries_user_text"):
                continue
            findings.append(
                Finding(
                    "INFO",
                    "network-payload-evidence",
                    "Harness persists the outbound request payload on disk",
                    f"{record['path']}: model={record.get('model') or 'n/a'}, "
                    f"endpoint={record.get('endpoint_host') or 'n/a'}, "
                    f"context~{record.get('context_bytes', 0)} bytes, "
                    f"tools={record.get('tool_count', 0)}",
                    confidence="HIGH",
                    metadata={"component_id": f"payload:{record['path']}", "payload": record},
                    recommendation=(
                        "This artefact mirrors what is sent to the model endpoint. Review it to confirm "
                        "exactly which prompt, tool schemas and conversation content leave the machine."
                    ),
                )
            )

    if not external:
        findings.append(
            Finding(
                "INFO",
                "network-egress",
                "No public outbound connection observed during the sampling window",
                f"pids={sorted(set(int(p) for p in pids))}; watch={watch}s. This does NOT prove the "
                "harness never sends data.",
                recommendation=(
                    "Exercise the harness (a real turn, a login, an update check) while running a "
                    "longer watch, and repeat the scan while the application is idle to catch beacons."
                ),
            )
        )

    metadata = {
        "pids": sorted(set(int(p) for p in pids)),
        "watch_seconds": watch,
        "interval_seconds": interval,
        "observed_connections": len(connections),
        "public_endpoints": len(endpoints),
        "declared_hosts": sorted({h.lower() for h in declared_hosts if h}),
        "declared_jurisdictions": sorted(declared_codes),
        "harvested_host_count": len(harvested),
        "harvested_hosts": sorted(h.lower() for h in harvested)[:200],
        "geoip_enabled": bool(geoip),
        "payload_evidence": payload_stats,
        "model_hosts": sorted(
            {str(r.get("endpoint_host")) for r in payload_records if r.get("endpoint_host")}
        ),
        "payload_records": [
            {
                key: record.get(key)
                for key in (
                    "path",
                    "model",
                    "endpoint_host",
                    "context_bytes",
                    "tool_count",
                    "carries_user_text",
                )
            }
            for record in payload_records[:50]
        ],
        "endpoints": endpoints,
        "generated_at": now_iso(),
    }
    return dedupe_findings(findings), metadata
