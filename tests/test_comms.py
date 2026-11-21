from __future__ import annotations

from harnessguard.comms import REFERENCED, SELF_DECLARED, UNATTRIBUTED
from harnessguard.geo import GeoRecord


def _connection(ip, port=443, samples=1):
    return {
        "pid": 10,
        "protocol": "tcp",
        "remote_ip": ip,
        "remote_port": port,
        "status": "ESTABLISHED",
        "samples": samples,
        "first_seen": "2026-01-01T00:00:00+00:00",
        "last_seen": "2026-01-01T00:00:05+00:00",
    }


def test_declared_endpoint_is_attributed(monkeypatch):
    import harnessguard.comms as comms

    monkeypatch.setattr(
        comms,
        "build_host_index",
        lambda hosts, ips: {"203.0.113.9": ["api.example.com"]},
    )
    endpoints = comms.attribute_endpoints(
        [_connection("203.0.113.9")],
        declared_hosts=["api.example.com"],
        harvested={},
    )
    assert endpoints[0]["attribution"] == SELF_DECLARED
    assert endpoints[0]["hosts"] == ["api.example.com"]


def test_undeclared_endpoint_stays_unattributed(monkeypatch):
    import harnessguard.comms as comms

    monkeypatch.setattr(comms, "build_host_index", lambda hosts, ips: {})
    endpoints = comms.attribute_endpoints(
        [_connection("198.51.100.4")], declared_hosts=["api.example.com"], harvested={}
    )
    assert endpoints[0]["attribution"] == UNATTRIBUTED


def test_geo_record_is_attached_to_endpoint(monkeypatch):
    import harnessguard.comms as comms

    monkeypatch.setattr(comms, "build_host_index", lambda hosts, ips: {})
    geo = {"198.51.100.4": GeoRecord(ip="198.51.100.4", country_code="AA", country="Elsewhere")}
    endpoints = comms.attribute_endpoints(
        [_connection("198.51.100.4")], declared_hosts=[], harvested={}, geo_records=geo
    )
    assert endpoints[0]["country_code"] == "AA"


def test_host_only_in_harness_files_is_referenced(monkeypatch):
    import harnessguard.comms as comms

    monkeypatch.setattr(
        comms,
        "build_host_index",
        lambda hosts, ips: {"198.51.100.4": ["telemetry.thirdparty.example"]},
    )
    endpoints = comms.attribute_endpoints(
        [_connection("198.51.100.4")],
        declared_hosts=["api.example.com"],
        harvested={"telemetry.thirdparty.example": ["/app/config.json"]},
    )
    assert endpoints[0]["attribution"] == REFERENCED


def test_scope_distinguishes_harness_from_descendants(monkeypatch):
    import harnessguard.comms as comms

    monkeypatch.setattr(comms, "build_host_index", lambda hosts, ips: {})
    root = _connection("198.51.100.4")
    root["pid"] = 10
    child = _connection("203.0.113.5")
    child["pid"] = 99
    endpoints = comms.attribute_endpoints(
        [root, child], declared_hosts=[], harvested={}, root_pids=[10]
    )
    scopes = {e["ip"]: e["scope"] for e in endpoints}
    assert scopes["198.51.100.4"] == "harness"
    assert scopes["203.0.113.5"] == "descendant"
