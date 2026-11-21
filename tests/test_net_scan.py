from __future__ import annotations

import json
from pathlib import Path

from harnessguard import net_scan


def test_public_endpoints_filters_private_and_loopback():
    connections = [
        {"remote_ip": "127.0.0.1", "remote_port": 51734},
        {"remote_ip": "10.0.0.5", "remote_port": 443},
        {"remote_ip": "192.168.1.20", "remote_port": 443},
        {"remote_ip": "93.184.216.34", "remote_port": 443},
    ]
    public = net_scan.public_endpoints(connections)
    assert [c["remote_ip"] for c in public] == ["93.184.216.34"]


def test_find_pids_matches_substring_and_regex(monkeypatch):
    table = {
        10: {"pid": 10, "ppid": 0, "name": "Harness.exe", "exe": "C:/h/Harness.exe", "cmdline": ""},
        11: {"pid": 11, "ppid": 0, "name": "node", "exe": "node", "cmdline": "srv --port 80"},
        12: {"pid": 12, "ppid": 0, "name": "other", "exe": "other", "cmdline": "nothing"},
    }
    monkeypatch.setattr(net_scan, "process_table", lambda: table)
    assert net_scan.find_pids(["harness"]) == [10]
    assert net_scan.find_pids([r"^srv\b"], regex=True) == [11]
    assert net_scan.find_pids(["absent"]) == []


def test_process_tree_includes_descendants(monkeypatch):
    table = {
        1: {"pid": 1, "ppid": 0, "name": "root", "exe": "", "cmdline": ""},
        2: {"pid": 2, "ppid": 1, "name": "child", "exe": "", "cmdline": ""},
        3: {"pid": 3, "ppid": 2, "name": "grandchild", "exe": "", "cmdline": ""},
        4: {"pid": 4, "ppid": 0, "name": "other", "exe": "", "cmdline": ""},
    }
    monkeypatch.setattr(net_scan, "process_table", lambda: table)
    assert net_scan.process_tree([1]) == {1, 2, 3}


def test_harvest_hosts_reads_declared_endpoints(tmp_path: Path):
    sample = tmp_path / "config.json"
    sample.write_text(
        json.dumps({"baseURL": "https://api.example.com/v1", "other": "http://cdn.example.org"}),
        encoding="utf-8",
    )
    hosts = net_scan.harvest_hosts([tmp_path])
    assert "api.example.com" in hosts
    assert "cdn.example.org" in hosts


def test_sample_connections_ignores_listeners_and_zero_ports(monkeypatch):
    def fake_collect(pids):
        return [
            {
                "pid": 1,
                "protocol": "tcp",
                "remote_ip": "203.0.113.9",
                "remote_port": 0,
                "status": "Bound",
            },
            {
                "pid": 1,
                "protocol": "tcp",
                "remote_ip": "203.0.113.10",
                "remote_port": 443,
                "status": "Listen",
            },
            {
                "pid": 1,
                "protocol": "tcp",
                "remote_ip": "203.0.113.11",
                "remote_port": 443,
                "status": "Established",
            },
        ]

    monkeypatch.setattr(net_scan, "collect_connections", fake_collect)
    monkeypatch.setattr(net_scan, "process_tree", lambda pids: set(pids))
    observed = net_scan.sample_connections([1], watch=0)
    assert [c["remote_ip"] for c in observed] == ["203.0.113.11"]


def test_build_host_index_maps_address_to_declared_host(monkeypatch):
    monkeypatch.setattr(net_scan, "resolve_hosts", lambda hosts: {"api.example.com": ["203.0.113.9"]})
    monkeypatch.setattr(net_scan, "reverse_dns", lambda ip: "edge.example.net")
    index = net_scan.build_host_index(["api.example.com"], ["203.0.113.9"])
    assert "api.example.com" in index["203.0.113.9"]
    assert "edge.example.net" in index["203.0.113.9"]
