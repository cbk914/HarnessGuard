from __future__ import annotations

from pathlib import Path

from harnessguard.blocking import (
    SCOPE_DNS,
    SCOPE_LOCAL,
    SCOPE_NETWORK,
    SCOPE_SKIP,
    apply_local_hosts,
    build_plan,
    hosts_lines,
    prompt_plan,
    render_markdown,
    render_summary,
    write_firewall_script,
    write_hosts_file,
    write_pihole_list,
    write_unifi_list,
)

ENDPOINTS = [
    {
        "ip": "203.0.113.10",
        "port": 443,
        "protocol": "tcp",
        "hosts": ["agent.example.io"],
        "tls_names": [],
        "country_code": "US",
        "org": "Example Net",
    },
    {
        "ip": "203.0.113.11",
        "port": 443,
        "protocol": "tcp",
        "hosts": ["rum-openway.guance.com"],
        "tls_names": [],
        "country_code": "CN",
        "org": "Example Telemetry",
    },
    {
        "ip": "203.0.113.12",
        "port": 443,
        "protocol": "tcp",
        "hosts": ["auth.example.com"],
        "tls_names": [],
        "country_code": "ES",
        "org": "Example Net",
    },
    {
        "ip": "203.0.113.13",
        "port": 443,
        "protocol": "tcp",
        "hosts": ["cdn.example.com"],
        "tls_names": [],
        "country_code": "ES",
        "org": "Example Net",
    },
]


def test_build_plan_assigns_necessity_and_blockability():
    plans = build_plan(ENDPOINTS)
    by_ip = {p.ip: p for p in plans}
    assert by_ip["203.0.113.11"].necessity == "optional"
    assert by_ip["203.0.113.11"].blockable is True
    assert by_ip["203.0.113.12"].necessity == "feature"
    assert by_ip["203.0.113.12"].blockable is True
    assert by_ip["203.0.113.10"].blockable is False


def test_model_host_from_payload_records_becomes_core():
    plans = build_plan(
        ENDPOINTS, payload_records=[{"endpoint_host": "agent.example.io"}]
    )
    by_ip = {p.ip: p for p in plans}
    assert by_ip["203.0.113.10"].necessity == "core"
    assert by_ip["203.0.113.10"].blockable is False


def test_hosts_lines_only_contain_blockable_targets():
    lines = hosts_lines(build_plan(ENDPOINTS))
    assert "0.0.0.0 rum-openway.guance.com" in lines
    assert "0.0.0.0 auth.example.com" in lines
    assert not any("agent.example.io" in line for line in lines)


def test_summary_mentions_what_each_destination_does():
    text = render_summary(build_plan(ENDPOINTS))
    assert "rum-openway.guance.com" in text
    assert "NOT NECESSARY" in text
    assert "diagnostics" in text
    assert "sign-in" in text


def test_markdown_summary_has_table():
    text = render_markdown(build_plan(ENDPOINTS))
    assert "| Endpoint | Necessity | Role |" in text
    assert "rum-openway.guance.com" in text


def test_write_artifacts(tmp_path: Path):
    plans = build_plan(ENDPOINTS)
    pihole = tmp_path / "pihole.txt"
    assert write_pihole_list(pihole, plans) >= 2
    assert "0.0.0.0 rum-openway.guance.com" in pihole.read_text(encoding="utf-8")

    unifi = tmp_path / "unifi.txt"
    assert write_unifi_list(unifi, plans) >= 2
    assert "rum-openway.guance.com" in unifi.read_text(encoding="utf-8")

    firewall = tmp_path / "firewall.sh"
    assert write_firewall_script(firewall, plans) >= 2
    assert "203.0.113.11" in firewall.read_text(encoding="utf-8")


def test_prompt_plan_records_choices():
    """Every offered destination is decided on its own, whatever the order."""
    choices = {
        "cdn.example.com": "d",
        "rum-openway.guance.com": "l",
        "auth.example.com": "s",
    }
    written: list[str] = []

    def fake_read(prompt: str) -> str:
        for line in reversed(written):
            if "(" in line and line.rstrip().endswith(")"):
                host = line.split("(", 1)[1].rsplit(")", 1)[0].split(",")[0].strip()
                return choices[host]
        raise AssertionError("a destination was offered without a prompt")

    selection = prompt_plan(build_plan(ENDPOINTS), read=fake_read, write=written.append)

    assert selection[SCOPE_SKIP] == ["203.0.113.12"]
    assert selection[SCOPE_DNS] == ["cdn.example.com"]
    assert selection[SCOPE_LOCAL] == ["rum-openway.guance.com"]
    assert selection[SCOPE_NETWORK] == []


def test_apply_local_hosts_writes_entries(tmp_path: Path):
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")
    result = apply_local_hosts(build_plan(ENDPOINTS), hosts_path=hosts)
    assert result["written"] is True
    content = hosts.read_text(encoding="utf-8")
    assert "0.0.0.0 rum-openway.guance.com" in content
    assert "127.0.0.1 localhost" in content


def test_hosts_file_lists_only_blockable_destinations(tmp_path: Path):
    path = tmp_path / "hosts"
    count = write_hosts_file(path, build_plan(ENDPOINTS))
    content = path.read_text(encoding="utf-8")
    assert count == 3
    assert "0.0.0.0 auth.example.com" in content
    assert "0.0.0.0 cdn.example.com" in content
    assert "0.0.0.0 rum-openway.guance.com" in content
    assert "agent.example.io" not in content


def test_artifact_only_contains_the_selected_destinations(tmp_path: Path):
    """A scope applies what the operator chose, not every blockable target."""
    plans = build_plan(ENDPOINTS)
    pihole = tmp_path / "pihole.txt"
    write_pihole_list(pihole, plans, hosts=["cdn.example.com"])
    content = pihole.read_text(encoding="utf-8")
    assert "0.0.0.0 cdn.example.com" in content
    assert "rum-openway.guance.com" not in content
    assert "auth.example.com" not in content


def test_local_hosts_only_writes_the_selected_destinations(tmp_path: Path):
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")
    result = apply_local_hosts(
        build_plan(ENDPOINTS), hosts_path=hosts, hosts=["cdn.example.com"]
    )
    assert result["written"] is True
    content = hosts.read_text(encoding="utf-8")
    assert "0.0.0.0 cdn.example.com" in content
    assert "rum-openway.guance.com" not in content


def test_firewall_script_only_covers_the_selected_addresses(tmp_path: Path):
    path = tmp_path / "firewall.sh"
    count = write_firewall_script(
        path, build_plan(ENDPOINTS), addresses=["203.0.113.11"]
    )
    content = path.read_text(encoding="utf-8")
    assert count == 1
    assert "203.0.113.11" in content
    assert "203.0.113.12" not in content


def test_edge_name_is_not_a_block_target():
    plans = build_plan(
        [
            {
                "ip": "23.33.143.48",
                "port": 443,
                "protocol": "tcp",
                "hosts": [
                    "platform.example.io",
                    "a23-33-143-48.deploy.static.akamaitechnologies.com",
                ],
                "tls_names": [],
                "country_code": "ES",
                "org": "Example Edge",
            }
        ]
    )
    assert plans[0].block_targets() == ["platform.example.io"]


def test_shared_edge_destination_is_not_blockable():
    """The edge address also serves unrelated services, so it is never offered."""
    plans = build_plan(
        [
            {
                "ip": "104.90.205.224",
                "port": 443,
                "protocol": "tcp",
                "hosts": ["a104-90-205-224.deploy.static.akamaitechnologies.com"],
                "tls_names": [],
                "country_code": "ES",
                "org": "Example Edge",
            }
        ]
    )
    assert plans[0].role == "edge"
    assert plans[0].blockable is False


def test_declared_destination_is_not_reported_as_not_necessary():
    plans = build_plan(ENDPOINTS, declared_hosts=["rum-openway.guance.com"])
    by_ip = {p.ip: p for p in plans}
    assert by_ip["203.0.113.11"].necessity == "feature"
