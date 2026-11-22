from __future__ import annotations

from harnessguard.endpoint_roles import (
    CORE,
    FEATURE,
    OPTIONAL,
    ROLE_ANALYTICS,
    ROLE_AUTHENTICATION,
    ROLE_CDN,
    ROLE_EDGE,
    ROLE_MODEL_API,
    ROLE_STORAGE,
    ROLE_TELEMETRY,
    ROLE_UNKNOWN,
    ROLE_UPDATE,
    classify_endpoint,
    classify_host,
)


def test_classify_host_by_label():
    assert classify_host("cdn.example.com")[0] == ROLE_CDN
    assert classify_host("auth.example.com")[0] == ROLE_AUTHENTICATION
    assert classify_host("files.example.com")[0] == ROLE_STORAGE
    assert classify_host("updates.example.com")[0] == ROLE_UPDATE
    assert classify_host("api.example.com")[0] == ROLE_UNKNOWN


def test_classify_host_by_known_provider():
    assert classify_host("rum-openway.guance.com")[0] == ROLE_TELEMETRY
    assert classify_host("static.sensorsdata.cn")[0] == ROLE_ANALYTICS
    assert classify_host("o123.ingest.sentry.io")[0] == ROLE_TELEMETRY


def test_essential_declaration_wins_over_heuristics():
    role, necessity, reason = classify_endpoint(
        ["telemetry.example.com"], essential_hosts=["telemetry.example.com"]
    )
    assert necessity == CORE
    assert "essential" in reason


def test_model_host_from_payloads_is_core():
    role, necessity, reason = classify_endpoint(
        ["api.example.com"], model_hosts=["api.example.com"]
    )
    assert role == ROLE_MODEL_API
    assert necessity == CORE
    assert "model endpoint" in reason


def test_declared_host_is_not_marked_optional():
    role, necessity, reason = classify_endpoint(
        ["telemetry.example.com"], declared_hosts=["telemetry.example.com"]
    )
    assert necessity == FEATURE
    assert "declares" in reason


def test_shared_edge_hostname_is_not_a_service_role():
    """A CDN edge name identifies the operator, not the service."""
    role, reason = classify_host("a104-90-205-224.deploy.static.akamaitechnologies.com")
    assert role == ROLE_EDGE
    assert "edge" in reason


def test_service_hostname_wins_over_an_edge_name():
    role, necessity, reason = classify_endpoint(
        ["a104-90-205-224.deploy.static.akamaitechnologies.com", "auth.example.com"]
    )
    assert role == ROLE_AUTHENTICATION


def test_declared_hostname_is_not_replaced_by_an_edge_name():
    """The edge name of the same address must not decide the role."""
    role, necessity, reason = classify_endpoint(
        ["agent.example.io", "a104-90-205-224.deploy.static.akamaitechnologies.com"],
        declared_hosts=["agent.example.io"],
    )
    assert role != ROLE_EDGE
    assert "edge" not in reason


def test_edge_only_endpoint_is_never_offered_for_blocking():
    role, necessity, reason = classify_endpoint(
        ["a23-33-143-48.deploy.static.akamaitechnologies.com"]
    )
    assert role == ROLE_EDGE
    assert necessity == FEATURE


def test_undetermined_telemetry_stays_optional():
    role, necessity, reason = classify_endpoint(["rum-openway.guance.com"])
    assert role == ROLE_TELEMETRY
    assert necessity == OPTIONAL
