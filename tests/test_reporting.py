from harnessguard.models import Finding
from harnessguard.reporting import exit_code, score


def test_duplicate_component_does_not_inflate_score():
    m = {"component_id": "first_party:/same"}
    findings = [
        Finding("HIGH", "snapshot-upload", "A", "a", metadata=m, confidence="HIGH"),
        Finding("HIGH", "snapshot-upload", "B", "b", metadata=m, confidence="HIGH"),
        Finding("HIGH", "snapshot-upload", "C", "c", metadata=m, confidence="HIGH"),
    ]
    assert score(findings) == 8


def test_confidence_affects_score():
    hi = [
        Finding(
            "HIGH", "snapshot-upload", "A", "x", metadata={"component_id": "a"}, confidence="HIGH"
        )
    ]
    lo = [
        Finding(
            "HIGH", "snapshot-upload", "A", "x", metadata={"component_id": "a"}, confidence="LOW"
        )
    ]
    assert score(lo) < score(hi)


def test_exit_codes_unchanged():
    assert exit_code([Finding("HIGH", "x", "x", "x")]) == 1
    assert exit_code([Finding("CRITICAL", "x", "x", "x")]) == 2
