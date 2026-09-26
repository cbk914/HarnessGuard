from harnessguard.models import Finding
from harnessguard.reporting import exit_code, risk_label, score


def test_high_exit_code():
    findings = [Finding("HIGH", "test", "High", "test")]
    assert score(findings) >= 8
    assert exit_code(findings) == 1


def test_critical_exit_code():
    findings = [Finding("CRITICAL", "test", "Critical", "test")]
    assert exit_code(findings) == 2
    assert risk_label(score(findings)) in {"ELEVATED", "HIGH", "SEVERE"}
