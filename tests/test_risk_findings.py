from app.services.findings import finding_fingerprint
from app.services.risk import calculate_risk, severity_for


def test_risk_is_deterministic_bounded_and_monotonic():
    baseline = calculate_risk(privilege_level=2)
    elevated = calculate_risk(privilege_level=9, sensitivity="critical", missing_mfa=True, broad_scope=True)
    assert baseline == calculate_risk(privilege_level=2)
    assert 0 <= baseline < elevated <= 100
    assert calculate_risk(privilege_level=99, sensitivity="critical", missing_mfa=True, inactivity_days=999, inheritance_depth=99, broad_scope=True, auth_anomaly=True, service_interactive=True) == 100


def test_severity_thresholds():
    assert [severity_for(value) for value in (0, 35, 65, 85)] == ["low", "medium", "high", "critical"]


def test_fingerprint_is_stable_and_distinct():
    first = finding_fingerprint("IG-IAM-001", "usr-1", {"role": "admin"})
    replay = finding_fingerprint("IG-IAM-001", "usr-1", {"role": "admin"})
    distinct_entity = finding_fingerprint("IG-IAM-001", "usr-2", {"role": "admin"})
    distinct_role = finding_fingerprint("IG-IAM-001", "usr-1", {"role": "audit"})
    assert first == replay
    assert len({first, distinct_entity, distinct_role}) == 3
