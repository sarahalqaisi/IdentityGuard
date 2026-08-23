from app.seed import REFERENCE_TIME, demo_dataset
from app.services.analyzer import analyze
from app.services.identity_graph import IdentityGraph
from app.services.rule_engine import RULES, evaluate_rules


def test_nested_potential_access_path_is_explainable():
    paths = IdentityGraph(demo_dataset()).paths_for_user("usr-alex")
    payroll = next(path for path in paths if path.target_resource == "res-payroll")
    assert payroll.path_nodes == ["usr-alex", "grp-staff", "grp-ops", "grp-sensitive", "role-sensitive", "perm-payroll", "res-payroll"]
    assert payroll.inheritance_depth == 3
    assert "Potential access path" in payroll.why_risky


def test_unknown_user_has_no_paths():
    assert IdentityGraph(demo_dataset()).paths_for_user("missing") == []


def test_rule_engine_covers_all_stable_rules_and_key_cases():
    dataset = demo_dataset()
    findings = evaluate_rules(dataset, IdentityGraph(dataset).all_paths(), REFERENCE_TIME)
    observed = {finding.rule_id for finding in findings}
    assert set(RULES) <= observed
    assert any(f.rule_id == "IG-IAM-001" and f.entity_id == "usr-riley" for f in findings)
    assert any(f.rule_id == "IG-IAM-002" and f.entity_id == "usr-riley" for f in findings)
    assert any(f.rule_id == "IG-IAM-005" and f.entity_id == "usr-svc" for f in findings)
    assert any(f.rule_id == "IG-IAM-006" and f.entity_id == "usr-alex" for f in findings)
    assert any("MFA" in f.remediation or "mfa" in f.remediation.lower() for f in findings if f.rule_id == "IG-IAM-001")


def test_replay_deduplication_is_deterministic():
    first = analyze(demo_dataset())
    second = analyze(demo_dataset())
    assert [finding.fingerprint for finding in first.findings] == [finding.fingerprint for finding in second.findings]
    assert len(first.findings) == len({finding.fingerprint for finding in first.findings})


def test_shared_role_and_high_impact_nodes():
    graph = IdentityGraph(demo_dataset())
    assert "role-sensitive" in graph.shared_sensitive_roles()
    assert graph.high_impact_nodes()
