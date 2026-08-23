"""Facade composing graph, IAM, risk, and authentication services."""

from datetime import datetime, timezone

from app.models import AnalysisResult, IdentityDataset
from app.services.auth_analytics import analyze_authentication
from app.services.identity_graph import IdentityGraph
from app.services.rule_engine import evaluate_rules


def analyze(dataset: IdentityDataset) -> AnalysisResult:
    graph = IdentityGraph(dataset)
    paths = graph.all_paths()
    reference = dataset.metadata.get("reference_time")
    now = datetime.fromisoformat(reference) if isinstance(reference, str) else datetime.now(timezone.utc)
    findings = evaluate_rules(dataset, paths, now=now)
    anomalies = analyze_authentication(dataset)
    privileged = sum(user.privileged for user in dataset.users)
    mfa_users = sum(user.mfa_enabled for user in dataset.users)
    summary = {
        "synthetic": True,
        "total_identities": len(dataset.users),
        "privileged_identities": privileged,
        "mfa_coverage_percent": round(mfa_users / len(dataset.users) * 100, 1) if dataset.users else 0.0,
        "critical_findings": sum(item.severity == "critical" for item in findings),
        "high_findings": sum(item.severity == "high" for item in findings),
        "potential_access_paths": len(paths),
        "authentication_anomalies": len(anomalies),
        "sensitive_resources": sum(resource.sensitivity in {"high", "critical"} for resource in dataset.resources),
    }
    return AnalysisResult(
        generated_at=now,
        findings=findings,
        attack_paths=paths,
        auth_anomalies=anomalies,
        summary=summary,
    )
