"""Modular deterministic IAM rule engine."""

from datetime import datetime, timezone
from typing import Any

from app.models import Finding, IdentityDataset, PrivilegePath
from app.services.findings import deduplicate_findings, finding_fingerprint
from app.services.recommendations import recommendation_for
from app.services.risk import calculate_risk, severity_for


RULES = {
    "IG-IAM-001": "Privileged account without MFA",
    "IG-IAM-002": "Dormant privileged account",
    "IG-IAM-003": "Disabled account retaining active role assignments",
    "IG-IAM-004": "Excessive privilege for standard user",
    "IG-IAM-005": "Service account with interactive login activity",
    "IG-IAM-006": "High-sensitivity permission inherited through nested groups",
    "IG-IAM-007": "Conflicting privileged roles",
    "IG-IAM-008": "Stale account with sensitive access",
    "IG-IAM-009": "Broad wildcard-style permission",
    "IG-IAM-010": "Privileged access without recent legitimate use",
}


def _finding(rule_id: str, entity: str, evidence: dict[str, Any], score: int, key: dict[str, Any]) -> Finding:
    fingerprint = finding_fingerprint(rule_id, entity, key)
    return Finding(
        id=fingerprint[:16],
        rule_id=rule_id,
        title=RULES[rule_id],
        severity=severity_for(score),
        risk_score=score,
        entity_id=entity,
        evidence=evidence,
        remediation=recommendation_for(rule_id),
        fingerprint=fingerprint,
        attack_techniques=["T1078"] if rule_id in {"IG-IAM-001", "IG-IAM-002", "IG-IAM-005", "IG-IAM-010"} else [],
    )


def evaluate_rules(dataset: IdentityDataset, paths: list[PrivilegePath], now: datetime | None = None) -> list[Finding]:
    reference = now or datetime.now(timezone.utc)
    roles = {role.id: role for role in dataset.roles}
    permissions = {permission.id: permission for permission in dataset.permissions}
    direct_roles: dict[str, list[str]] = {}
    for item in dataset.user_roles:
        direct_roles.setdefault(item.source_id, []).append(item.target_id)
    paths_by_user: dict[str, list[PrivilegePath]] = {}
    for path in paths:
        paths_by_user.setdefault(path.source_identity, []).append(path)
    findings: list[Finding] = []
    successful_interactive = {
        event.username
        for event in dataset.authentication_events
        if event.result == "success" and event.interactive
    }
    for user in dataset.users:
        days = (reference - user.last_login).days if user.last_login else 9999
        assigned = direct_roles.get(user.id, [])
        assigned_levels = [roles[role].privilege_level for role in assigned if role in roles]
        effective_paths = paths_by_user.get(user.id, [])
        max_level = max(assigned_levels + [path.effective_privilege for path in effective_paths], default=0)
        if user.privileged and not user.mfa_enabled:
            score = calculate_risk(privilege_level=max_level, missing_mfa=True)
            findings.append(_finding("IG-IAM-001", user.id, {"mfa_enabled": False, "privilege_level": max_level}, score, {"mfa": False}))
        if user.privileged and days >= 90:
            score = calculate_risk(privilege_level=max_level, inactivity_days=days)
            findings.append(_finding("IG-IAM-002", user.id, {"inactive_days": days}, score, {"threshold": 90}))
        if not user.enabled and assigned:
            score = calculate_risk(privilege_level=max_level, sensitivity="high")
            findings.append(_finding("IG-IAM-003", user.id, {"role_ids": sorted(assigned)}, score, {"roles": sorted(assigned)}))
        if not user.privileged and max_level >= 7:
            score = calculate_risk(privilege_level=max_level, sensitivity="high")
            findings.append(_finding("IG-IAM-004", user.id, {"effective_privilege": max_level}, score, {"level": max_level}))
        if user.account_type == "service" and user.username in successful_interactive:
            score = calculate_risk(privilege_level=max_level, service_interactive=True)
            findings.append(_finding("IG-IAM-005", user.id, {"interactive_login": True}, score, {"interactive": True}))
        for path in effective_paths:
            if path.inheritance_depth >= 2:
                score = calculate_risk(privilege_level=path.effective_privilege, sensitivity="critical", inheritance_depth=path.inheritance_depth)
                findings.append(_finding("IG-IAM-006", user.id, {"path": path.path_nodes, "target": path.target_resource}, score, {"target": path.target_resource, "path": path.path_nodes}))
        privileged_roles = sorted(role for role in assigned if roles.get(role) and roles[role].privilege_level >= 8)
        if len(privileged_roles) >= 2:
            score = calculate_risk(privilege_level=10, sensitivity="high")
            findings.append(_finding("IG-IAM-007", user.id, {"conflicting_roles": privileged_roles}, score, {"roles": privileged_roles}))
        if days >= 120 and effective_paths:
            score = calculate_risk(privilege_level=max_level, sensitivity="high", inactivity_days=days)
            findings.append(_finding("IG-IAM-008", user.id, {"inactive_days": days, "sensitive_paths": len(effective_paths)}, score, {"targets": sorted(path.target_resource for path in effective_paths)}))
        if user.privileged and days >= 45:
            score = calculate_risk(privilege_level=max_level, inactivity_days=days)
            findings.append(_finding("IG-IAM-010", user.id, {"inactive_days": days}, score, {"threshold": 45}))
    for role_permission in dataset.role_permissions:
        permission = permissions.get(role_permission.target_id)
        if permission and (permission.action == "*" or permission.resource_id == "*"):
            score = calculate_risk(privilege_level=roles[role_permission.source_id].privilege_level, sensitivity=permission.sensitivity, broad_scope=True)
            findings.append(_finding("IG-IAM-009", role_permission.source_id, {"permission_id": permission.id, "action": permission.action}, score, {"permission": permission.id}))
    for finding in findings:
        finding.created_at = reference
    return deduplicate_findings(findings)


def coverage() -> list[dict[str, str]]:
    return [{"rule_id": rule_id, "title": title, "status": "implemented"} for rule_id, title in RULES.items()]
