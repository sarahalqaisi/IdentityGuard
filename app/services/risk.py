"""Deterministic 0-100 IdentityGuard risk model."""

from app.models import Sensitivity


SENSITIVITY_WEIGHT: dict[Sensitivity, int] = {
    "low": 0,
    "medium": 8,
    "high": 16,
    "critical": 24,
}


def calculate_risk(
    *,
    privilege_level: int = 0,
    sensitivity: Sensitivity = "low",
    missing_mfa: bool = False,
    inactivity_days: int = 0,
    inheritance_depth: int = 0,
    broad_scope: bool = False,
    auth_anomaly: bool = False,
    service_interactive: bool = False,
) -> int:
    score = min(max(privilege_level, 0), 10) * 3
    score += SENSITIVITY_WEIGHT[sensitivity]
    score += 16 if missing_mfa else 0
    score += 12 if inactivity_days >= 90 else 6 if inactivity_days >= 45 else 0
    score += min(max(inheritance_depth, 0), 4) * 3
    score += 12 if broad_scope else 0
    score += 12 if auth_anomaly else 0
    score += 12 if service_interactive else 0
    return min(score, 100)


def severity_for(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 35:
        return "medium"
    return "low"
