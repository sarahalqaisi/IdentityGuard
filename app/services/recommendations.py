"""Explainable least-privilege recommendations; no changes are applied."""

RECOMMENDATIONS = {
    "IG-IAM-001": "Require phishing-resistant MFA before retaining privileged access.",
    "IG-IAM-002": "Disable the dormant account or remove privileged roles after owner review.",
    "IG-IAM-003": "Remove active role assignments from the disabled account.",
    "IG-IAM-004": "Replace the privileged role with the minimum scoped role required for current duties.",
    "IG-IAM-005": "Disable interactive authentication and use a workload-specific identity mechanism.",
    "IG-IAM-006": "Review the nested membership and remove inherited sensitive access where unnecessary.",
    "IG-IAM-007": "Separate conflicting administrative duties and require an approved elevation workflow.",
    "IG-IAM-008": "Disable or recertify the stale account and remove sensitive access until reviewed.",
    "IG-IAM-009": "Replace the wildcard permission with explicit resource and action scopes.",
    "IG-IAM-010": "Remove unused privileged access or require time-bound elevation.",
}


def recommendation_for(rule_id: str) -> str:
    return RECOMMENDATIONS[rule_id]
