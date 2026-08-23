# IdentityGuard Risk Model

IdentityGuard calculates a deterministic analytical score from 0 to 100. It is not CVSS, a probability of compromise, or a compliance score.

## Formula

```text
score = min(100,
    3 × privilege_level
  + sensitivity_weight
  + missing_MFA_weight
  + inactivity_weight
  + 3 × min(inheritance_depth, 4)
  + broad_scope_weight
  + authentication_anomaly_weight
  + interactive_service_account_weight)
```

| Factor | Weight |
|---|---:|
| Privilege level | 0–30 |
| Resource sensitivity: low / medium / high / critical | 0 / 8 / 16 / 24 |
| Missing MFA | 16 |
| Inactive 45–89 days / at least 90 days | 6 / 12 |
| Inheritance depth | 0–12 |
| Broad permission scope | 12 |
| Authentication anomaly | 12 |
| Interactive service-account use | 12 |

Severity bands are low (0–34), medium (35–64), high (65–84), and critical (85–100).

## Examples

- Privilege level 2, low sensitivity: `6`.
- Privilege level 8, critical resource, missing MFA: `64`.
- Multiple maximum-weight factors are capped at `100`.

## Assumptions and limitations

Weights are transparent project policy choices for prioritizing synthetic/demo findings. They are not calibrated against breach outcomes, real organizations, or an external standard. Deployments would require stakeholder-approved thresholds, entitlement context, asset criticality, compensating controls, and validation against local risk appetite.
