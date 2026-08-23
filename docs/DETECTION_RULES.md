# Detection Rules

These deterministic demonstration policies are not universal IAM standards.

| ID | Rule | Primary evidence |
|---|---|---|
| IG-IAM-001 | Privileged account without MFA | Privilege and MFA state |
| IG-IAM-002 | Dormant privileged account | At least 90 inactive days |
| IG-IAM-003 | Disabled account retaining active roles | Enabled state and direct roles |
| IG-IAM-004 | Excessive privilege for standard user | Effective privilege at least 7 |
| IG-IAM-005 | Service account with interactive login activity | Account type and successful event |
| IG-IAM-006 | High-sensitivity permission inherited through nested groups | Potential path and group depth |
| IG-IAM-007 | Conflicting privileged roles | At least two directly assigned roles at level 8+ |
| IG-IAM-008 | Stale account with sensitive access | At least 120 inactive days and sensitive path |
| IG-IAM-009 | Broad wildcard-style permission | Wildcard action or resource |
| IG-IAM-010 | Privileged access without recent legitimate use | At least 45 inactive days |

Authentication rules include success after repeated failures, impossible-travel-like activity, new devices, and interactive service-account activity. They are labeled heuristic anomalies and do not assert compromise.
