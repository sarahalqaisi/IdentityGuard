"""Stable finding identity and replay deduplication."""

import hashlib
import json
from collections.abc import Iterable
from typing import Any

from app.models import Finding


def finding_fingerprint(
    rule_id: str, entity_id: str, evidence_key: dict[str, Any]
) -> str:
    canonical = json.dumps(
        {"rule_id": rule_id, "entity_id": entity_id, "evidence": evidence_key},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def deduplicate_findings(findings: Iterable[Finding]) -> list[Finding]:
    unique: dict[str, Finding] = {}
    for finding in findings:
        unique.setdefault(finding.fingerprint, finding)
    return sorted(unique.values(), key=lambda item: (-item.risk_score, item.rule_id, item.entity_id))
