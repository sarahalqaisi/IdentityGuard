#!/usr/bin/env python3
"""Validate deterministic seed data and all references for CI."""

from app.seed import demo_dataset
from app.services.analyzer import analyze
from app.services.importer import validate_references


first = demo_dataset()
second = demo_dataset()
validate_references(first)
assert first.model_dump_json() == second.model_dump_json()
first_result = analyze(first)
second_result = analyze(second)
assert [item.fingerprint for item in first_result.findings] == [item.fingerprint for item in second_result.findings]
assert first_result.summary == second_result.summary
assert first_result.model_dump_json() == second_result.model_dump_json()
print(f"Demo validation passed: {len(first.users)} identities, {len(first_result.findings)} findings")
