"""Bounded local JSON import with referential-integrity validation."""

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from app.models import IdentityDataset


MAX_INPUT_BYTES = 2_000_000
MAX_RECORDS = 10_000


class DatasetImportError(ValueError):
    """Safe validation error suitable for CLI/API presentation."""


def _unique(records: list[Any], label: str) -> set[str]:
    identifiers = [record.id for record in records]
    if len(identifiers) != len(set(identifiers)):
        raise DatasetImportError(f"duplicate {label} identifiers are not allowed")
    return set(identifiers)


def validate_references(dataset: IdentityDataset) -> None:
    users = _unique(dataset.users, "user")
    groups = _unique(dataset.groups, "group")
    roles = _unique(dataset.roles, "role")
    permissions = _unique(dataset.permissions, "permission")
    resources = _unique(dataset.resources, "resource")
    _unique(dataset.authentication_events, "authentication event")
    username_set = {user.username for user in dataset.users}
    if len(username_set) != len(dataset.users):
        raise DatasetImportError("duplicate usernames are not allowed")

    def check(assignments, sources: set[str], targets: set[str], label: str) -> None:
        pairs: set[tuple[str, str]] = set()
        for item in assignments:
            pair = (item.source_id, item.target_id)
            if pair in pairs:
                raise DatasetImportError(f"duplicate {label} assignment")
            pairs.add(pair)
            if item.source_id not in sources or item.target_id not in targets:
                raise DatasetImportError(f"unknown reference in {label} assignment")

    check(dataset.user_groups, users, groups, "user-group")
    check(dataset.nested_groups, groups, groups, "nested-group")
    check(dataset.user_roles, users, roles, "user-role")
    check(dataset.group_roles, groups, roles, "group-role")
    check(dataset.role_permissions, roles, permissions, "role-permission")
    for permission in dataset.permissions:
        if permission.resource_id != "*" and permission.resource_id not in resources:
            raise DatasetImportError("unknown resource reference in permission")
    for event in dataset.authentication_events:
        if event.username not in username_set:
            raise DatasetImportError("authentication event references an unknown username")


def parse_dataset(raw: bytes) -> IdentityDataset:
    if len(raw) > MAX_INPUT_BYTES:
        raise DatasetImportError("dataset exceeds the 2 MB input limit")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DatasetImportError("dataset must be valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise DatasetImportError("dataset root must be a JSON object")
    count = sum(len(value) for value in payload.values() if isinstance(value, list))
    if count > MAX_RECORDS:
        raise DatasetImportError("dataset exceeds the 10,000-record limit")
    try:
        dataset = IdentityDataset.model_validate(payload)
    except ValidationError as exc:
        raise DatasetImportError("dataset does not match the supported identity schema") from exc
    validate_references(dataset)
    return dataset


def load_dataset(path: Path) -> IdentityDataset:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise DatasetImportError("dataset file could not be read") from exc
    if size > MAX_INPUT_BYTES:
        raise DatasetImportError("dataset exceeds the 2 MB input limit")
    try:
        return parse_dataset(path.read_bytes())
    except OSError as exc:
        raise DatasetImportError("dataset file could not be read") from exc
