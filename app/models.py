"""Typed, provider-neutral identity dataset and analysis models."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


Identifier = str
Sensitivity = Literal["low", "medium", "high", "critical"]
Severity = Literal["low", "medium", "high", "critical"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class User(StrictModel):
    id: Identifier = Field(min_length=1, max_length=64)
    username: str = Field(pattern=r"^[A-Za-z0-9._-]+$", max_length=128)
    display_name: str = Field(min_length=1, max_length=200)
    department: str = Field(min_length=1, max_length=100)
    account_type: Literal["human", "service"] = "human"
    enabled: bool = True
    privileged: bool = False
    mfa_enabled: bool = False
    last_login: datetime | None = None
    created_at: datetime


class Group(StrictModel):
    id: Identifier = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=500)


class Role(StrictModel):
    id: Identifier = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=128)
    privilege_level: int = Field(ge=0, le=10)
    description: str = Field(default="", max_length=500)


class Resource(StrictModel):
    id: Identifier = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=128)
    resource_type: str = Field(min_length=1, max_length=64)
    sensitivity: Sensitivity


class Permission(StrictModel):
    id: Identifier = Field(min_length=1, max_length=64)
    action: str = Field(min_length=1, max_length=128)
    resource_id: Identifier
    sensitivity: Sensitivity


class AuthenticationEvent(StrictModel):
    id: Identifier = Field(min_length=1, max_length=64)
    timestamp: datetime
    username: str = Field(min_length=1, max_length=128)
    source_ip: str = Field(min_length=1, max_length=45)
    country: str = Field(min_length=2, max_length=64)
    latitude: float = Field(ge=-90, le=90)
    longitude: float = Field(ge=-180, le=180)
    device_id: str = Field(min_length=1, max_length=128)
    result: Literal["success", "failure"]
    auth_method: str = Field(min_length=1, max_length=64)
    mfa_used: bool
    interactive: bool = True
    risk_metadata: dict[str, Any] = Field(default_factory=dict)


class Assignment(StrictModel):
    source_id: Identifier
    target_id: Identifier


class IdentityDataset(StrictModel):
    metadata: dict[str, Any] = Field(default_factory=dict)
    users: list[User]
    groups: list[Group]
    roles: list[Role]
    permissions: list[Permission]
    resources: list[Resource]
    user_groups: list[Assignment] = Field(default_factory=list)
    nested_groups: list[Assignment] = Field(default_factory=list)
    user_roles: list[Assignment] = Field(default_factory=list)
    group_roles: list[Assignment] = Field(default_factory=list)
    role_permissions: list[Assignment] = Field(default_factory=list)
    authentication_events: list[AuthenticationEvent] = Field(default_factory=list)

    @field_validator("metadata")
    @classmethod
    def require_synthetic_marker(cls, value: dict[str, Any]) -> dict[str, Any]:
        if value.get("synthetic") is not True:
            raise ValueError("datasets must explicitly set metadata.synthetic to true")
        return value


class Finding(StrictModel):
    id: str
    rule_id: str
    title: str
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    entity_id: str
    evidence: dict[str, Any]
    remediation: str
    fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    attack_techniques: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PrivilegePath(StrictModel):
    path_nodes: list[str]
    path_length: int = Field(ge=1)
    source_identity: str
    target_resource: str
    effective_privilege: int = Field(ge=0, le=10)
    inheritance_depth: int = Field(ge=0)
    why_risky: str


class AuthAnomaly(StrictModel):
    rule_id: str
    username: str
    event_ids: list[str]
    risk_score: int = Field(ge=0, le=100)
    explanation: str
    heuristic: bool = True


class AnalysisResult(StrictModel):
    generated_at: datetime
    dataset_source: Literal["synthetic"] = "synthetic"
    findings: list[Finding]
    attack_paths: list[PrivilegePath]
    auth_anomalies: list[AuthAnomaly]
    summary: dict[str, Any]
