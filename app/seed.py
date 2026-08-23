"""Deterministic, entirely synthetic IdentityGuard demonstration dataset."""

from datetime import datetime, timedelta, timezone

from app.models import (
    Assignment,
    AuthenticationEvent,
    Group,
    IdentityDataset,
    Permission,
    Resource,
    Role,
    User,
)


SEED = 20250823
REFERENCE_TIME = datetime(2025, 1, 15, 12, 0, tzinfo=timezone.utc)


def demo_dataset() -> IdentityDataset:
    now = REFERENCE_TIME
    return IdentityDataset(
        metadata={"synthetic": True, "seed": SEED, "reference_time": now.isoformat(), "organization": "Example Research Campus"},
        users=[
            User(id="usr-alex", username="alex.demo", display_name="Alex Demo", department="Research", enabled=True, privileged=False, mfa_enabled=True, last_login=now - timedelta(days=2), created_at=now - timedelta(days=500)),
            User(id="usr-riley", username="riley.demo", display_name="Riley Demo", department="Finance", enabled=True, privileged=True, mfa_enabled=False, last_login=now - timedelta(days=140), created_at=now - timedelta(days=800)),
            User(id="usr-casey", username="casey.demo", display_name="Casey Demo", department="Operations", enabled=False, privileged=True, mfa_enabled=True, last_login=now - timedelta(days=180), created_at=now - timedelta(days=900)),
            User(id="usr-svc", username="svc-reports", display_name="Synthetic Reporting Service", department="Platform", account_type="service", enabled=True, privileged=True, mfa_enabled=False, last_login=now - timedelta(hours=1), created_at=now - timedelta(days=300)),
            User(id="usr-jordan", username="jordan.demo", display_name="Jordan Demo", department="Support", enabled=True, privileged=False, mfa_enabled=True, last_login=now - timedelta(days=1), created_at=now - timedelta(days=250)),
        ],
        groups=[
            Group(id="grp-staff", name="All Staff", description="Synthetic standard employee group"),
            Group(id="grp-ops", name="Operations Nested", description="Nested access group"),
            Group(id="grp-sensitive", name="Sensitive Data Readers", description="Sensitive resource access group"),
        ],
        roles=[
            Role(id="role-reader", name="Standard Reader", privilege_level=2),
            Role(id="role-sensitive", name="Sensitive Data Administrator", privilege_level=8),
            Role(id="role-global", name="Global Administrator", privilege_level=10),
            Role(id="role-audit", name="Audit Administrator", privilege_level=9),
        ],
        resources=[
            Resource(id="res-wiki", name="Internal Knowledge Base", resource_type="application", sensitivity="medium"),
            Resource(id="res-payroll", name="Synthetic Payroll Vault", resource_type="database", sensitivity="critical"),
            Resource(id="res-control", name="Identity Control Plane", resource_type="service", sensitivity="critical"),
        ],
        permissions=[
            Permission(id="perm-read", action="read", resource_id="res-wiki", sensitivity="medium"),
            Permission(id="perm-payroll", action="admin", resource_id="res-payroll", sensitivity="critical"),
            Permission(id="perm-wildcard", action="*", resource_id="res-control", sensitivity="critical"),
        ],
        user_groups=[Assignment(source_id="usr-alex", target_id="grp-staff"), Assignment(source_id="usr-jordan", target_id="grp-staff")],
        nested_groups=[Assignment(source_id="grp-staff", target_id="grp-ops"), Assignment(source_id="grp-ops", target_id="grp-sensitive")],
        user_roles=[
            Assignment(source_id="usr-riley", target_id="role-global"),
            Assignment(source_id="usr-riley", target_id="role-audit"),
            Assignment(source_id="usr-casey", target_id="role-sensitive"),
            Assignment(source_id="usr-svc", target_id="role-global"),
        ],
        group_roles=[Assignment(source_id="grp-sensitive", target_id="role-sensitive")],
        role_permissions=[
            Assignment(source_id="role-reader", target_id="perm-read"),
            Assignment(source_id="role-sensitive", target_id="perm-payroll"),
            Assignment(source_id="role-global", target_id="perm-wildcard"),
            Assignment(source_id="role-audit", target_id="perm-payroll"),
        ],
        authentication_events=[
            AuthenticationEvent(id="evt-1", timestamp=now - timedelta(hours=3), username="riley.demo", source_ip="192.0.2.10", country="Jordan", latitude=31.95, longitude=35.91, device_id="device-a", result="success", auth_method="password", mfa_used=False),
            AuthenticationEvent(id="evt-2", timestamp=now - timedelta(hours=2), username="riley.demo", source_ip="198.51.100.20", country="United States", latitude=40.71, longitude=-74.01, device_id="device-b", result="success", auth_method="password", mfa_used=False),
            AuthenticationEvent(id="evt-3", timestamp=now - timedelta(minutes=14), username="svc-reports", source_ip="203.0.113.7", country="Jordan", latitude=31.95, longitude=35.91, device_id="runner-1", result="failure", auth_method="password", mfa_used=False),
            AuthenticationEvent(id="evt-4", timestamp=now - timedelta(minutes=10), username="svc-reports", source_ip="203.0.113.7", country="Jordan", latitude=31.95, longitude=35.91, device_id="runner-1", result="failure", auth_method="password", mfa_used=False),
            AuthenticationEvent(id="evt-5", timestamp=now - timedelta(minutes=7), username="svc-reports", source_ip="203.0.113.7", country="Jordan", latitude=31.95, longitude=35.91, device_id="runner-1", result="failure", auth_method="password", mfa_used=False),
            AuthenticationEvent(id="evt-6", timestamp=now - timedelta(minutes=2), username="svc-reports", source_ip="203.0.113.7", country="Jordan", latitude=31.95, longitude=35.91, device_id="runner-1", result="success", auth_method="password", mfa_used=False, interactive=True),
        ],
    )
