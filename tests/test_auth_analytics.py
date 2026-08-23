from datetime import datetime, timedelta, timezone

from app.models import AuthenticationEvent
from app.seed import demo_dataset
from app.services.auth_analytics import analyze_authentication, impossible_travel


def event(identifier, hours, latitude, longitude, country="Testland"):
    return AuthenticationEvent(id=identifier, timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc) + timedelta(hours=hours), username="alex.demo", source_ip="192.0.2.1", country=country, latitude=latitude, longitude=longitude, device_id="device-a", result="success", auth_method="password", mfa_used=True)


def test_impossible_travel_clear_synthetic_case():
    anomalies = impossible_travel([event("a", 0, 31.95, 35.91), event("b", 1, 40.71, -74.01)])
    assert len(anomalies) == 1
    assert "Heuristic anomaly" in anomalies[0].explanation


def test_normal_travel_same_location_and_insufficient_data():
    assert impossible_travel([event("a", 0, 31.95, 35.91), event("b", 10, 32.0, 35.95)]) == []
    assert impossible_travel([event("a", 0, 31.95, 35.91), event("b", 1, 31.95, 35.91)]) == []
    assert impossible_travel([event("a", 0, 31.95, 35.91)]) == []


def test_demo_auth_rules_detect_failures_travel_and_service_login():
    rules = {item.rule_id for item in analyze_authentication(demo_dataset())}
    assert {"IG-AUTH-002", "IG-AUTH-003", "IG-AUTH-007"} <= rules
