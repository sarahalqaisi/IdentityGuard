"""Explainable authentication-event heuristics for synthetic data."""

from collections import defaultdict
from datetime import timedelta
from math import asin, cos, radians, sin, sqrt

from app.models import AuthAnomaly, AuthenticationEvent, IdentityDataset


def geographic_distance_km(first: AuthenticationEvent, second: AuthenticationEvent) -> float:
    radius = 6371.0
    lat1, lon1, lat2, lon2 = map(
        radians, (first.latitude, first.longitude, second.latitude, second.longitude)
    )
    dlat, dlon = lat2 - lat1, lon2 - lon1
    value = sin(dlat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
    return 2 * radius * asin(sqrt(value))


def impossible_travel(
    events: list[AuthenticationEvent], speed_threshold_kmh: float = 900.0
) -> list[AuthAnomaly]:
    successful = sorted(
        (event for event in events if event.result == "success"), key=lambda event: event.timestamp
    )
    anomalies: list[AuthAnomaly] = []
    for first, second in zip(successful, successful[1:]):
        if first.username != second.username:
            continue
        hours = (second.timestamp - first.timestamp).total_seconds() / 3600
        if hours <= 0:
            continue
        distance = geographic_distance_km(first, second)
        speed = distance / hours
        if distance > 100 and speed > speed_threshold_kmh:
            anomalies.append(
                AuthAnomaly(
                    rule_id="IG-AUTH-003",
                    username=first.username,
                    event_ids=[first.id, second.id],
                    risk_score=min(100, int(55 + speed / 100)),
                    explanation=(
                        f"Heuristic anomaly: {distance:.0f} km between successful synthetic logins "
                        f"in {hours:.2f} hours implies {speed:.0f} km/h."
                    ),
                )
            )
    return anomalies


def analyze_authentication(dataset: IdentityDataset) -> list[AuthAnomaly]:
    by_user: dict[str, list[AuthenticationEvent]] = defaultdict(list)
    for event in sorted(dataset.authentication_events, key=lambda item: item.timestamp):
        by_user[event.username].append(event)
    users = {user.username: user for user in dataset.users}
    anomalies: list[AuthAnomaly] = []
    for username, events in by_user.items():
        for index, event in enumerate(events):
            recent = [
                previous
                for previous in events[:index]
                if event.timestamp - timedelta(minutes=15) <= previous.timestamp < event.timestamp
            ]
            failures = [previous for previous in recent if previous.result == "failure"]
            if len(failures) >= 3 and event.result == "success":
                anomalies.append(
                    AuthAnomaly(
                        rule_id="IG-AUTH-002",
                        username=username,
                        event_ids=[item.id for item in failures[-3:]] + [event.id],
                        risk_score=65,
                        explanation="Heuristic anomaly: successful login followed at least three recent failures.",
                    )
                )
        successful = [event for event in events if event.result == "success"]
        known_devices: set[str] = set()
        for event in successful:
            if known_devices and event.device_id not in known_devices:
                anomalies.append(
                    AuthAnomaly(
                        rule_id="IG-AUTH-004",
                        username=username,
                        event_ids=[event.id],
                        risk_score=35,
                        explanation="Heuristic anomaly: successful synthetic login from a previously unseen device.",
                    )
                )
            known_devices.add(event.device_id)
        user = users.get(username)
        if user and user.account_type == "service":
            for event in successful:
                if event.interactive:
                    anomalies.append(
                        AuthAnomaly(
                            rule_id="IG-AUTH-007",
                            username=username,
                            event_ids=[event.id],
                            risk_score=72,
                            explanation="Heuristic anomaly: service account completed an interactive login.",
                        )
                    )
        anomalies.extend(impossible_travel(events))
    keys: set[tuple[str, str, tuple[str, ...]]] = set()
    result = []
    for anomaly in anomalies:
        key = (anomaly.rule_id, anomaly.username, tuple(anomaly.event_ids))
        if key not in keys:
            keys.add(key)
            result.append(anomaly)
    return sorted(result, key=lambda item: (-item.risk_score, item.rule_id, item.username))
