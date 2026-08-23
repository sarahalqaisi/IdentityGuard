from datetime import datetime, timezone

from sqlalchemy import select

from app.database import FindingRecord, create_session_factory


def test_sqlite_finding_fingerprint_is_unique(tmp_path):
    sessions = create_session_factory(f"sqlite:///{tmp_path / 'identityguard.db'}")
    record = FindingRecord(
        fingerprint="a" * 64,
        rule_id="IG-IAM-001",
        entity_id="usr-demo",
        risk_score=46,
        payload="{}",
        created_at=datetime.now(timezone.utc),
    )
    with sessions.begin() as session:
        session.add(record)
    with sessions() as session:
        stored = session.scalar(select(FindingRecord).where(FindingRecord.fingerprint == "a" * 64))
        assert stored is not None
        assert stored.rule_id == "IG-IAM-001"
