"""Regression tests for dashboard database insertion behavior."""

import sys
import os
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dashboard.database import LogDatabase


def _sample_log(ts: str, sequence: int = 1):
    return {
        "timestamp": ts,
        "agent": "test-agent",
        "sequence": sequence,
        "event_type": "HTTP_REQUEST",
        "severity": "INFO",
        "severity_score": 1,
        "source_ip": "10.0.1.10",
        "dest_ip": "10.0.1.11",
        "port": 80,
        "protocol": "HTTP",
        "user": "tester",
        "message": "GET /health HTTP/1.1 - 200",
        "bytes_transferred": 512,
        "status_code": 200,
        "url": "/health",
        "is_anomaly": False,
        "anomaly_score": 0.0,
        "ml_is_anomaly": False,
        "threat_type": "",
        "threat_level": "",
    }


def test_same_agent_sequence_with_new_timestamp_is_not_dropped(tmp_path):
    """A restarted agent should be able to reuse sequence values."""
    db = LogDatabase(db_path=str(tmp_path / "logs.db"))
    now = datetime.now(timezone.utc)

    first = _sample_log(now.isoformat(), sequence=1)
    second = _sample_log((now + timedelta(seconds=1)).isoformat(), sequence=1)

    db.insert_log(first)
    db.insert_log(second)

    stats = db.get_stats()
    assert stats["total_logs"] == 2


def test_exact_replay_is_deduplicated(tmp_path):
    """An exact replayed message should not be inserted twice."""
    db = LogDatabase(db_path=str(tmp_path / "logs.db"))
    ts = datetime.now(timezone.utc).isoformat()
    entry = _sample_log(ts, sequence=8)

    db.insert_log(entry)
    db.insert_log(entry)

    stats = db.get_stats()
    assert stats["total_logs"] == 1
