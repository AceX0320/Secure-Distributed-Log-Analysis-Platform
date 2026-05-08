"""Tests for the log parser and end-to-end pipeline."""

import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from processing.log_parser import LogParser
from agents.log_generator import SecurityLogGenerator
from processing.anomaly_detector import AnomalyDetector
from config.settings import FEATURE_COLUMNS


class TestLogParser:
    """Test suite for LogParser."""

    def test_parse_json_string(self):
        raw = json.dumps({"event_type": "HTTP_REQUEST", "severity": "INFO",
                          "source_ip": "10.0.1.1", "port": 80})
        result = LogParser.parse_log(raw)
        assert result is not None
        assert result["event_type"] == "HTTP_REQUEST"

    def test_parse_dict(self):
        raw = {"event_type": "DNS_QUERY", "severity": "LOW",
               "source_ip": "10.0.1.1", "port": 53}
        result = LogParser.parse_log(raw)
        assert result is not None

    def test_parse_invalid_returns_none(self):
        assert LogParser.parse_log("not json") is None
        assert LogParser.parse_log({"severity": "INFO"}) is None

    def test_extract_features_length(self):
        log = {"severity_score": 3, "bytes_transferred": 1000, "port": 443,
               "hour_of_day": 14, "minute_of_hour": 30,
               "is_privileged_port": 1, "is_common_attack_port": 1,
               "request_length": 50, "message": "test"}
        features = LogParser.extract_features(log)
        assert len(features) == len(FEATURE_COLUMNS)

    def test_extract_features_dict(self):
        log = {"severity_score": 5, "bytes_transferred": 5000, "port": 80,
               "hour_of_day": 3, "minute_of_hour": 15,
               "is_privileged_port": 1, "is_common_attack_port": 1,
               "request_length": 100, "message": "attack"}
        fdict = LogParser.extract_features_dict(log)
        assert set(fdict.keys()) == set(FEATURE_COLUMNS)

    def test_enrich_log_adds_fields(self):
        log = {"event_type": "SQL_INJECTION", "severity": "HIGH",
               "source_ip": "1.2.3.4", "port": 80,
               "timestamp": "2024-06-01T12:30:00+00:00", "message": "test"}
        enriched = LogParser.enrich_log(log)
        assert "event_type_code" in enriched
        assert "protocol_code" in enriched
        assert "severity_score" in enriched
        assert "hour_of_day" in enriched


class TestPipeline:
    """End-to-end pipeline tests."""

    def test_generator_to_detector(self):
        gen = SecurityLogGenerator("pipeline-test")
        detector = AnomalyDetector()
        for _ in range(50):
            log = gen.generate_log()
            result = detector.detect(log)
            assert "is_anomaly" in result
            assert isinstance(result["is_anomaly"], bool)

    def test_full_flow(self):
        gen = SecurityLogGenerator("flow-test")
        detector = AnomalyDetector()
        anomaly_count = 0
        n = 200
        for _ in range(n):
            log = gen.generate_log()
            parsed = LogParser.parse_log(log)
            assert parsed is not None
            enriched = LogParser.enrich_log(parsed)
            result = detector.detect(enriched)
            if result["is_anomaly"]:
                anomaly_count += 1
        # Should have some anomalies but not all
        assert 0 < anomaly_count < n
