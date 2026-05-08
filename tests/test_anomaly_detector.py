"""Tests for the Anomaly Detector."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from processing.anomaly_detector import AnomalyDetector


class TestAnomalyDetector:
    """Test suite for AnomalyDetector."""

    def setup_method(self):
        self.detector = AnomalyDetector()

    def test_detect_returns_required_keys(self):
        log = {
            "event_type": "HTTP_REQUEST", "severity": "INFO",
            "severity_score": 1, "source_ip": "10.0.1.10",
            "port": 443, "bytes_transferred": 1500,
            "message": "GET /api HTTP/1.1", "hour_of_day": 14,
            "minute_of_hour": 30, "is_privileged_port": 1,
            "is_common_attack_port": 1, "request_length": 20,
        }
        result = self.detector.detect(log)
        assert "is_anomaly" in result
        assert "anomaly_score" in result
        assert "confidence" in result
        assert "threat_type" in result
        assert "threat_level" in result

    def test_normal_event_detection(self):
        log = {
            "event_type": "HEALTH_CHECK", "severity": "INFO",
            "severity_score": 1, "source_ip": "10.0.1.10",
            "port": 8080, "bytes_transferred": 200,
            "message": "Health check OK", "hour_of_day": 10,
            "minute_of_hour": 0, "is_privileged_port": 0,
            "is_common_attack_port": 1, "request_length": 15,
        }
        result = self.detector.detect(log)
        # With rule-based, low severity normal events should not be anomalous
        if result["detection_method"] == "rule_based":
            assert result["is_anomaly"] is False

    def test_attack_event_detection(self):
        log = {
            "event_type": "SQL_INJECTION", "severity": "CRITICAL",
            "severity_score": 5, "source_ip": "185.220.101.34",
            "port": 80, "bytes_transferred": 3000,
            "message": "' OR '1'='1", "hour_of_day": 3,
            "minute_of_hour": 15, "is_privileged_port": 1,
            "is_common_attack_port": 1, "request_length": 15,
        }
        result = self.detector.detect(log)
        if result["detection_method"] == "rule_based":
            assert result["is_anomaly"] is True
            assert result["threat_type"] == "Injection Attack"

    def test_batch_detect(self):
        logs = [
            {"event_type": "HTTP_REQUEST", "severity": "INFO",
             "severity_score": 1, "port": 443, "bytes_transferred": 100,
             "message": "OK", "hour_of_day": 12, "minute_of_hour": 0,
             "is_privileged_port": 1, "is_common_attack_port": 1,
             "request_length": 2, "source_ip": "10.0.1.1"},
            {"event_type": "BRUTE_FORCE", "severity": "HIGH",
             "severity_score": 4, "port": 22, "bytes_transferred": 500,
             "message": "Failed login", "hour_of_day": 3, "minute_of_hour": 0,
             "is_privileged_port": 1, "is_common_attack_port": 1,
             "request_length": 12, "source_ip": "185.220.101.34"},
        ]
        results = self.detector.batch_detect(logs)
        assert len(results) == 2
        for r in results:
            assert "is_anomaly" in r
            assert "event_type" in r

    def test_threat_level_calculation(self):
        assert AnomalyDetector._calc_threat("CRITICAL", 0.8) == "CRITICAL"
        assert AnomalyDetector._calc_threat("HIGH", 0.5) == "HIGH"
        assert AnomalyDetector._calc_threat("MEDIUM", 0.3) == "MEDIUM"
        assert AnomalyDetector._calc_threat("INFO", 0.1) == "LOW"
