"""Tests for the Security Log Generator."""

import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.log_generator import SecurityLogGenerator
from config.settings import NORMAL_EVENT_TYPES, ATTACK_EVENT_TYPES


class TestLogGenerator:
    """Test suite for SecurityLogGenerator."""

    def setup_method(self):
        self.generator = SecurityLogGenerator("test-agent")

    def test_generates_valid_json(self):
        log = self.generator.generate_log()
        json_str = json.dumps(log)
        parsed = json.loads(json_str)
        assert isinstance(parsed, dict)

    def test_has_required_fields(self):
        log = self.generator.generate_log()
        required = ["timestamp", "agent", "event_type", "severity",
                     "source_ip", "dest_ip", "port", "protocol",
                     "message", "bytes_transferred"]
        for field in required:
            assert field in log, f"Missing field: {field}"

    def test_agent_name_matches(self):
        log = self.generator.generate_log()
        assert log["agent"] == "test-agent"

    def test_severity_score_range(self):
        for _ in range(100):
            log = self.generator.generate_log()
            assert 1 <= log["severity_score"] <= 5

    def test_event_types_are_valid(self):
        all_types = set(NORMAL_EVENT_TYPES + ATTACK_EVENT_TYPES)
        for _ in range(100):
            log = self.generator.generate_log()
            assert log["event_type"] in all_types

    def test_sequence_increments(self):
        gen = SecurityLogGenerator("seq-test")
        logs = [gen.generate_log() for _ in range(10)]
        for i, log in enumerate(logs):
            assert log["sequence"] == i + 1

    def test_anomaly_flag_exists(self):
        for _ in range(50):
            log = self.generator.generate_log()
            assert isinstance(log["is_anomaly"], bool)

    def test_generates_both_normal_and_attack(self):
        normal_count = 0
        attack_count = 0
        for _ in range(500):
            log = self.generator.generate_log()
            if log["is_anomaly"]:
                attack_count += 1
            else:
                normal_count += 1
        assert normal_count > 0, "No normal events generated"
        assert attack_count > 0, "No attack events generated"

    def test_port_classification(self):
        log = self.generator.generate_log()
        if log["port"] < 1024:
            assert log["is_privileged_port"] == 1
        else:
            assert log["is_privileged_port"] == 0
