"""
Log Parser and Feature Extractor

Parses raw JSON security logs and extracts numerical feature vectors
suitable for the Isolation Forest anomaly detection model.
"""

import json
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import FEATURE_COLUMNS, SEVERITY_LEVELS


class LogParser:
    """Parses and normalizes security log entries for ML processing."""

    # Event type to numerical encoding
    EVENT_TYPE_ENCODING = {
        "HTTP_REQUEST": 0, "SSH_LOGIN_SUCCESS": 1, "FILE_ACCESS": 2,
        "DNS_QUERY": 3, "DHCP_LEASE": 4, "NTP_SYNC": 5,
        "HEALTH_CHECK": 6, "API_CALL": 7, "USER_LOGIN": 8,
        "SESSION_START": 9,
        "BRUTE_FORCE": 10, "SQL_INJECTION": 11, "PORT_SCAN": 12,
        "DDOS_ATTEMPT": 13, "PRIVILEGE_ESCALATION": 14,
        "MALWARE_DETECTED": 15, "DATA_EXFILTRATION": 16,
        "XSS_ATTEMPT": 17, "UNAUTHORIZED_ACCESS": 18,
        "COMMAND_INJECTION": 19,
    }

    # Protocol to numerical encoding
    PROTOCOL_ENCODING = {
        "TCP": 0, "UDP": 1, "HTTP": 2, "HTTPS": 3,
        "SSH": 4, "DNS": 5, "FTP": 6, "SMTP": 7, "LOCAL": 8,
    }

    @classmethod
    def parse_log(cls, raw_log: str | dict) -> dict | None:
        """
        Parse a raw log entry (JSON string or dict) into a structured dict.

        Args:
            raw_log: Raw log as JSON string or dictionary.

        Returns:
            Parsed log dictionary or None if parsing fails.
        """
        try:
            if isinstance(raw_log, str):
                log = json.loads(raw_log)
            else:
                log = raw_log

            # Ensure required fields exist
            required_fields = ["event_type", "severity", "source_ip", "port"]
            for field in required_fields:
                if field not in log:
                    return None

            return log

        except (json.JSONDecodeError, KeyError, TypeError) as e:
            print(f"[LogParser] Parse error: {e}")
            return None

    @classmethod
    def extract_features(cls, log: dict) -> list[float]:
        """
        Extract numerical feature vector from a parsed log entry.

        Features extracted:
        - severity_score: Numerical severity (1-5)
        - bytes_transferred: Volume of data
        - port: Target port number
        - hour_of_day: Hour component of timestamp (0-23)
        - minute_of_hour: Minute component (0-59)
        - is_privileged_port: 1 if port < 1024
        - is_common_attack_port: 1 if port in known attack ports
        - request_length: Length of the log message

        Args:
            log: Parsed log dictionary.

        Returns:
            List of numerical features.
        """
        features = [
            float(log.get("severity_score", SEVERITY_LEVELS.get(log.get("severity", "INFO"), 1))),
            float(log.get("bytes_transferred", 0)),
            float(log.get("port", 0)),
            float(log.get("hour_of_day", 0)),
            float(log.get("minute_of_hour", 0)),
            float(log.get("is_privileged_port", 1 if log.get("port", 0) < 1024 else 0)),
            float(log.get("is_common_attack_port", 0)),
            float(log.get("request_length", len(log.get("message", "")))),
        ]
        return features

    @classmethod
    def extract_features_dict(cls, log: dict) -> dict:
        """
        Extract features as a named dictionary (for DataFrame creation).

        Args:
            log: Parsed log dictionary.

        Returns:
            Dictionary mapping feature names to values.
        """
        features = cls.extract_features(log)
        return dict(zip(FEATURE_COLUMNS, features))

    @classmethod
    def enrich_log(cls, log: dict) -> dict:
        """
        Enrich a log entry with additional computed fields.

        Args:
            log: Parsed log dictionary.

        Returns:
            Enriched log dictionary.
        """
        enriched = log.copy()

        # Add numerical encodings
        enriched["event_type_code"] = cls.EVENT_TYPE_ENCODING.get(
            log.get("event_type", ""), -1
        )
        enriched["protocol_code"] = cls.PROTOCOL_ENCODING.get(
            log.get("protocol", ""), -1
        )

        # Add computed severity score if missing
        if "severity_score" not in enriched:
            enriched["severity_score"] = SEVERITY_LEVELS.get(
                log.get("severity", "INFO"), 1
            )

        # Add time features if timestamp present
        if "timestamp" in log and "hour_of_day" not in log:
            try:
                ts = datetime.fromisoformat(log["timestamp"])
                enriched["hour_of_day"] = ts.hour
                enriched["minute_of_hour"] = ts.minute
            except (ValueError, TypeError):
                enriched["hour_of_day"] = 0
                enriched["minute_of_hour"] = 0

        # Add port classification if missing
        port = log.get("port", 0)
        if "is_privileged_port" not in enriched:
            enriched["is_privileged_port"] = 1 if port < 1024 else 0
        if "is_common_attack_port" not in enriched:
            enriched["is_common_attack_port"] = (
                1 if port in [21, 22, 23, 25, 80, 443, 445, 3389, 8080] else 0
            )
        if "request_length" not in enriched:
            enriched["request_length"] = len(log.get("message", ""))

        return enriched


if __name__ == "__main__":
    # Quick test
    sample = {
        "timestamp": "2024-01-01T12:30:00+00:00",
        "event_type": "SQL_INJECTION",
        "severity": "CRITICAL",
        "source_ip": "185.220.101.34",
        "dest_ip": "10.0.1.10",
        "port": 80,
        "protocol": "HTTP",
        "user": "admin",
        "message": "SQL injection detected: ' OR '1'='1",
        "bytes_transferred": 2500,
    }

    parsed = LogParser.parse_log(sample)
    print("Parsed:", json.dumps(parsed, indent=2))

    features = LogParser.extract_features(parsed)
    print("\nFeatures:", features)

    enriched = LogParser.enrich_log(parsed)
    print("\nEnriched:", json.dumps(enriched, indent=2))
