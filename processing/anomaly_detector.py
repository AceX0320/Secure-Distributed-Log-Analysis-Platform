"""
Anomaly Detection Module

Uses a pre-trained Isolation Forest model to detect anomalous security
log events in real time.
"""

import os
import sys
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import joblib
except ImportError:
    joblib = None

from config.settings import MODEL_PATH, FEATURE_COLUMNS
from processing.log_parser import LogParser


class AnomalyDetector:
    """Detects anomalous security events using Isolation Forest."""

    THREAT_CLASSIFICATIONS = {
        "BRUTE_FORCE": "Credential Attack",
        "SQL_INJECTION": "Injection Attack",
        "PORT_SCAN": "Reconnaissance",
        "DDOS_ATTEMPT": "Denial of Service",
        "PRIVILEGE_ESCALATION": "Privilege Abuse",
        "MALWARE_DETECTED": "Malware",
        "DATA_EXFILTRATION": "Data Breach",
        "XSS_ATTEMPT": "Injection Attack",
        "UNAUTHORIZED_ACCESS": "Unauthorized Access",
        "COMMAND_INJECTION": "Injection Attack",
    }

    def __init__(self, model_path=None):
        self.model_path = model_path or MODEL_PATH
        self.model = None
        self._load_model()

    def _load_model(self):
        if joblib is None:
            print("[AnomalyDetector] joblib not installed. Using rule-based detection.")
            return
        if not os.path.exists(self.model_path):
            print(f"[AnomalyDetector] Model not found. Run 'python models/train_model.py'. Using fallback.")
            return
        try:
            self.model = joblib.load(self.model_path)
            print(f"[AnomalyDetector] Model loaded from {self.model_path}")
        except Exception as e:
            print(f"[AnomalyDetector] Error loading model: {e}")

    def detect(self, log):
        features = LogParser.extract_features(log)
        if self.model is not None:
            return self._ml_detection(log, features)
        return self._rule_based_detection(log, features)

    def _ml_detection(self, log, features):
        feature_array = np.array(features).reshape(1, -1)
        prediction = self.model.predict(feature_array)[0]
        raw_score = self.model.decision_function(feature_array)[0]
        confidence = max(0.0, min(1.0, 0.5 - raw_score))
        is_anomaly = prediction == -1
        event_type = log.get("event_type", "UNKNOWN")
        if is_anomaly:
            threat_type = self.THREAT_CLASSIFICATIONS.get(event_type, "Unknown Threat")
            threat_level = self._calc_threat(log.get("severity", "MEDIUM"), confidence)
        else:
            threat_type = "None"
            threat_level = "SAFE"
        return {"is_anomaly": is_anomaly, "anomaly_score": float(raw_score),
                "confidence": float(confidence), "threat_type": threat_type,
                "threat_level": threat_level, "detection_method": "isolation_forest"}

    def _rule_based_detection(self, log, features):
        event_type = log.get("event_type", "")
        severity_score = features[0]
        bytes_transferred = features[1]
        score = 0.0
        if severity_score >= 4:
            score += 0.4
        if event_type in self.THREAT_CLASSIFICATIONS:
            score += 0.5
        if bytes_transferred > 100000:
            score += 0.2
        is_anomaly = score >= 0.5
        confidence = min(1.0, score)
        if is_anomaly:
            threat_type = self.THREAT_CLASSIFICATIONS.get(event_type, "Suspicious Activity")
            threat_level = self._calc_threat(log.get("severity", "MEDIUM"), confidence)
        else:
            threat_type = "None"
            threat_level = "SAFE"
        return {"is_anomaly": is_anomaly, "anomaly_score": float(-score if is_anomaly else score),
                "confidence": float(confidence), "threat_type": threat_type,
                "threat_level": threat_level, "detection_method": "rule_based"}

    @staticmethod
    def _calc_threat(severity, confidence):
        if severity == "CRITICAL" and confidence > 0.5:
            return "CRITICAL"
        if severity in ("CRITICAL", "HIGH") and confidence > 0.3:
            return "HIGH"
        if severity in ("HIGH", "MEDIUM") and confidence > 0.2:
            return "MEDIUM"
        return "LOW"

    def batch_detect(self, logs):
        return [{**log, **self.detect(log)} for log in logs]
