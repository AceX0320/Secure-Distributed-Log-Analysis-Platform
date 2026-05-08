"""
Centralized Configuration for the Secure Distributed Log Analysis Platform.

All configurable parameters are defined here. Environment variables take
precedence over defaults for production flexibility.
"""

import os

# ============================================================
# Kafka Configuration
# ============================================================
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "127.0.0.1:9094")
KAFKA_TOPIC_RAW_LOGS = os.getenv("KAFKA_TOPIC_RAW", "raw-logs")
KAFKA_TOPIC_PROCESSED_LOGS = os.getenv("KAFKA_TOPIC_PROCESSED", "processed-logs")
KAFKA_TOPIC_ANOMALOUS_LOGS = os.getenv("KAFKA_TOPIC_ANOMALOUS", "anomalous-logs")
KAFKA_CONSUMER_GROUP = os.getenv("KAFKA_CONSUMER_GROUP", "log-analysis-group")
KAFKA_DASHBOARD_GROUP = os.getenv("KAFKA_DASHBOARD_GROUP", "dashboard-group")

# ============================================================
# Spark Configuration
# ============================================================
SPARK_MASTER_URL = os.getenv("SPARK_MASTER_URL", "spark://localhost:7077")
SPARK_APP_NAME = "SecurityLogAnalysis"
SPARK_BATCH_INTERVAL_SECONDS = int(os.getenv("SPARK_BATCH_INTERVAL", "5"))
SPARK_CHECKPOINT_DIR = os.getenv("SPARK_CHECKPOINT_DIR", "./checkpoints")

# Internal Kafka address used by Spark (within Docker network)
SPARK_KAFKA_BOOTSTRAP = os.getenv("SPARK_KAFKA_BOOTSTRAP", "127.0.0.1:9094")

# External environment dependencies (primarily for Windows local execution)
JAVA_HOME = os.getenv("JAVA_HOME", r"C:\Program Files\Java\jdk-17")
HADOOP_HOME = os.getenv("HADOOP_HOME", r"C:\hadoop")

# ============================================================
# Log Generator Configuration
# ============================================================
NUM_AGENTS = int(os.getenv("NUM_AGENTS", "3"))
LOG_RATE_MIN = float(os.getenv("LOG_RATE_MIN", "0.2"))   # seconds between logs
LOG_RATE_MAX = float(os.getenv("LOG_RATE_MAX", "0.5"))   # seconds between logs
ANOMALY_PROBABILITY = float(os.getenv("ANOMALY_PROBABILITY", "0.15"))

# Agent identifiers
AGENT_NAMES = [
    "web-server-01",
    "db-server-01",
    "firewall-01",
]

# ============================================================
# Anomaly Detection / ML Configuration
# ============================================================
MODEL_PATH = os.getenv(
    "MODEL_PATH",
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "isolation_forest_model.pkl")
)
MODEL_CONTAMINATION = float(os.getenv("MODEL_CONTAMINATION", "0.15"))
MODEL_N_ESTIMATORS = int(os.getenv("MODEL_N_ESTIMATORS", "200"))
MODEL_TRAINING_SAMPLES = int(os.getenv("MODEL_TRAINING_SAMPLES", "10000"))

# Feature columns used by the ML model
FEATURE_COLUMNS = [
    "severity_score",
    "bytes_transferred",
    "port",
    "hour_of_day",
    "minute_of_hour",
    "is_privileged_port",
    "is_common_attack_port",
    "request_length",
]

# ============================================================
# Dashboard Configuration
# ============================================================
DASHBOARD_HOST = os.getenv("DASHBOARD_HOST", "0.0.0.0")
DASHBOARD_PORT = int(os.getenv("DASHBOARD_PORT", "5000"))
DASHBOARD_DEBUG = os.getenv("DASHBOARD_DEBUG", "false").lower() == "true"
DASHBOARD_SECRET_KEY = os.getenv("DASHBOARD_SECRET_KEY", "secure-log-platform-secret-2024")

# ============================================================
# Database Configuration
# ============================================================
DATABASE_PATH = os.getenv(
    "DATABASE_PATH",
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "dashboard", "logs.db")
)
DB_MAX_RECORDS = int(os.getenv("DB_MAX_RECORDS", "5000000"))
DB_CLEANUP_THRESHOLD = int(os.getenv("DB_CLEANUP_THRESHOLD", "5100000"))

# ============================================================
# Security Event Types
# ============================================================
NORMAL_EVENT_TYPES = [
    "HTTP_REQUEST",
    "SSH_LOGIN_SUCCESS",
    "FILE_ACCESS",
    "DNS_QUERY",
    "DHCP_LEASE",
    "NTP_SYNC",
    "HEALTH_CHECK",
    "API_CALL",
    "USER_LOGIN",
    "SESSION_START",
]

ATTACK_EVENT_TYPES = [
    "BRUTE_FORCE",
    "SQL_INJECTION",
    "PORT_SCAN",
    "DDOS_ATTEMPT",
    "PRIVILEGE_ESCALATION",
    "MALWARE_DETECTED",
    "DATA_EXFILTRATION",
    "XSS_ATTEMPT",
    "UNAUTHORIZED_ACCESS",
    "COMMAND_INJECTION",
]

SEVERITY_LEVELS = {
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}

PROTOCOLS = ["TCP", "UDP", "HTTP", "HTTPS", "SSH", "DNS", "FTP", "SMTP"]
