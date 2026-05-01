"""
SQLite Database Layer

Provides persistent storage for processed logs and anomalies,
with query methods for the dashboard visualizations.
"""

import os
import sys
import sqlite3
import json
import threading
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.settings import DATABASE_PATH, DB_MAX_RECORDS, DB_CLEANUP_THRESHOLD


class LogDatabase:
    """Thread-safe SQLite database for security log storage and querying."""

    def __init__(self, db_path=None):
        self.db_path = db_path or DATABASE_PATH
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._local = threading.local()
        self._init_db()

    def _get_conn(self):
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
        return self._local.conn

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT, agent TEXT, event_type TEXT,
                severity TEXT, severity_score INTEGER,
                source_ip TEXT, dest_ip TEXT, port INTEGER,
                protocol TEXT, user TEXT, message TEXT,
                bytes_transferred INTEGER, status_code INTEGER,
                url TEXT, is_anomaly BOOLEAN DEFAULT 0,
                anomaly_score REAL, ml_is_anomaly BOOLEAN DEFAULT 0,
                threat_type TEXT, threat_level TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_logs_event_type ON logs(event_type);
            CREATE INDEX IF NOT EXISTS idx_logs_anomaly ON logs(ml_is_anomaly);
            CREATE INDEX IF NOT EXISTS idx_logs_source_ip ON logs(source_ip);
            CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs(severity);

            CREATE TABLE IF NOT EXISTS statistics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stat_name TEXT UNIQUE, stat_value TEXT,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.commit()

    def insert_log(self, log_data):
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO logs (timestamp, agent, event_type, severity,
                severity_score, source_ip, dest_ip, port, protocol,
                user, message, bytes_transferred, status_code, url,
                is_anomaly, anomaly_score, ml_is_anomaly, threat_type, threat_level)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            log_data.get("timestamp"), log_data.get("agent"),
            log_data.get("event_type"), log_data.get("severity"),
            log_data.get("severity_score"), log_data.get("source_ip"),
            log_data.get("dest_ip"), log_data.get("port"),
            log_data.get("protocol"), log_data.get("user"),
            log_data.get("message"), log_data.get("bytes_transferred"),
            log_data.get("status_code"), log_data.get("url"),
            log_data.get("is_anomaly", False),
            log_data.get("anomaly_score", 0.0),
            log_data.get("ml_is_anomaly", False),
            log_data.get("threat_type", ""),
            log_data.get("threat_level", ""),
        ))
        conn.commit()
        self._cleanup_if_needed()

    def _cleanup_if_needed(self):
        conn = self._get_conn()
        count = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        if count > DB_CLEANUP_THRESHOLD:
            conn.execute(f"""
                DELETE FROM logs WHERE id IN (
                    SELECT id FROM logs ORDER BY id ASC
                    LIMIT {count - DB_MAX_RECORDS}
                )
            """)
            conn.commit()

    def get_stats(self):
        conn = self._get_conn()
        total = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        anomalies = conn.execute(
            "SELECT COUNT(*) FROM logs WHERE ml_is_anomaly = 1"
        ).fetchone()[0]
        critical = conn.execute(
            "SELECT COUNT(*) FROM logs WHERE severity = 'CRITICAL'"
        ).fetchone()[0]
        unique_ips = conn.execute(
            "SELECT COUNT(DISTINCT source_ip) FROM logs"
        ).fetchone()[0]
        return {
            "total_logs": total, "total_anomalies": anomalies,
            "critical_events": critical, "unique_source_ips": unique_ips,
            "anomaly_rate": round(anomalies / total * 100, 2) if total > 0 else 0,
        }

    def get_event_type_distribution(self):
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT event_type, COUNT(*) as count FROM logs
            WHERE ml_is_anomaly = 1
            GROUP BY event_type ORDER BY count DESC LIMIT 10
        """).fetchall()
        return [{"event_type": r["event_type"], "count": r["count"]} for r in rows]

    def get_severity_distribution(self):
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT severity, COUNT(*) as count FROM logs
            GROUP BY severity ORDER BY count DESC
        """).fetchall()
        return [{"severity": r["severity"], "count": r["count"]} for r in rows]

    def get_top_source_ips(self, limit=10):
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT source_ip, COUNT(*) as count,
                   SUM(CASE WHEN ml_is_anomaly = 1 THEN 1 ELSE 0 END) as anomaly_count
            FROM logs GROUP BY source_ip
            ORDER BY anomaly_count DESC, count DESC LIMIT ?
        """, (limit,)).fetchall()
        return [{"source_ip": r["source_ip"], "count": r["count"],
                 "anomaly_count": r["anomaly_count"]} for r in rows]

    def get_timeline_data(self, minutes=30):
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT strftime('%H:%M', timestamp) as time_bucket,
                   COUNT(*) as total,
                   SUM(CASE WHEN ml_is_anomaly = 1 THEN 1 ELSE 0 END) as anomalies
            FROM logs GROUP BY time_bucket
            ORDER BY time_bucket DESC LIMIT ?
        """, (minutes,)).fetchall()
        result = [{"time": r["time_bucket"], "total": r["total"],
                    "anomalies": r["anomalies"]} for r in rows]
        result.reverse()
        return result

    def get_recent_anomalies(self, limit=20):
        conn = self._get_conn()
        rows = conn.execute("""
            SELECT * FROM logs WHERE ml_is_anomaly = 1
            ORDER BY id DESC LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_recent_logs(self, limit=50):
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM logs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
