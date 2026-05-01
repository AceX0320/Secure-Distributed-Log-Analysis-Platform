"""
Realistic Security Log Generator

Generates structured JSON security log events that simulate real-world
network and server activity, including both normal operations and
various attack patterns.
"""

import json
import random
import string
import time
from datetime import datetime, timezone

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import (
    NORMAL_EVENT_TYPES,
    ATTACK_EVENT_TYPES,
    SEVERITY_LEVELS,
    PROTOCOLS,
    ANOMALY_PROBABILITY,
)


class SecurityLogGenerator:
    """Generates realistic security log events for distributed servers."""

    # Realistic IP address pools
    INTERNAL_IPS = [
        "10.0.1.10", "10.0.1.11", "10.0.1.12", "10.0.1.20",
        "10.0.2.10", "10.0.2.15", "10.0.2.30", "10.0.3.5",
        "192.168.1.100", "192.168.1.101", "192.168.1.200",
    ]

    EXTERNAL_IPS = [
        "203.0.113.50", "198.51.100.23", "192.0.2.100",
        "45.33.32.156", "104.26.10.78", "172.67.180.245",
        "91.189.88.181", "151.101.1.140", "13.107.42.14",
    ]

    SUSPICIOUS_IPS = [
        "185.220.101.34",  # Known Tor exit node
        "171.25.193.25",   # Known Tor exit node
        "89.234.157.254",  # VPN/proxy
        "62.210.105.116",  # Flagged scanner
        "45.148.10.143",   # Malicious botnet
        "194.26.192.64",   # Known attacker
    ]

    COMMON_URLS = [
        "/api/v1/users", "/api/v1/auth/login", "/api/v1/data",
        "/index.html", "/dashboard", "/admin/panel",
        "/health", "/api/v1/logs", "/api/v1/config",
        "/static/css/main.css", "/static/js/app.js",
    ]

    ATTACK_PAYLOADS = [
        "' OR '1'='1",
        "UNION SELECT * FROM users",
        "<script>alert('xss')</script>",
        "../../../../etc/passwd",
        "; rm -rf /",
        "admin' --",
        "eval(base64_decode('...'))",
        "' OR 1=1--",
    ]



    USERNAMES = [
        "admin", "root", "john.doe", "jane.smith",
        "svc_account", "backup_user", "deploy_bot",
        "monitoring", "guest", "test_user",
    ]

    def __init__(self, agent_name: str = "agent-01"):
        """Initialize the log generator for a specific agent/server."""
        self.agent_name = agent_name
        self.sequence_number = 0

    def generate_log(self) -> dict:
        """Generate a single security log event."""
        self.sequence_number += 1
        is_attack = random.random() < ANOMALY_PROBABILITY

        if is_attack:
            return self._generate_attack_log()
        else:
            return self._generate_normal_log()

    def _generate_normal_log(self) -> dict:
        """Generate a normal (benign) log event."""
        event_type = random.choice(NORMAL_EVENT_TYPES)
        severity = random.choice(["INFO", "LOW"])
        source_ip = random.choice(self.INTERNAL_IPS + self.EXTERNAL_IPS)
        dest_ip = random.choice(self.INTERNAL_IPS)
        port = random.choice([80, 443, 22, 53, 8080, 3306, 5432, 8443])
        protocol = random.choice(PROTOCOLS)
        user = random.choice(self.USERNAMES)
        url = random.choice(self.COMMON_URLS)
        bytes_transferred = random.randint(64, 15000)
        status_code = random.choice([200, 200, 200, 201, 204, 301, 304])

        messages = {
            "HTTP_REQUEST": f"GET {url} HTTP/1.1 - {status_code}",
            "SSH_LOGIN_SUCCESS": f"Accepted publickey for {user} from {source_ip} port {port}",
            "FILE_ACCESS": f"User {user} accessed /data/reports/report_{random.randint(1,100)}.pdf",
            "DNS_QUERY": f"Query: {random.choice(['google.com','github.com','api.internal.com'])} A IN",
            "DHCP_LEASE": f"DHCPACK on {source_ip} to {self._random_mac()} via eth0",
            "NTP_SYNC": f"NTP synchronized to time.google.com, offset +{random.uniform(0, 0.05):.4f}s",
            "HEALTH_CHECK": f"Health check passed for service {self.agent_name}",
            "API_CALL": f"POST {url} - {status_code} - {bytes_transferred}B - {random.randint(5, 200)}ms",
            "USER_LOGIN": f"User {user} logged in successfully from {source_ip}",
            "SESSION_START": f"New session started for {user} (session_id: {self._random_session_id()})",
        }

        return self._build_log_entry(
            event_type=event_type,
            severity=severity,
            source_ip=source_ip,
            dest_ip=dest_ip,
            port=port,
            protocol=protocol,
            user=user,
            message=messages.get(event_type, f"Normal event: {event_type}"),
            bytes_transferred=bytes_transferred,
            status_code=status_code,
            url=url,
            is_anomaly=False,
        )

    def _generate_attack_log(self) -> dict:
        """Generate an attack/anomalous log event."""
        event_type = random.choice(ATTACK_EVENT_TYPES)
        source_ip = random.choice(self.SUSPICIOUS_IPS + self.EXTERNAL_IPS[:3])
        dest_ip = random.choice(self.INTERNAL_IPS)
        user = random.choice(["admin", "root", "unknown", ""])

        attack_configs = {
            "BRUTE_FORCE": {
                "severity": "HIGH",
                "port": 22,
                "protocol": "SSH",
                "bytes": random.randint(200, 800),
                "status": 401,
                "message": f"[THREAT ALERT - BRUTE_FORCE] Excessive failed SSH logins for {user} from {source_ip} (attempts: {random.randint(50, 500)})",
            },
            "SQL_INJECTION": {
                "severity": "CRITICAL",
                "port": random.choice([80, 443, 8080]),
                "protocol": "HTTP",
                "bytes": random.randint(500, 5000),
                "status": 500,
                "message": f"[THREAT ALERT - SQL_INJECTION] Malicious SQL payload detected in HTTP request: {random.choice(self.ATTACK_PAYLOADS)}",
            },
            "PORT_SCAN": {
                "severity": "MEDIUM",
                "port": random.randint(1, 65535),
                "protocol": "TCP",
                "bytes": random.randint(40, 120),
                "status": 0,
                "message": f"[THREAT ALERT - PORT_SCAN] Rapid sequential connection attempts from {source_ip} ({random.randint(100, 1000)} ports in {random.randint(1, 10)}s)",
            },
            "DDOS_ATTEMPT": {
                "severity": "CRITICAL",
                "port": random.choice([80, 443]),
                "protocol": random.choice(["TCP", "UDP"]),
                "bytes": random.randint(50000, 500000),
                "status": 503,
                "message": f"[THREAT ALERT - DDOS_ATTEMPT] Volumetric traffic flood originating from {source_ip} ({random.randint(5000, 50000)} req/s)",
            },
            "PRIVILEGE_ESCALATION": {
                "severity": "CRITICAL",
                "port": 0,
                "protocol": "LOCAL",
                "bytes": random.randint(100, 2000),
                "status": 0,
                "message": f"[THREAT ALERT - PRIV_ESCALATION] Suspicious root-level access attempt by user '{user}' on /etc/shadow",
            },
            "MALWARE_DETECTED": {
                "severity": "CRITICAL",
                "port": random.choice([80, 443, 8080]),
                "protocol": "HTTP",
                "bytes": random.randint(10000, 100000),
                "status": 200,
                "message": f"[THREAT ALERT - MALWARE] Known malware signature matched in network stream: Trojan.GenericKD.{random.randint(10000, 99999)}",
            },
            "DATA_EXFILTRATION": {
                "severity": "HIGH",
                "port": random.choice([443, 8443, 53]),
                "protocol": random.choice(["HTTPS", "DNS"]),
                "bytes": random.randint(100000, 5000000),
                "status": 200,
                "message": f"[THREAT ALERT - EXFILTRATION] Anomalous outbound data transfer ({random.randint(1, 50)}MB) to untrusted IP {source_ip}",
            },
            "XSS_ATTEMPT": {
                "severity": "HIGH",
                "port": random.choice([80, 443]),
                "protocol": "HTTP",
                "bytes": random.randint(300, 3000),
                "status": 200,
                "message": f"[THREAT ALERT - XSS_ATTEMPT] Cross-Site Scripting payload found in URL parameter: {random.choice(self.ATTACK_PAYLOADS)}",
            },
            "UNAUTHORIZED_ACCESS": {
                "severity": "HIGH",
                "port": random.choice([22, 3389, 5900]),
                "protocol": random.choice(["SSH", "TCP"]),
                "bytes": random.randint(100, 1000),
                "status": 403,
                "message": f"[THREAT ALERT - UNAUTH_ACCESS] Connection attempt blocked to restricted zone from {source_ip}",
            },
            "COMMAND_INJECTION": {
                "severity": "CRITICAL",
                "port": random.choice([80, 443]),
                "protocol": "HTTP",
                "bytes": random.randint(200, 5000),
                "status": 500,
                "message": f"[THREAT ALERT - CMD_INJECTION] OS Command execution attempt detected: {random.choice(self.ATTACK_PAYLOADS)}",
            },
        }

        config = attack_configs.get(event_type, attack_configs["UNAUTHORIZED_ACCESS"])

        return self._build_log_entry(
            event_type=event_type,
            severity=config["severity"],
            source_ip=source_ip,
            dest_ip=dest_ip,
            port=config["port"],
            protocol=config["protocol"],
            user=user,
            message=config["message"],
            bytes_transferred=config["bytes"],
            status_code=config["status"],
            url=random.choice(self.COMMON_URLS),
            is_anomaly=True,
        )

    def _build_log_entry(self, **kwargs) -> dict:
        """Build a structured log entry dictionary."""
        now = datetime.now(timezone.utc)
        return {
            "timestamp": now.isoformat(),
            "agent": self.agent_name,
            "sequence": self.sequence_number,
            "event_type": kwargs["event_type"],
            "severity": kwargs["severity"],
            "severity_score": SEVERITY_LEVELS.get(kwargs["severity"], 1),
            "source_ip": kwargs["source_ip"],
            "dest_ip": kwargs["dest_ip"],
            "port": kwargs["port"],
            "protocol": kwargs["protocol"],
            "user": kwargs["user"],
            "message": kwargs["message"],
            "bytes_transferred": kwargs["bytes_transferred"],
            "status_code": kwargs["status_code"],
            "url": kwargs.get("url", ""),
            "is_anomaly": kwargs["is_anomaly"],
            "hour_of_day": now.hour,
            "minute_of_hour": now.minute,
            "is_privileged_port": 1 if kwargs["port"] < 1024 else 0,
            "is_common_attack_port": 1 if kwargs["port"] in [21, 22, 23, 25, 80, 443, 445, 3389, 8080] else 0,
            "request_length": len(kwargs["message"]),
        }

    @staticmethod
    def _random_mac() -> str:
        """Generate a random MAC address."""
        return ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))

    @staticmethod
    def _random_session_id() -> str:
        """Generate a random session ID."""
        return "".join(random.choices(string.hexdigits[:16], k=32))


if __name__ == "__main__":
    # Quick test: generate and print sample logs
    gen = SecurityLogGenerator("test-agent")
    for i in range(10):
        log = gen.generate_log()
        print(json.dumps(log, indent=2))
        print("---")
