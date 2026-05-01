"""
Dashboard Kafka Consumer

Consumes processed and anomalous logs from Kafka topics and forwards
them to the Flask-SocketIO dashboard for real-time visualization.
"""

import json
import sys
import os
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kafka import KafkaConsumer
from kafka.errors import NoBrokersAvailable

from config.settings import (
    KAFKA_BOOTSTRAP_SERVERS, KAFKA_TOPIC_PROCESSED_LOGS,
    KAFKA_TOPIC_ANOMALOUS_LOGS, KAFKA_DASHBOARD_GROUP,
)


class DashboardConsumer:
    """Kafka consumer that feeds real-time data to the dashboard."""

    def __init__(self, socketio, database, bootstrap_servers=None):
        self.socketio = socketio
        self.database = database
        self.bootstrap_servers = bootstrap_servers or KAFKA_BOOTSTRAP_SERVERS
        self.running = False
        self._threads = []

    def start(self):
        """Start consumer threads for processed and anomalous topics."""
        self.running = True

        t1 = threading.Thread(
            target=self._consume_topic,
            args=(KAFKA_TOPIC_PROCESSED_LOGS, "processed_log"),
            daemon=True, name="Consumer-Processed",
        )
        t2 = threading.Thread(
            target=self._consume_topic,
            args=(KAFKA_TOPIC_ANOMALOUS_LOGS, "anomaly_detected"),
            daemon=True, name="Consumer-Anomalous",
        )

        self._threads = [t1, t2]
        t1.start()
        t2.start()
        print("[DashboardConsumer] Started consuming from Kafka topics.")

    def stop(self):
        self.running = False
        for t in self._threads:
            t.join(timeout=5)

    def _consume_topic(self, topic, event_name):
        """Consume messages from a Kafka topic and emit via SocketIO."""
        consumer = None
        while self.running:
            try:
                if consumer is None:
                    consumer = KafkaConsumer(
                        topic,
                        bootstrap_servers=self.bootstrap_servers,
                        group_id=f"{KAFKA_DASHBOARD_GROUP}-{topic}",
                        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                        auto_offset_reset="latest",
                        enable_auto_commit=True,
                        consumer_timeout_ms=1000,
                        api_version=(3, 5, 0),
                    )
                    print(f"[DashboardConsumer] Connected to topic: {topic}")

                for message in consumer:
                    if not self.running:
                        break
                    log_data = message.value
                    try:
                        self.database.insert_log(log_data)
                    except Exception as e:
                        print(f"[DashboardConsumer] DB insert error: {e}")

                    self.socketio.emit(event_name, log_data)

            except NoBrokersAvailable:
                print(f"[DashboardConsumer] Kafka not available for {topic}, retrying in 5s...")
                time.sleep(5)
            except Exception as e:
                print(f"[DashboardConsumer] Error on {topic}: {e}")
                time.sleep(2)
                consumer = None
