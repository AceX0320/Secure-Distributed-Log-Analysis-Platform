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

from confluent_kafka import Consumer, KafkaError, KafkaException

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
                    conf = {
                        'bootstrap.servers': self.bootstrap_servers,
                        'group.id': f"{KAFKA_DASHBOARD_GROUP}-{topic}",
                        'auto.offset.reset': 'earliest',
                        'enable.auto.commit': True,
                    }
                    consumer = Consumer(conf)
                    consumer.subscribe([topic])
                    print(f"[DashboardConsumer] Connected to topic: {topic}")

                msg = consumer.poll(timeout=1.0)
                if msg is None:
                    continue

                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        continue
                    print(f"[DashboardConsumer] Kafka error on {topic}: {msg.error()}")
                    continue

                try:
                    log_data = json.loads(msg.value().decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    print(f"[DashboardConsumer] Decode error on {topic}: {e}")
                    continue

                try:
                    self.database.insert_log(log_data)
                except Exception as e:
                    print(f"[DashboardConsumer] DB insert error: {e}")

                self.socketio.emit(event_name, log_data)

            except KafkaException as e:
                print(f"[DashboardConsumer] Kafka exception for {topic}: {e}, retrying in 5s...")
                if consumer:
                    try:
                        consumer.close()
                    except Exception:
                        pass
                consumer = None
                time.sleep(5)
            except Exception as e:
                print(f"[DashboardConsumer] Error on {topic}: {e}")
                if consumer:
                    try:
                        consumer.close()
                    except Exception:
                        pass
                consumer = None
                time.sleep(2)

        if consumer:
            try:
                consumer.close()
            except Exception:
                pass
