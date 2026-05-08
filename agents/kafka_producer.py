"""
Kafka Producer Agent

Multi-threaded log producer that simulates multiple distributed server
agents sending security logs to Apache Kafka in real time.
"""

import json
import sys
import os
import time
import threading
import random
import signal
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kafka import KafkaProducer
from kafka.errors import KafkaError, NoBrokersAvailable
from colorama import Fore, Style, init as colorama_init

from config.settings import (
    KAFKA_BOOTSTRAP_SERVERS,
    KAFKA_TOPIC_RAW_LOGS,
    AGENT_NAMES,
    LOG_RATE_MIN,
    LOG_RATE_MAX,
    NUM_AGENTS,
)
from agents.log_generator import SecurityLogGenerator

# Initialize colorama for Windows color support
colorama_init()

# Global shutdown flag
shutdown_event = threading.Event()


def create_kafka_producer(retries: int = 10, retry_delay: int = 5) -> KafkaProducer:
    """
    Create a Kafka producer with retry logic.

    Args:
        retries: Number of connection attempts.
        retry_delay: Seconds to wait between retries.

    Returns:
        Connected KafkaProducer instance.
    """
    for attempt in range(1, retries + 1):
        try:
            producer = KafkaProducer(
                bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
                value_serializer=lambda v: json.dumps(v).encode("utf-8"),
                key_serializer=lambda k: k.encode("utf-8") if k else None,
                acks="all",
                retries=3,
                max_block_ms=10000,
                request_timeout_ms=15000,
                linger_ms=10,
                batch_size=16384,
            )
            print(f"{Fore.GREEN}[OK] Connected to Kafka at {KAFKA_BOOTSTRAP_SERVERS}{Style.RESET_ALL}")
            return producer
        except NoBrokersAvailable:
            print(
                f"{Fore.YELLOW}[WAIT] Kafka not ready (attempt {attempt}/{retries}), "
                f"retrying in {retry_delay}s...{Style.RESET_ALL}"
            )
            time.sleep(retry_delay)

    print(f"{Fore.RED}[FAIL] Failed to connect to Kafka after {retries} attempts.{Style.RESET_ALL}")
    sys.exit(1)


def agent_worker(
    producer: KafkaProducer,
    agent_name: str,
    topic: str,
    agent_index: int,
):
    """
    Worker function for each log collection agent thread.

    Args:
        producer: Shared KafkaProducer instance.
        agent_name: Name identifier for this agent.
        topic: Kafka topic to publish to.
        agent_index: Index for color coding.
    """
    generator = SecurityLogGenerator(agent_name)
    colors = [Fore.CYAN, Fore.MAGENTA, Fore.BLUE, Fore.GREEN, Fore.YELLOW]
    color = colors[agent_index % len(colors)]
    log_count = 0

    print(f"{color}[Agent: {agent_name}] Started collecting logs...{Style.RESET_ALL}")

    while not shutdown_event.is_set():
        try:
            log_entry = generator.generate_log()
            log_count += 1

            # Use source_ip as partition key for ordering
            future = producer.send(
                topic,
                key=log_entry["source_ip"],
                value=log_entry,
            )
            future.get(timeout=5) # Wait for send to complete to catch errors

            # Log to console with severity color coding
            severity = log_entry["severity"]
            if severity == "CRITICAL":
                sev_color = Fore.RED
            elif severity == "HIGH":
                sev_color = Fore.YELLOW
            elif severity == "MEDIUM":
                sev_color = Fore.LIGHTYELLOW_EX
            else:
                sev_color = Fore.WHITE

            anomaly_tag = f"{Fore.RED}[ANOMALY]{Style.RESET_ALL} " if log_entry["is_anomaly"] else ""

            print(
                f"{color}[{agent_name}]{Style.RESET_ALL} "
                f"#{log_count:>5} | "
                f"{sev_color}{severity:<8}{Style.RESET_ALL} | "
                f"{anomaly_tag}"
                f"{log_entry['event_type']:<22} | "
                f"{log_entry['source_ip']:<16} -> {log_entry['dest_ip']:<16} | "
                f"{log_entry['message'][:60]}"
            )

            # Random delay between logs
            delay = random.uniform(LOG_RATE_MIN, LOG_RATE_MAX)
            shutdown_event.wait(delay)

        except KafkaError as e:
            print(f"{Fore.RED}[{agent_name}] Kafka error: {e}{Style.RESET_ALL}")
            time.sleep(1)
        except Exception as e:
            print(f"{Fore.RED}[{agent_name}] Error: {e}{Style.RESET_ALL}")
            time.sleep(1)

    print(f"{color}[{agent_name}] Shutting down... (sent {log_count} logs){Style.RESET_ALL}")


def signal_handler(signum, frame):
    """Handle graceful shutdown on SIGINT/SIGTERM."""
    print(f"\n{Fore.YELLOW}[!] Shutdown signal received. Stopping agents...{Style.RESET_ALL}")
    shutdown_event.set()


def main():
    """Main entry point: start all log collection agent threads."""
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print(f"\n{Fore.CYAN}{'='*70}")
    print(f"  Secure Distributed Log Analysis Platform")
    print(f"  Log Collection Agents")
    print(f"{'='*70}{Style.RESET_ALL}")
    print(f"  Kafka Broker:  {KAFKA_BOOTSTRAP_SERVERS}")
    print(f"  Topic:         {KAFKA_TOPIC_RAW_LOGS}")
    print(f"  Agents:        {NUM_AGENTS}")
    print(f"  Log Rate:      {LOG_RATE_MIN}s - {LOG_RATE_MAX}s per log")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")

    # Create shared Kafka producer
    producer = create_kafka_producer()

    # Start agent threads
    threads = []
    for i in range(NUM_AGENTS):
        agent_name = AGENT_NAMES[i] if i < len(AGENT_NAMES) else f"agent-{i+1:02d}"
        t = threading.Thread(
            target=agent_worker,
            args=(producer, agent_name, KAFKA_TOPIC_RAW_LOGS, i),
            daemon=True,
            name=f"Agent-{agent_name}",
        )
        threads.append(t)
        t.start()

    print(f"\n{Fore.GREEN}[OK] All {NUM_AGENTS} agents started. Press Ctrl+C to stop.{Style.RESET_ALL}\n")

    # Wait for shutdown
    try:
        while not shutdown_event.is_set():
            shutdown_event.wait(1)
    except KeyboardInterrupt:
        shutdown_event.set()

    # Cleanup
    for t in threads:
        t.join(timeout=5)

    producer.flush(timeout=5)
    producer.close()
    print(f"\n{Fore.GREEN}[OK] All agents stopped. Kafka producer closed.{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
