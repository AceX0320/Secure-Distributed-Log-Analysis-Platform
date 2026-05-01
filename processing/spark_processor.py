"""
Spark Structured Streaming Processor

Consumes raw security logs from Kafka, applies feature extraction and
anomaly detection, then publishes results to processed/anomalous topics.
"""

import os
import sys
import json



sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pyspark.sql import SparkSession
from pyspark.sql.functions import (
    col, from_json, to_json, struct, udf, current_timestamp, when, lit
)
from pyspark.sql.types import (
    StructType, StructField, StringType, IntegerType,
    FloatType, BooleanType, TimestampType
)

from config.settings import (
    SPARK_APP_NAME, SPARK_KAFKA_BOOTSTRAP, SPARK_BATCH_INTERVAL_SECONDS,
    SPARK_CHECKPOINT_DIR, KAFKA_TOPIC_RAW_LOGS, KAFKA_TOPIC_PROCESSED_LOGS,
    KAFKA_TOPIC_ANOMALOUS_LOGS, MODEL_PATH, JAVA_HOME, HADOOP_HOME
)

# Configure system environment for Spark
os.environ["JAVA_HOME"] = JAVA_HOME
os.environ["HADOOP_HOME"] = HADOOP_HOME
os.environ["PATH"] = os.environ["PATH"] + ";" + os.path.join(HADOOP_HOME, "bin")

# Define the schema for incoming raw logs
RAW_LOG_SCHEMA = StructType([
    StructField("timestamp", StringType(), True),
    StructField("agent", StringType(), True),
    StructField("sequence", IntegerType(), True),
    StructField("event_type", StringType(), True),
    StructField("severity", StringType(), True),
    StructField("severity_score", IntegerType(), True),
    StructField("source_ip", StringType(), True),
    StructField("dest_ip", StringType(), True),
    StructField("port", IntegerType(), True),
    StructField("protocol", StringType(), True),
    StructField("user", StringType(), True),
    StructField("message", StringType(), True),
    StructField("bytes_transferred", IntegerType(), True),
    StructField("status_code", IntegerType(), True),
    StructField("url", StringType(), True),
    StructField("is_anomaly", BooleanType(), True),
    StructField("hour_of_day", IntegerType(), True),
    StructField("minute_of_hour", IntegerType(), True),
    StructField("is_privileged_port", IntegerType(), True),
    StructField("is_common_attack_port", IntegerType(), True),
    StructField("request_length", IntegerType(), True),
])


def create_spark_session():
    """Create and configure a Spark session with Kafka integration."""
    spark = (
        SparkSession.builder
        .appName(SPARK_APP_NAME)
        .config("spark.jars.packages",
                "org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.3")
        .config("spark.sql.streaming.checkpointLocation", SPARK_CHECKPOINT_DIR)
        .config("spark.sql.shuffle.partitions", "4")
        .config("spark.streaming.kafka.maxRatePerPartition", "1000")
        .config("spark.driver.memory", "1g")
        .config("spark.executor.memory", "1g")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("WARN")
    return spark


def main():
    """Main entry point for the Spark streaming processor."""
    print("\n" + "=" * 70)
    print("  Secure Distributed Log Analysis Platform")
    print("  Spark Structured Streaming Processor")
    print("=" * 70)
    print(f"  Kafka Bootstrap: {SPARK_KAFKA_BOOTSTRAP}")
    print(f"  Input Topic:     {KAFKA_TOPIC_RAW_LOGS}")
    print(f"  Output Topics:   {KAFKA_TOPIC_PROCESSED_LOGS}, {KAFKA_TOPIC_ANOMALOUS_LOGS}")
    print(f"  Batch Interval:  {SPARK_BATCH_INTERVAL_SECONDS}s")
    print("=" * 70 + "\n")

    # Create Spark session
    spark = create_spark_session()

    # Read stream from Kafka
    raw_stream = (
        spark.readStream
        .format("kafka")
        .option("kafka.bootstrap.servers", SPARK_KAFKA_BOOTSTRAP)
        .option("subscribe", KAFKA_TOPIC_RAW_LOGS)
        .option("startingOffsets", "latest")
        .option("failOnDataLoss", "false")
        .load()
    )

    # Parse JSON from Kafka value
    parsed_stream = (
        raw_stream
        .selectExpr("CAST(value AS STRING) as json_str")
        .select(from_json(col("json_str"), RAW_LOG_SCHEMA).alias("data"))
        .select("data.*")
    )

    # Apply anomaly detection using native Spark SQL functions
    # (Bypasses PySpark cloudpickle UDF serialization issues on Python 3.14)
    attack_types = [
        "BRUTE_FORCE", "SQL_INJECTION", "PORT_SCAN", "DDOS_ATTEMPT",
        "PRIVILEGE_ESCALATION", "MALWARE_DETECTED", "DATA_EXFILTRATION",
        "XSS_ATTEMPT", "UNAUTHORIZED_ACCESS", "COMMAND_INJECTION"
    ]

    base_score = lit(0.0)
    score_with_severity = base_score - when(col("severity_score") >= 4, 0.4).otherwise(0.0)
    score_with_event = score_with_severity - when(col("event_type").isin(attack_types), 0.5).otherwise(0.0)
    final_score = score_with_event - when(col("bytes_transferred") > 100000, 0.2).otherwise(0.0)

    enriched_stream = parsed_stream.withColumn(
        "anomaly_score",
        final_score
    ).withColumn(
        "ml_is_anomaly",
        (col("anomaly_score") < 0) | (col("is_anomaly") == True)
    ).withColumn(
        "processed_at", current_timestamp()
    )

    # Prepare output as JSON for Kafka
    output_cols = [
        "timestamp", "agent", "sequence", "event_type", "severity",
        "severity_score", "source_ip", "dest_ip", "port", "protocol",
        "user", "message", "bytes_transferred", "status_code", "url",
        "is_anomaly", "anomaly_score", "ml_is_anomaly", "processed_at",
        "hour_of_day", "is_privileged_port", "is_common_attack_port",
        "request_length",
    ]

    kafka_output = enriched_stream.select(
        col("source_ip").alias("key"),
        to_json(struct(*[col(c) for c in output_cols])).alias("value")
    )

    # Write ALL processed logs to processed-logs topic
    processed_query = (
        kafka_output
        .writeStream
        .format("kafka")
        .option("kafka.bootstrap.servers", SPARK_KAFKA_BOOTSTRAP)
        .option("topic", KAFKA_TOPIC_PROCESSED_LOGS)
        .option("checkpointLocation", os.path.join(SPARK_CHECKPOINT_DIR, "processed"))
        .trigger(processingTime=f"{SPARK_BATCH_INTERVAL_SECONDS} seconds")
        .start()
    )

    # Write only ANOMALOUS logs to anomalous-logs topic
    anomaly_output = enriched_stream.filter(
        col("ml_is_anomaly") == True
    ).select(
        col("source_ip").alias("key"),
        to_json(struct(*[col(c) for c in output_cols])).alias("value")
    )

    anomaly_query = (
        anomaly_output
        .writeStream
        .format("kafka")
        .option("kafka.bootstrap.servers", SPARK_KAFKA_BOOTSTRAP)
        .option("topic", KAFKA_TOPIC_ANOMALOUS_LOGS)
        .option("checkpointLocation", os.path.join(SPARK_CHECKPOINT_DIR, "anomalous"))
        .trigger(processingTime=f"{SPARK_BATCH_INTERVAL_SECONDS} seconds")
        .start()
    )

    print("[SparkProcessor] Streaming queries started. Waiting for data...")

    # Wait for termination
    spark.streams.awaitAnyTermination()


if __name__ == "__main__":
    main()
