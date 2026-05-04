# Secure Distributed Log Analysis Platform

A production-grade distributed platform for scalable security log analysis featuring real-time AI-powered anomaly detection.

## Architecture

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────────────┐     ┌─────────────────────┐
│  Log Collection   │     │   Message Broker  │     │  Processing Cluster      │     │  Security Dashboard  │
│    Agents (3x)    │────▶│   Apache Kafka    │────▶│  Spark Structured        │────▶│  Flask + Socket.IO   │
│  (Multi-threaded) │     │   (KRaft Mode)    │     │  Streaming + AI (IF)     │     │  Real-time Charts    │
└──────────────────┘     └──────────────────┘     └──────────────────────────┘     └─────────────────────┘
```

### Components

|Component|Technology|Purpose|
|-|-|-|
|Log Agents|Python + kafka-python|Generate \& publish security events|
|Message Broker|Apache Kafka (KRaft)|Durable event streaming backbone|
|Stream Processor|PySpark Structured Streaming|Real-time log processing \& ML inference|
|Anomaly Detection|scikit-learn Isolation Forest|Unsupervised AI anomaly detection|
|Dashboard|Flask + Socket.IO + Plotly.js|Real-time security visualization|
|Storage|SQLite|Persistent log storage|
|Orchestration|Docker Compose|Container management|

### Kafka Topics

* `raw-logs` — Raw security events from agents
* `processed-logs` — All logs after Spark processing
* `anomalous-logs` — ML-detected anomalies only

## Prerequisites

* **Docker Desktop** — Required for all platforms (Windows, macOS, Linux)
* **Python 3.8+** — For running the dashboard locally
* **pip** — Python package manager

> **Note:** Java and Hadoop are **NOT** required on your local machine. The Spark processor runs entirely inside the Docker container, so no local Java/Hadoop setup is needed.

Follow these steps **in order** to ensure data synchronization and persistence. The system is now configured to automatically catch up on any logs produced while components are offline.

### Step 1: Install Python Dependencies

```bash
pip install -r requirements.txt
```

### Step 2: Start the Infrastructure (Kafka + Spark + Agents)

This starts Kafka (message broker), Spark (master + worker), and 3 log-generation agents:

```bash
docker-compose up -d --build
```

Wait ~30 seconds for services to become healthy. Verify:

* Kafka Broker: Topics created automatically by the `kafka-init` container
* Spark Master UI: http://localhost:8080
* Spark Worker UI: http://localhost:8081

Run the PySpark stream processing job inside the `spark-master` container. This job extracts features, calculates anomaly scores, and routes logs to the correct topics.

```bash
docker exec spark-master /opt/spark/bin/spark-submit --packages org.apache.spark:spark-sql-kafka-0-10_2.12:3.5.3 /app/processing/spark_processor.py
```

You should see `[SparkProcessor] Streaming queries started. Waiting for data...` once it is ready. It will automatically catch up on any logs sent to Kafka while it was offline.

### Step 4: Start the Dashboard *(new terminal)*

```bash
python dashboard/app.py
```

Dashboard: **http://localhost:5000**

You should see:
```
[DashboardConsumer] Connected to topic: processed-logs
[DashboardConsumer] Connected to topic: anomalous-logs
```

### Step 5 (Optional): Train the AI Model

The ML model is used for batch analysis only (not required for real-time streaming):

```bash
python models/train_model.py
```

This generates 10,000 synthetic logs, trains an Isolation Forest model, and saves it to `models/isolation_forest_model.pkl`.

## Data Synchronization & Persistence

The platform is designed to handle intermittent service interruptions:
*   **Kafka Persistence**: Kafka stores data in persistent Docker volumes.
*   **Spark Checkpoints**: Spark uses the `./checkpoints` directory to track its progress. If you restart the processor, it resumes exactly where it left off.
*   **Database Sync**: The dashboard automatically fetches recent history from `logs.db` on load, and its Kafka consumer uses an `earliest` policy to ensure no processed logs are missed during downtime.
*   **Duplicate Prevention**: The database uses a unique constraint on `(agent, sequence)` to ensure that re-processed logs do not create duplicate entries.

## Shutdown

Follow these steps **in order** to cleanly stop everything:

### 1. Stop the Dashboard

In the terminal running `python dashboard/app.py`, press **Ctrl+C**.

### 2. Stop the Spark Processor

In the terminal running the `docker exec` Spark command, press **Ctrl+C**.

### 3. Stop All Docker Containers

```bash
docker-compose down
```

To also remove persistent data volumes (Kafka logs, Spark work dirs):

```bash
docker-compose down -v
```

> **⚠️ If you closed a terminal without pressing Ctrl+C** and the dashboard is still running on port 5000, find and kill the orphaned process:
>
> **Windows:**
> ```powershell
> netstat -ano | findstr :5000
> taskkill /PID <PID_NUMBER> /F
> ```
>
> **macOS / Linux:**
> ```bash
> lsof -i :5000
> kill -9 <PID_NUMBER>
> ```

## Project Structure

```
├── docker-compose.yml          # Kafka + Spark containers
├── requirements.txt            # Python dependencies
├── config/
│   └── settings.py             # Centralized configuration
├── agents/
│   ├── log\_generator.py        # Realistic security log generator
│   └── kafka\_producer.py       # Multi-threaded Kafka producer
├── processing/
│   ├── log\_parser.py           # Feature extraction pipeline
│   ├── anomaly\_detector.py     # Isolation Forest ML detector
│   └── spark\_processor.py      # Spark Structured Streaming job
├── models/
│   └── train\_model.py          # Model training script
├── dashboard/
│   ├── app.py                  # Flask + Socket.IO server
│   ├── kafka\_consumer.py       # Dashboard Kafka consumer
│   ├── database.py             # SQLite persistence layer
│   ├── templates/index.html    # Dashboard UI
│   └── static/                 # CSS + JS assets
└── tests/                      # Unit \& integration tests
```

## AI/ML Details

### Isolation Forest Algorithm

* **Type**: Unsupervised anomaly detection
* **Training**: 10,000 synthetic log samples
* **Contamination**: 15% (expected anomaly rate)
* **Features**: 8 numerical features extracted from each log
* **Output**: Anomaly score + binary classification

### Feature Engineering

|Feature|Description|
|-|-|
|severity\_score|Numerical severity (1-5)|
|bytes\_transferred|Data volume|
|port|Target port number|
|hour\_of\_day|Time component (0-23)|
|minute\_of\_hour|Time component (0-59)|
|is\_privileged\_port|Port < 1024|
|is\_common\_attack\_port|Known attack port|
|request\_length|Log message length|

### Attack Types Detected

* Brute Force, SQL Injection, XSS, Command Injection
* Port Scanning, DDoS Attempts
* Privilege Escalation, Data Exfiltration
* Malware Detection, Unauthorized Access

## Running Tests

```bash
python -m pytest tests/ -v
```

## Configuration

All settings are in `config/settings.py` and can be overridden via environment variables:

|Variable|Default|Description|
|-|-|-|
|KAFKA\_BOOTSTRAP\_SERVERS|localhost:9094|Kafka broker address|
|SPARK\_MASTER\_URL|spark://localhost:7077|Spark master|
|NUM\_AGENTS|3|Number of log agents|
|ANOMALY\_PROBABILITY|0.15|Attack event probability|
|DASHBOARD\_PORT|5000|Dashboard port|

## Tools \& Technologies

* **Apache Kafka** — Distributed event streaming
* **Apache Spark** — Distributed stream processing
* **Python** — Core programming language
* **scikit-learn** — Machine learning
* **Flask + Socket.IO** — Real-time web dashboard
* **Plotly.js** — Interactive data visualization
* **Docker** — Containerized deployment

