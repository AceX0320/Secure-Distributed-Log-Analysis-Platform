"""
Flask + Socket.IO Dashboard Application

Real-time security dashboard that visualizes processed logs and anomalies.
"""

import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO

from config.settings import DASHBOARD_HOST, DASHBOARD_PORT, DASHBOARD_SECRET_KEY
from dashboard.database import LogDatabase
from dashboard.kafka_consumer import DashboardConsumer

app = Flask(__name__)
app.config["SECRET_KEY"] = DASHBOARD_SECRET_KEY
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

db = LogDatabase()
consumer = None


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def api_stats():
    return jsonify(db.get_stats())


@app.route("/api/event-types")
def api_event_types():
    return jsonify(db.get_event_type_distribution())


@app.route("/api/severity")
def api_severity():
    return jsonify(db.get_severity_distribution())


@app.route("/api/top-ips")
def api_top_ips():
    return jsonify(db.get_top_source_ips())


@app.route("/api/timeline")
def api_timeline():
    return jsonify(db.get_timeline_data())


@app.route("/api/recent-anomalies")
def api_recent_anomalies():
    return jsonify(db.get_recent_anomalies())


@app.route("/api/recent-logs")
def api_recent_logs():
    return jsonify(db.get_recent_logs())


@socketio.on("connect")
def handle_connect():
    print("[Dashboard] Client connected")
    stats = db.get_stats()
    socketio.emit("stats_update", stats)


@socketio.on("disconnect")
def handle_disconnect():
    print("[Dashboard] Client disconnected")


@socketio.on("request_stats")
def handle_request_stats():
    socketio.emit("stats_update", db.get_stats())


def main():
    global consumer
    print("\n" + "=" * 60)
    print("  Secure Distributed Log Analysis Platform")
    print("  Security Dashboard")
    print("=" * 60)
    print(f"  URL: http://localhost:{DASHBOARD_PORT}")
    print("=" * 60 + "\n")

    consumer = DashboardConsumer(socketio, db)
    consumer.start()

    socketio.run(app, host=DASHBOARD_HOST, port=DASHBOARD_PORT,
                 debug=False, use_reloader=False, allow_unsafe_werkzeug=True)


if __name__ == "__main__":
    main()
