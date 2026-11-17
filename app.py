from flask import Flask, render_template_string
import requests
import json
import os
import getpass
from collections import Counter

app = Flask(__name__)

# --- Configuration (override with environment variables) ---
PIHOLE_URL = os.environ.get("PIHOLE_URL", "http://127.0.0.1")
LOG_FILE = os.environ.get("SURICATA_LOG", "/var/log/suricata/eve.json")
DEVICES_FILE = os.environ.get("DEVICES_FILE", "devices.json")
DASHBOARD_HOST = os.environ.get("DASHBOARD_HOST", "127.0.0.1")
DASHBOARD_PORT = int(os.environ.get("DASHBOARD_PORT", "5000"))


def load_devices():
    """Load {ip: friendly_name} from a local, git-ignored JSON file.

    Copy devices.example.json to devices.json and fill in your own devices.
    """
    try:
        with open(DEVICES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Warning: {DEVICES_FILE} not found. "
              "Copy devices.example.json to devices.json and edit it.")
        return {}
    except json.JSONDecodeError as e:
        print(f"Warning: could not parse {DEVICES_FILE}: {e}")
        return {}


DEVICES = load_devices()

# Authenticate with Pi-hole v6
password = getpass.getpass("Enter Pi-hole password: ")

api = requests.Session()
login = api.post(
    f"{PIHOLE_URL}/api/auth",
    json={"password": password},
    timeout=10
)
login.raise_for_status()

sid = login.json()["session"]["sid"]
api.headers.update({"X-FTL-SID": sid})

# Do not retain the password in memory longer than needed
del password

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Network Security Monitor</title>
    <meta http-equiv="refresh" content="15">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #101827;
            color: white;
            margin: 25px;
        }
        h1 { color: #38bdf8; }
        h2 { color: #7dd3fc; }
        .cards {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }
        .card {
            background: #1e293b;
            padding: 20px;
            border-radius: 10px;
            flex: 1;
            min-width: 160px;
        }
        .number {
            font-size: 28px;
            color: #38bdf8;
            margin-top: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            background: #1e293b;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #475569;
            word-break: break-word;
        }
        th { color: #38bdf8; }
        .error { color: #f87171; }
        .status { color: #4ade80; }
    </style>
</head>
<body>

<h1>Network Security Monitoring</h1>
<p class="status">Dashboard running | Refreshes every 15 seconds</p>

<h2>Pi-hole DNS Statistics</h2>
<div class="cards">
    <div class="card">
        Total DNS Queries
        <div class="number">{{ dns.total }}</div>
    </div>
    <div class="card">
        Blocked Queries
        <div class="number">{{ dns.blocked }}</div>
    </div>
    <div class="card">
        Block Percentage
        <div class="number">{{ dns.percent }}%</div>
    </div>
    <div class="card">
        Forwarded Queries
        <div class="number">{{ dns.forwarded }}</div>
    </div>
</div>

{% if dns_error %}
<p class="error">Pi-hole API: {{ dns_error }}</p>
{% endif %}

<h2>Suricata Intrusion Detection</h2>
<div class="cards">
    <div class="card">
        Alerts in Recent Log Window
        <div class="number">{{ total }}</div>
    </div>
    <div class="card">
        High Severity (1–2)
        <div class="number">{{ high }}</div>
    </div>
    <div class="card">
        Events Read
        <div class="number">{{ events }}</div>
    </div>
</div>

<h2>Alert Categories</h2>
<ul>
{% for name, count in categories %}
    <li>{{ name }}: {{ count }}</li>
{% endfor %}
</ul>

<h2>Recent Suricata Alerts</h2>
<table>
<tr>
    <th>Time</th>
    <th>Source</th>
    <th>Destination</th>
    <th>Protocol</th>
    <th>Severity</th>
    <th>Signature</th>
</tr>
{% for a in alerts %}
<tr>
    <td>{{ a.time }}</td>
    <td>{{ a.src }}</td>
    <td>{{ a.dst }}</td>
    <td>{{ a.proto }}</td>
    <td>{{ a.severity }}</td>
    <td>{{ a.signature }}</td>
</tr>
{% endfor %}
</table>

</body>
</html>
"""


def get_pihole_stats():
    response = api.get(
        f"{PIHOLE_URL}/api/stats/summary",
        timeout=10
    )
    response.raise_for_status()

    data = response.json()
    queries = data.get("queries", {})

    return {
        "total": queries.get("total", 0),
        "blocked": queries.get("blocked", 0),
        "percent": queries.get("percent_blocked", 0),
        "forwarded": queries.get("forwarded", 0)
    }


def get_suricata_alerts():
    alerts = []
    categories = Counter()
    total = 0
    high = 0
    events = 0

    if not os.path.exists(LOG_FILE):
        return alerts, categories, total, high, events

    # Read only the last 2 MB to avoid loading the entire log
    with open(LOG_FILE, "rb") as file:
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(max(0, size - 2 * 1024 * 1024))
        if file.tell() > 0:
            file.readline()
        lines = file.readlines()

    known_ips = set(DEVICES.keys())

    for line in lines:
        try:
            data = json.loads(line)
            events += 1

            if data.get("event_type") != "alert":
                continue

            total += 1
            alert = data.get("alert", {})
            severity = alert.get("severity", 0)

            if severity in (1, 2):
                high += 1

            categories[alert.get("category", "Unknown")] += 1
            src_ip = data.get("src_ip", "")
            dst_ip = data.get("dest_ip", "")

            # Ignore alerts that don't involve a known device
            if src_ip not in known_ips and dst_ip not in known_ips:
                continue

            src_name = DEVICES.get(src_ip, "External")
            dst_name = DEVICES.get(dst_ip, "External")

            alerts.append({
                "time": data.get("timestamp", ""),
                "src": src_name,
                "dst": dst_name,
                "proto": data.get("proto", ""),
                "severity": severity,
                "signature": alert.get("signature", "")
            })

        except (json.JSONDecodeError, TypeError):
            continue

    return alerts[-20:][::-1], categories, total, high, events


@app.route("/")
def dashboard():
    dns_error = ""

    try:
        dns = get_pihole_stats()
    except requests.RequestException:
        dns = {
            "total": "Unavailable",
            "blocked": "Unavailable",
            "percent": "Unavailable",
            "forwarded": "Unavailable"
        }
        dns_error = "Could not retrieve statistics. Check Pi-hole."

    alerts, categories, total, high, events = get_suricata_alerts()

    return render_template_string(
        HTML,
        dns=dns,
        dns_error=dns_error,
        alerts=alerts,
        categories=categories.most_common(),
        total=total,
        high=high,
        events=events
    )


if __name__ == "__main__":
    try:
        app.run(host=DASHBOARD_HOST, port=DASHBOARD_PORT, debug=False)
    finally:
        try:
            api.delete(
                f"{PIHOLE_URL}/api/auth",
                timeout=5
            )
        except requests.RequestException:
            pass
