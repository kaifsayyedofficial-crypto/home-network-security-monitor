# 🛡️ Home Network Security Monitoring Dashboard

A home-lab **defensive monitoring** project that combines **Pi-hole**, **Suricata**, an **Ubuntu VM**, and a **Flask** web dashboard. It demonstrates DNS filtering and visibility, network intrusion-detection concepts, Linux service administration, Python integration, and dashboard development.

> **⚠️ Scope:** This is a learning project for a network you own or have permission to monitor. It is a monitoring/alerting lab, **not** an automated blocking system.

![Dashboard overview](docs/dashboard-overview.png)

---

## 📑 Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [Lab Environment](#3-lab-environment)
4. [Features](#4-features)
5. [Software and Services](#5-software-and-services)
6. [Installation and Setup](#6-installation-and-setup)
7. [How the Application Works](#7-how-the-application-works)
8. [Validation and Testing](#8-validation-and-testing)
9. [Repository Structure](#9-repository-structure)
10. [Security and Privacy Before Publishing](#10-security-and-privacy-before-publishing)
11. [Known Limitations](#11-known-limitations)
12. [Future Improvements](#12-future-improvements)
13. [References](#13-references)

---

## 1. Project Overview

The Ubuntu virtual machine runs:

- **Pi-hole**: DNS sinkhole that receives DNS requests from configured home devices, forwards permitted requests to an upstream resolver, and blocks domains on its blocklists.
- **Suricata**: network intrusion detection system (IDS) that inspects packets visible to its network interface and writes events/alerts to an EVE JSON log.
- **Flask**: Python web framework serving a local dashboard.
- **Python Requests**: calls the Pi-hole v6 API to retrieve aggregate DNS statistics.
- **JSON processing**: reads Suricata's `eve.json` events and extracts alert fields.

The dashboard displays aggregate Pi-hole DNS statistics and recent Suricata alerts. A small IP-to-name dictionary labels known home devices. The alert filter retains only alerts whose source or destination matches one of the configured known device IP addresses.

---

## 2. Architecture

```text
Known home devices
(phone / laptop / other clients)
          |
          | DNS requests (if configured to use Pi-hole)
          v
Home router (DHCP advertises Pi-hole DNS)
          |
          v
Ubuntu VM: 192.168.0.117
  +--------------------------+
  | Pi-hole DNS service      |----> Upstream DNS (Quad9 configured)
  |                          |
  | Suricata IDS             |----> /var/log/suricata/eve.json
  |                          |
  | Flask dashboard :5000    |
  +--------------------------+
          ^
          |
Laptop browser on home LAN
http://192.168.0.117:5000
```

### Important visibility limitation

- Pi-hole can report DNS requests only from clients that actually use it. It does not reveal every app action or every full URL. HTTPS and encrypted DNS further limit what DNS monitoring can show.
- Suricata only inspects packets delivered to the VM's interface. A bridged VM on Wi-Fi is **not guaranteed to see all unicast traffic between other wireless clients**.

Therefore, this lab should **not** be described as complete, whole-network packet monitoring. For reliable full-LAN visibility, a suitable router/AP traffic-mirroring feature or a network TAP is normally needed.

---

## 3. Lab Environment

> Record your own final versions and configuration before publishing.

| Item | Current project setup |
|---|---|
| Host | Lenovo IdeaPad Gaming 3 |
| Host CPU | AMD Ryzen 5 5600H |
| Host memory | 8 GB |
| Virtualization | VMware VM |
| Guest OS | Ubuntu |
| VM network | Bridged to host Wi-Fi (VMware VMnet0) |
| Guest interface | `ens33` |
| Ubuntu VM IP | `192.168.0.117` (DHCP reservation) |
| LAN subnet | `192.168.0.0/24` |
| Router | TP-Link TL-WR845N, `192.168.0.1` |
| DNS monitoring | Pi-hole v6 |
| IDS | Suricata 8.0.6 |
| Dashboard | Flask 3.1.3, Python 3.14.8 |
| Dashboard URL | `http://192.168.0.117:5000` (LAN only) |

*Replace or remove private addresses, hardware details, and device labels if you prefer not to publish them.*

---

## 4. Features

- 📊 Pi-hole aggregate DNS query, blocked query, block percentage, and forwarded query statistics
- 🚨 Suricata alert count, severity 1–2 count, event count, alert categories, and a recent alert table
- 🏷️ Friendly labels for known IP addresses
- 🎯 Filter to show only alerts involving configured known device IPs
- 🌐 External endpoint labels instead of displaying unrelated external IP addresses
- 🔄 Auto-refreshing dashboard (every 15 seconds)
- 🔒 Local-LAN access, with UFW rules restricting dashboard access to the LAN

---

## 5. Software and Services

| Component | Role |
|---|---|
| Ubuntu | Linux operating system hosting the services |
| VMware | Runs Ubuntu as a virtual machine |
| Pi-hole | DNS filtering and DNS query statistics |
| Suricata | Network IDS; generates EVE JSON events |
| Flask | Hosts the dashboard web application |
| Requests | Makes HTTP requests to the Pi-hole API |
| UFW | Host firewall |
| Python `json` | Parses Suricata JSON log lines |
| Python `collections.Counter` | Counts alert categories |

---

## 6. Installation and Setup

The following is a reproducible outline. Review the current official installation instructions before installing software, because versions and commands can change.

### Ubuntu preparation

```bash
sudo apt update
sudo apt upgrade -y
```

### Python project environment

```bash
mkdir -p ~/network-monitor
cd ~/network-monitor
sudo apt install python3-venv python3-pip -y
python3 -m venv venv
source venv/bin/activate
pip install flask requests
```

`venv` isolates this project's Python packages from system Python packages.

### Pi-hole

Install Pi-hole using its official installation guide. Configure the router's DHCP DNS setting to advertise the Pi-hole VM address to clients. Reserve the VM's address in the router so it does not change unexpectedly.

Dashboard API access uses Pi-hole v6 authentication. The app prompts for the password at runtime. **Never put the password, session ID, or any other secret directly in source code or Git.**

### Suricata

Install Suricata using the official instructions for your Ubuntu release. Configure the monitored interface in `suricata.yaml`, validate the configuration, update rules, and enable the service.

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo suricata-update
sudo systemctl enable --now suricata
sudo systemctl status suricata --no-pager
```

### Firewall

The project used UFW to permit only required services from the home LAN. Review your own rules before applying any firewall command, and do not blindly copy rules to a different network.

Example inspection commands:

```bash
sudo ufw status numbered
sudo ss -ltnup
```

### Run the dashboard

```bash
cd ~/network-monitor
source venv/bin/activate
python -m py_compile app.py
python app.py
```

Open the dashboard from a device on the same LAN:

```text
http://192.168.0.117:5000
```

> The Flask development server is suitable for a local learning demo only. Do not expose it directly to the public internet.

---

## 7. How the Application Works

1. Flask starts and requests the Pi-hole password using a hidden terminal prompt.
2. The app authenticates to Pi-hole v6 and receives a temporary session ID.
3. The app sends that session ID in the `X-FTL-SID` header when requesting `/api/stats/summary`.
4. The app reads the recent portion of `/var/log/suricata/eve.json`.
5. Each JSON line is parsed. Non-alert events are skipped for the alert table.
6. For each alert, the source and destination IPs are checked against the `DEVICES` dictionary.
7. Alerts that do not involve a known device are skipped. A non-matching endpoint on a retained alert is labelled `External`.
8. Flask renders the values into an HTML page, which refreshes periodically.
9. When the app exits, it attempts to end the Pi-hole API session.

---

## 8. Validation and Testing

Use only your own lab devices and ordinary browsing/DNS activity.

| Test | Expected observation |
|---|---|
| Open Pi-hole admin page | Pi-hole web interface loads on the LAN |
| Browse normally from a configured client | Client DNS activity appears in Pi-hole |
| Query a domain on a blocklist | Pi-hole reports a blocked query |
| Check Suricata service | `active (running)` |
| Validate Suricata config | Test command reports successful configuration |
| Open Flask dashboard | Dashboard loads from a LAN browser |
| Generate ordinary home-network activity | Dashboard statistics update on refresh |
| Compare known-device labels | Configured local IPs show friendly labels |
| Check alert filter | Only alerts involving configured IPs appear |

> An alert is not automatically proof of an attack. Review the signature, context, source, destination, severity, and whether the alert is a known false positive before drawing conclusions.

### Screenshots

| Pi-hole DNS statistics | Suricata alerts |
|---|---|
| ![Pi-hole](docs/pihole-dns-statistics.png) | ![Suricata](docs/suricata-alerts.png) |

---

## 9. Repository Structure

```text
home-network-security-monitor/
├── app.py
├── README.md
├── requirements.txt
├── .gitignore
├── docs/
│   ├── architecture.png
│   ├── dashboard-overview.png
│   ├── pihole-dns-statistics.png
│   ├── suricata-alerts.png
│   ├── validation-tests.png
│   └── technical-report.pdf
└── screenshots/
    └── (optional additional redacted screenshots)
```

Do not commit the virtual environment, logs, credentials, session tokens, or private data.

---

## 10. Security and Privacy Before Publishing

- Do not publish Pi-hole passwords, API session IDs, cookies, tokens, or `.env` secrets.
- Do not commit `venv/`, cache files, large EVE logs, or raw packet captures.
- Redact public IP addresses, MAC addresses, personal device names, usernames, Wi-Fi SSIDs, and sensitive browser tabs from screenshots.
- Consider replacing real device labels with generic ones such as `Test Phone A`.
- Keep the dashboard bound/restricted to the local network; do not port-forward it to the internet.
- Use a production WSGI server and proper authentication before any deployment beyond a private lab.

Suggested `.gitignore`:

```gitignore
venv/
__pycache__/
*.py[cod]
.env
*.log
*.pcap
eve.json
fast.log
.DS_Store
```

---

## 11. Known Limitations

- Pi-hole statistics are DNS-level, not a full record of web browsing.
- Clients using a VPN, Android Private DNS, manually configured DNS, or other encrypted DNS may bypass Pi-hole.
- Suricata's visibility depends on the traffic the VM interface receives. Bridged Wi-Fi does not guarantee visibility of all client-to-client or client-to-internet unicast traffic.
- Device names are based on manually configured IP mappings. DHCP changes can make labels stale unless reservations are maintained.
- The dashboard is a monitoring prototype, not a SIEM, endpoint agent, or automatic prevention system.
- Flask's built-in development server is not intended for public production deployment.

---

## 12. Future Improvements

- Port mirroring or a network TAP for full-LAN packet visibility
- Production WSGI server (e.g. Gunicorn) behind a reverse proxy with authentication
- Dynamic device discovery instead of a static IP-to-name dictionary
- Historical storage and trend charts for DNS and alert data
- Notifications (email/Telegram) for high-severity alerts

---

## 13. References

- [Pi-hole documentation](https://docs.pi-hole.net/)
- [Suricata documentation](https://docs.suricata.io/)
- [Flask documentation](https://flask.palletsprojects.com/)
- [Ubuntu documentation](https://help.ubuntu.com/)
- UFW manual: `man ufw`

---

## 👤 Author

**Kaif Sayyed**: B.E. Computer Engineering (Honours in Cyber Security), Mumbai University

## 📄 License

Add a license of your choice (e.g. [MIT](https://choosealicense.com/licenses/mit/)) and place a `LICENSE` file in the repository root.
