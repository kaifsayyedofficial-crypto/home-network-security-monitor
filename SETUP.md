# Setup Guide

## Requirements

- Ubuntu VM with access to the Pi-hole host
- Python 3.10 or newer
- Pi-hole v6 reachable from the VM
- Suricata installed and writing EVE JSON events
- Git

## 1. Clone the repository

```bash
git clone https://github.com/kaifsayyedofficial-crypto/home-network-security-monitor.git
cd home-network-security-monitor
```

## 2. Create and activate a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

## 3. Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## 4. Check Suricata

```bash
sudo systemctl status suricata
```

Check whether the EVE log is readable:

```bash
sudo test -r /var/log/suricata/eve.json && echo "EVE log is readable" || echo "Check log permissions"
```

## 5. Check Pi-hole

Open the Pi-hole admin page in a browser:

```text
http://<PIHOLE_IP>/admin
```

Use your actual Pi-hole address. Do not put passwords or API session IDs
in source code or commit them.

## 6. Run the application

Use the launch command documented in the current `app.py`. The exact command
has not been verified against the source code in this repository.

If the app listens on port 5000, open:

```text
http://<UBUNTU_VM_IP>:5000
```

## Troubleshooting

- For Pi-hole authentication errors, check reachability and local credentials.
- If alerts are missing, check Suricata status and EVE log updates.
- If Flask cannot read `eve.json`, configure least-privilege file permissions.
- No displayed alerts does not prove that no suspicious activity occurred.

## Scope and limitations

Use this project only on networks you own or are authorized to monitor.
Suricata on a bridged Wi-Fi VM may not observe all traffic between wireless
clients.
