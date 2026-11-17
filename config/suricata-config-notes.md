# Configuration Notes

This project combines Pi-hole DNS statistics with Suricata IDS alerts in a
Python Flask dashboard.

## Runtime configuration

- Ubuntu VM interface: `ens33` (development environment example)
- Suricata EVE JSON log: `/var/log/suricata/eve.json`
- Flask dashboard port: `5000`
- Pi-hole host: configure for your own LAN
- Pi-hole API: Pi-hole v6 authentication flow

## Before running

1. Confirm Pi-hole is reachable from the Ubuntu VM.
2. Confirm Suricata is running and writing `eve.json`.
3. Ensure the Flask process can read the Suricata log using least-privilege
   permissions.
4. Restrict dashboard access to your trusted network using the host firewall.
5. Replace example interface names, IP addresses and paths for your setup.

## Secrets and privacy

Never commit passwords, API session IDs, tokens, `.env` files, raw logs,
real MAC addresses, or personal device names. Keep `devices.example.json`
limited to placeholder values.

## Monitoring limitation

Suricata in a VMware bridged Wi-Fi VM may not see every unicast packet
between other wireless clients. Describe this as monitoring traffic visible
to the VM, not guaranteed full-LAN visibility.
