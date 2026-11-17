import os
import getpass

import requests

BASE_URL = os.environ.get("PIHOLE_URL", "http://127.0.0.1")

password = getpass.getpass("Enter Pi-hole password: ")

try:
    session = requests.Session()

    login = session.post(
        f"{BASE_URL}/api/auth",
        json={"password": password},
        timeout=10
    )
    del password

    print("Login HTTP status:", login.status_code)

    # Never print the full login response: it contains the session ID (SID).
    auth_data = login.json()
    sid = auth_data.get("session", {}).get("sid")

    if not sid:
        print("Authentication failed.")
        raise SystemExit(1)

    response = session.get(
        f"{BASE_URL}/api/stats/summary",
        headers={"X-FTL-SID": sid},
        timeout=10
    )
    response.raise_for_status()

    print("\nAuthentication successful!")
    print("Pi-hole API response:")
    print(response.json())

    session.delete(
        f"{BASE_URL}/api/auth",
        json={"sid": sid},
        timeout=10
    )

except requests.RequestException as error:
    print("API request failed:", error)
