"""
Sample CGNAT PBA allocate + security lookup against a running IPDR API.
"""
import requests
from datetime import datetime, timedelta

API = "http://127.0.0.1:8000/api/cgnat"


def main():
    now = datetime.utcnow()
    allocate = {
        "event_time": now.isoformat(),
        "event_type": "allocate",
        "inside_ip": "100.64.10.25",
        "outside_ip": "203.0.113.10",
        "port_start": 1024,
        "port_end": 2047,
        "port_block_size": 1024,
        "protocol": "ANY",
        "router_ip": "192.0.2.1",
        "source": "sample",
    }
    r = requests.post(f"{API}/blocks", json=allocate, timeout=10)
    print("ALLOCATE:", r.status_code, r.text)

    lookup = requests.get(
        f"{API}/lookup",
        params={
            "public_ip": "203.0.113.10",
            "public_port": 1500,
            "at": (now + timedelta(minutes=5)).isoformat(),
        },
        timeout=10,
    )
    print("LOOKUP:", lookup.status_code, lookup.text)

    deallocate = {
        **allocate,
        "event_time": (now + timedelta(hours=1)).isoformat(),
        "event_type": "deallocate",
        "released_at": (now + timedelta(hours=1)).isoformat(),
    }
    r2 = requests.post(f"{API}/blocks", json=deallocate, timeout=10)
    print("DEALLOCATE:", r2.status_code, r2.text)


if __name__ == "__main__":
    main()
