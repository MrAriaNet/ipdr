"""
Sample CGNAT PBA (no NAT connection / XLATE table) against a running IPDR API.

Demonstrates:
  - allocate a port block
  - security lookup by public_ip:public_port (any port inside the block)
  - reverse lookup by subscriber inside_ip
  - deallocate
"""
import requests
from datetime import datetime, timedelta

API = "http://127.0.0.1:8000/api/cgnat"


def main():
    now = datetime.utcnow()
    # Pure PBA event — no inside_port, no destination, no session id
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

    # Mid-block public port — must resolve without a connection table
    lookup = requests.get(
        f"{API}/lookup",
        params={
            "public_ip": "203.0.113.10",
            "public_port": 1500,
            "at": (now + timedelta(minutes=5)).isoformat(),
        },
        timeout=10,
    )
    print("LOOKUP (public→inside):", lookup.status_code, lookup.text)

    reverse = requests.get(
        f"{API}/lookup/by-subscriber",
        params={
            "inside_ip": "100.64.10.25",
            "at": (now + timedelta(minutes=5)).isoformat(),
        },
        timeout=10,
    )
    print("LOOKUP (inside→blocks):", reverse.status_code, reverse.text)

    deallocate = {
        **allocate,
        "event_time": (now + timedelta(hours=1)).isoformat(),
        "event_type": "deallocate",
        "released_at": (now + timedelta(hours=1)).isoformat(),
    }
    r2 = requests.post(f"{API}/blocks", json=deallocate, timeout=10)
    print("DEALLOCATE:", r2.status_code, r2.text)

    # After release, same public port should not map to this subscriber
    after = requests.get(
        f"{API}/lookup",
        params={
            "public_ip": "203.0.113.10",
            "public_port": 1500,
            "at": (now + timedelta(hours=2)).isoformat(),
        },
        timeout=10,
    )
    print("LOOKUP after release:", after.status_code, after.text)


if __name__ == "__main__":
    main()
