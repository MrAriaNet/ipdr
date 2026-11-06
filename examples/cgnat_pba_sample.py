"""
Sample Cisco ASR-style CGNAT PBA (scattered port set) + security lookup.

Simulates HSL allocate with start/step/num_ports (IEs 361/363/364),
then looks up a public port that belongs to the set (and one that does not).
"""
import requests
from datetime import datetime, timedelta, timezone

API = "http://127.0.0.1:8000/api/cgnat"


def main():
    now = datetime.now(timezone.utc)
    # Cisco example style: start=4000, step=8, num_ports=512
    # ports: 4000, 4008, 4016, ...  end = 4000 + 511*8
    allocate = {
        "event_time": now.isoformat(),
        "event_type": "allocate",
        "inside_ip": "100.64.10.25",
        "outside_ip": "203.0.113.10",
        "port_start": 4000,
        "port_end": 4000 + 511 * 8,
        "port_block_size": 512,
        "port_step": 8,
        "protocol": "ANY",
        "router_ip": "192.0.2.1",
        "source": "sample",
        "mapping_mode": "pba",
    }
    r = requests.post(f"{API}/blocks", json=allocate, timeout=10)
    print("ALLOCATE:", r.status_code, r.text)

    at = (now + timedelta(minutes=5)).isoformat()
    # Port in scattered set (4000 + 1*8)
    ok = requests.get(
        f"{API}/lookup",
        params={"public_ip": "203.0.113.10", "public_port": 4008, "at": at},
        timeout=10,
    )
    print("LOOKUP port 4008 (in set):", ok.status_code, ok.text)

    # Port in numeric span but NOT in scattered set (step 8)
    bad = requests.get(
        f"{API}/lookup",
        params={"public_ip": "203.0.113.10", "public_port": 4001, "at": at},
        timeout=10,
    )
    print("LOOKUP port 4001 (NOT in set):", bad.status_code, bad.text)

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
