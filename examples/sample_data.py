"""
Sample script for generating IPDR test data
"""
import requests
import random
from datetime import datetime, timedelta
from typing import List

API_BASE = "http://localhost:8000/api/ipdr"


def generate_sample_records(count: int = 10) -> List[dict]:
    """Generate sample records"""
    records = []
    base_time = datetime.now() - timedelta(days=1)
    
    source_ips_v4 = [
        "192.168.1.10", "192.168.1.20", "10.0.0.5", "172.16.0.10"
    ]
    dest_ips_v4 = [
        "8.8.8.8", "1.1.1.1", "93.184.216.34", "151.101.1.140"
    ]
    source_ips_v6 = [
        "2001:db8::10", "2001:db8::20", "fd12:3456:789a::1"
    ]
    dest_ips_v6 = [
        "2001:4860:4860::8888", "2606:4700:4700::1111", "2001:db8:1::53"
    ]

    # name, number
    protocols = [
        ("TCP", 6), ("UDP", 17), ("ICMP", 1), ("ICMPv6", 58),
        ("GRE", 47), ("ESP", 50), ("SCTP", 132), ("OSPFIGP", 89),
    ]
    services = ["HTTP", "HTTPS", "DNS", "SSH", "FTP", "SMTP", None]

    for i in range(count):
        start_time = base_time + timedelta(
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59)
        )
        duration = random.randint(1, 3600)
        end_time = start_time + timedelta(seconds=duration)

        bytes_up = random.randint(1000, 10000000)
        bytes_down = random.randint(10000, 100000000)
        use_v6 = random.random() < 0.4
        proto_name, proto_num = random.choice(protocols)
        if use_v6 and proto_name == "ICMP":
            proto_name, proto_num = "ICMPv6", 58

        record = {
            "source_ip": random.choice(source_ips_v6 if use_v6 else source_ips_v4),
            "source_port": random.randint(1024, 65535),
            "destination_ip": random.choice(dest_ips_v6 if use_v6 else dest_ips_v4),
            "destination_port": random.choice([80, 443, 53, 22, 21, 25, 3306]),
            "ip_version": 6 if use_v6 else 4,
            "protocol": proto_name,
            "protocol_number": proto_num,
            "session_start_time": start_time.isoformat(),
            "session_end_time": end_time.isoformat(),
            "duration_seconds": duration,
            "bytes_uploaded": bytes_up,
            "bytes_downloaded": bytes_down,
            "total_bytes": bytes_up + bytes_down,
            "packets_uploaded": random.randint(10, 1000),
            "packets_downloaded": random.randint(100, 10000),
            "total_packets": random.randint(110, 11000),
            "service_type": random.choice(services),
            "application_name": random.choice(["Browser", "FTP Client", "SSH Client", None]),
            "user_id": f"user_{random.randint(1, 5)}",
            "billing_model": random.choice(["prepaid", "postpaid", "hybrid"]),
            "cost": round(random.uniform(0.01, 10.0), 2),
            "is_suspicious": random.random() < 0.1,
            "threat_type": random.choice([None, "suspicious_port", "unusual_rst"]) if random.random() < 0.1 else None
        }
        records.append(record)
    
    return records


def create_records(records: List[dict]):
    """Send records to API"""
    created = 0
    failed = 0
    
    for record in records:
        try:
            response = requests.post(f"{API_BASE}/records", json=record)
            if response.status_code == 201:
                created += 1
                print(f"[SUCCESS] Record {created} created: {record['source_ip']} -> {record['destination_ip']}")
            else:
                failed += 1
                print(f"[ERROR] Failed to create record: {response.status_code} - {response.text}")
        except Exception as e:
            failed += 1
            print(f"[ERROR] Exception: {str(e)}")
    
    print(f"\n[SUCCESS] {created} records created successfully")
    if failed > 0:
        print(f"[ERROR] {failed} records failed")


def main():
    """Main function"""
    print("[INFO] Starting IPDR sample data generation...\n")
    
    # Check API connection
    try:
        response = requests.get(f"{API_BASE.replace('/api/ipdr', '')}/health")
        if response.status_code != 200:
            print("[ERROR] Server is not available. Please start the server first.")
            return
    except Exception as e:
        print(f"[ERROR] Connection error: {str(e)}")
        print("Please make sure the server is running (uvicorn app.main:app)")
        return
    
    # Generate and create records
    records = generate_sample_records(count=20)
    create_records(records)
    
    print("\n[INFO] View data at:")
    print("   http://localhost:8000/dashboard")


if __name__ == "__main__":
    main()
