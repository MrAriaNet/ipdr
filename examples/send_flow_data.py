"""
Example script for sending flow data to the simple collector
Useful for testing or routers that don't support NetFlow
"""
import socket
import json
import time
import random
from datetime import datetime, timedelta
from typing import Dict

COLLECTOR_HOST = "localhost"
COLLECTOR_PORT = 9999


def send_flow(flow_data: Dict):
    """Send flow data to collector"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        data = json.dumps(flow_data).encode('utf-8')
        sock.sendto(data, (COLLECTOR_HOST, COLLECTOR_PORT))
        print(f"[SENT] {flow_data['source_ip']}:{flow_data['source_port']} -> "
              f"{flow_data['destination_ip']}:{flow_data['destination_port']} "
              f"({flow_data['protocol']}, {flow_data['total_bytes']} bytes)")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to send flow: {str(e)}")
        return False
    finally:
        sock.close()


def generate_sample_flow() -> Dict:
    """Generate a sample flow record"""
    source_ips = ["192.168.1.10", "192.168.1.20", "10.0.0.5"]
    dest_ips = ["8.8.8.8", "1.1.1.1", "93.184.216.34"]
    protocols = ["TCP", "UDP", "ICMP"]
    services = ["HTTP", "HTTPS", "DNS", "SSH", None]
    
    start_time = datetime.now() - timedelta(seconds=random.randint(1, 60))
    duration = random.randint(1, 300)
    end_time = start_time + timedelta(seconds=duration)
    
    bytes_up = random.randint(1000, 10000000)
    bytes_down = random.randint(10000, 100000000)
    
    return {
        "source_ip": random.choice(source_ips),
        "source_port": random.randint(1024, 65535),
        "destination_ip": random.choice(dest_ips),
        "destination_port": random.choice([80, 443, 53, 22, 3306]),
        "protocol": random.choice(protocols),
        "service_type": random.choice(services),
        "bytes_uploaded": bytes_up,
        "bytes_downloaded": bytes_down,
        "total_bytes": bytes_up + bytes_down,
        "packets_uploaded": random.randint(10, 1000),
        "packets_downloaded": random.randint(100, 10000),
        "total_packets": random.randint(110, 11000),
        "session_start_time": start_time.isoformat(),
        "session_end_time": end_time.isoformat(),
        "duration_seconds": duration,
        "user_id": f"user_{random.randint(1, 5)}"
    }


def main():
    """Main function"""
    print("=" * 60)
    print("Flow Data Sender - Simple Collector Test")
    print("=" * 60)
    print(f"Target: {COLLECTOR_HOST}:{COLLECTOR_PORT}")
    print("Press Ctrl+C to stop\n")
    
    try:
        count = 0
        while True:
            flow = generate_sample_flow()
            if send_flow(flow):
                count += 1
            time.sleep(2)  # Send a flow every 2 seconds
    except KeyboardInterrupt:
        print(f"\n\nStopped. Sent {count} flows.")


if __name__ == "__main__":
    main()

