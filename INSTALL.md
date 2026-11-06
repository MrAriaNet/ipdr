# IPDR Install & Usage Guide (English)

This document covers installation on a **Linux server** (Ubuntu, Debian, AlmaLinux) and day-to-day usage.

> Code and APIs are in English. Persian guides:  
> [README-FA.md](README-FA.md) · [INSTALL-FA.md](INSTALL-FA.md) · [ROUTER_SETUP-FA.md](ROUTER_SETUP-FA.md) · [CGNAT_ASR-FA.md](CGNAT_ASR-FA.md) · [LEA-FA.md](LEA-FA.md) · [examples/router_config_examples-FA.md](examples/router_config_examples-FA.md)

> Sample passwords are for lab use only. Change them in production.

---

## Prerequisites

| Item | Recommended |
|------|-------------|
| OS | Ubuntu 22.04+ / Debian 12+ / AlmaLinux 8 or 9 |
| Python | 3.10 or newer |
| PostgreSQL | 14 or newer |
| Access | User with sudo |

Default ports:

- API / dashboard: TCP `8000`
- NetFlow v1/v5/v7/v8/v9 and IPFIX: UDP `2055`
- sFlow v2/v4/v5: UDP `6343`
- Experimental JSON collector: UDP `9999`

---

## 1. Install system packages

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip postgresql postgresql-contrib \
  build-essential libpq-dev curl git
sudo systemctl enable --now postgresql
```

### AlmaLinux / RHEL

```bash
sudo dnf install -y python3 python3-pip postgresql-server postgresql-contrib \
  gcc gcc-c++ libpq-devel curl git
sudo postgresql-setup --initdb
sudo systemctl enable --now postgresql
```

On AlmaLinux you may need to adjust local auth in `pg_hba.conf` for the app user (e.g. `md5` or `scram-sha-256`).

---

## 2. Get the project

```bash
sudo mkdir -p /opt/ipdr
sudo chown "$USER":"$USER" /opt/ipdr
cd /opt
git clone https://github.com/MrAriaNet/ipdr.git ipdr
cd /opt/ipdr
```

If the repository is not published yet, copy the project folder onto the server and `cd` into it.

---

## 3. PostgreSQL database

```bash
sudo -u postgres psql <<'SQL'
CREATE USER ipdr_user WITH PASSWORD 'CHANGE_ME_STRONG_PASSWORD';
CREATE DATABASE ipdr_db OWNER ipdr_user;
GRANT ALL PRIVILEGES ON DATABASE ipdr_db TO ipdr_user;
SQL
```

PostgreSQL 15+:

```bash
sudo -u postgres psql -d ipdr_db -c "GRANT ALL ON SCHEMA public TO ipdr_user;"
```

Test connectivity:

```bash
psql -h 127.0.0.1 -U ipdr_user -d ipdr_db -c 'SELECT 1;'
```

---

## 4. Virtualenv and dependencies

```bash
cd /opt/ipdr
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 5. Configure `.env`

```bash
cp .env.example .env
nano .env
```

Example:

```env
DATABASE_URL=postgresql://ipdr_user:CHANGE_ME_STRONG_PASSWORD@127.0.0.1:5432/ipdr_db
CORS_ORIGINS=*
SFLOW_EXTRAPOLATE=true
IPDR_AUTH_REQUIRED=false
IPDR_API_KEYS=admin:change-me-admin,lea:change-me-lea,ops:change-me-ops,collector:change-me-collector
IPDR_RETENTION_DAYS=365
CGNAT_RETENTION_DAYS=365
AAA_RETENTION_DAYS=365
```

In production, replace `CORS_ORIGINS=*` with a comma-separated allow-list, set `IPDR_AUTH_REQUIRED=true`, and use strong API keys.

Create / upgrade tables:

```bash
source venv/bin/activate
python setup.py
```

---

## 6. Temporary run (lab)

```bash
source venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Check:

```bash
curl http://127.0.0.1:8000/health
```

URLs:

| URL | Purpose |
|-----|---------|
| `http://SERVER_IP:8000` | Home |
| `http://SERVER_IP:8000/dashboard` | Dashboard |
| `http://SERVER_IP:8000/docs` | API docs (Swagger) |
| `http://SERVER_IP:8000/redoc` | ReDoc |
| `http://SERVER_IP:8000/health` | Health (UTC clock, DB, features) |
| `http://SERVER_IP:8000/api/ipdr/protocols` | Full IANA protocol list |

---

## 7. Permanent run with systemd (recommended)

```bash
sudo useradd --system --home /opt/ipdr --shell /usr/sbin/nologin ipdr || true
sudo chown -R ipdr:ipdr /opt/ipdr
sudo cp deploy/ipdr.service /etc/systemd/system/ipdr.service
sudo systemctl daemon-reload
sudo systemctl enable --now ipdr
sudo systemctl status ipdr
```

Service logs:

```bash
journalctl -u ipdr -f
```

Application logs:

```bash
tail -f /opt/ipdr/logs/ipdr_*.log
```

---

## 8. Firewall

### Ubuntu / Debian (UFW)

```bash
sudo ufw allow 8000/tcp comment 'IPDR API'
sudo ufw allow 2055/udp comment 'IPDR NetFlow'
sudo ufw allow 6343/udp comment 'IPDR sFlow'
sudo ufw reload
```

### AlmaLinux (firewalld)

```bash
sudo firewall-cmd --permanent --add-port=8000/tcp
sudo firewall-cmd --permanent --add-port=2055/udp
sudo firewall-cmd --permanent --add-port=6343/udp
sudo firewall-cmd --reload
```

Only management / router networks should reach these ports.

---

## 9. Using the API and dashboard

1. Open the dashboard and filter by IP, protocol, service, or text search.
2. Use **Statistics** for aggregates.
3. Use `/docs` for scripting.
4. CGNAT / LEA panel: public IP:port lookup, reverse lookup, investigate (see [LEA.md](LEA.md)).

Create a sample record:

```bash
curl -X POST "http://127.0.0.1:8000/api/ipdr/records" \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "192.168.1.10",
    "source_port": 54321,
    "destination_ip": "8.8.8.8",
    "destination_port": 53,
    "session_start_time": "2026-01-15T10:00:00Z",
    "session_end_time": "2026-01-15T10:00:05Z",
    "duration_seconds": 5,
    "bytes_uploaded": 1000,
    "bytes_downloaded": 2000,
    "total_bytes": 3000,
    "packets_uploaded": 10,
    "packets_downloaded": 20,
    "total_packets": 30,
    "protocol": "UDP",
    "service_type": "DNS",
    "user_id": "lab-user"
  }'
```

Bulk sample data:

```bash
source /opt/ipdr/venv/bin/activate
python /opt/ipdr/examples/sample_data.py
```

---

## 10. Cisco router

The NetFlow collector supports **v1, v5, v7, v8, v9**, and **IPFIX**. On the server:

```bash
curl -X POST "http://127.0.0.1:8000/api/collector/start" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: change-me-admin" \
  -d '{"collector_type":"netflow","host":"0.0.0.0","port":2055}'

# If you need sFlow:
curl -X POST "http://127.0.0.1:8000/api/collector/start" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: change-me-admin" \
  -d '{"collector_type":"sflow","host":"0.0.0.0","port":6343}'
```

Sample Cisco IOS / IOS-XE (NetFlow v5):

```cisco
ip flow-export version 5
ip flow-export destination SERVER_IP 2055
ip flow-export source Loopback0
ip flow-cache timeout active 1
ip flow-cache timeout inactive 15

interface GigabitEthernet0/0
 ip flow ingress
 ip flow egress
```

On the router:

```cisco
show ip flow export
show ip cache flow
```

More detail: [ROUTER_SETUP.md](ROUTER_SETUP.md)

---

## 11. MikroTik router

On RouterOS:

```mikrotik
/ip traffic-flow
set enabled=yes interfaces=all cache-entries=1M active-flow-timeout=1m inactive-flow-timeout=15s

/ip traffic-flow target
add dst-address=SERVER_IP:2055 version=5
```

Prefer specific interfaces instead of `all` when possible (e.g. `ether1,bridge`).

Verify:

```mikrotik
/ip traffic-flow print
/ip traffic-flow target print
/ip traffic-flow status
```

On the server:

```bash
curl -s http://127.0.0.1:8000/api/collector/status
sudo tcpdump -ni any udp port 2055 -c 10
```

---

## 12. Common troubleshooting

| Problem | What to check |
|---------|----------------|
| DB connection error | `postgresql` service, `DATABASE_URL`, `pg_hba.conf` |
| Port 8000 closed | Firewall, `ss -lntp \| grep 8000` |
| Router sends but no records | Collector status, `tcpdump`, `logs/` and `journalctl -u ipdr` |
| scapy / dependency build fails | Install `build-essential` or `gcc` and `libpq-dev` / `libpq-devel` |
| 401 on API | `IPDR_AUTH_REQUIRED` and `X-API-Key` / `IPDR_API_KEYS` |

---

## 13. Production security

1. Strong PostgreSQL password; restrict DB network access
2. Restrict `CORS_ORIGINS`
3. Put the API behind a TLS reverse proxy (e.g. Nginx)
4. Do not expose ports 8000 / 2055 / 6343 to the public Internet unless required
5. Regular database backups
6. Enable `IPDR_AUTH_REQUIRED=true` with role-separated API keys
7. Keep ASR + IPDR host on **NTP**; health returns `utc_now`

---

## 14. CGNAT Port Block Allocation (PBA) — Cisco ASR

On **ASR 1001-X** with **PBA**, overload is heavy and per-session NetFlow from the CGN is not the model. IPDR ingests Cisco **NAT HSL** port-set allocate/deallocate (NetFlow v9):

```cisco
ip nat settings mode cgn
ip nat settings pap bpa set-size 512 step-size 8
ip nat log translations flow-export v9 udp destination IPDR_SERVER 2055
```

```bash
curl -X POST "http://127.0.0.1:8000/api/collector/start" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: change-me-admin" \
  -d '{"collector_type":"netflow","host":"0.0.0.0","port":2055}'

curl "http://127.0.0.1:8000/api/cgnat/lookup?public_ip=203.0.113.10&public_port=4008&at=2026-11-06T12:30:00Z" \
  -H "X-API-Key: change-me-lea"
```

Full ASR CLI / HSL field map: [CGNAT_ASR.md](CGNAT_ASR.md) · فارسی: [CGNAT_ASR-FA.md](CGNAT_ASR-FA.md)  
Sample: `python examples/cgnat_pba_sample.py`

---

## 15. LEA / security workflow

Full investigate (CGNAT → AAA → flows) and warrant export:

```bash
curl -s -X POST "http://127.0.0.1:8000/api/lea/investigate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: change-me-lea" \
  -d '{
    "public_ip": "203.0.113.10",
    "public_port": 1500,
    "at": "2026-11-06T12:30:00Z",
    "case_ref": "CASE-2026-001",
    "window_seconds": 300,
    "legal_hold": true
  }'
```

Guide: [LEA.md](LEA.md) · Persian: [LEA-FA.md](LEA-FA.md)

sFlow sampling / volume extrapolation: [SFLOW.md](SFLOW.md)

---

## Related links

| Topic | English | فارسی |
|-------|---------|--------|
| Project overview | [README.md](README.md) | [README-FA.md](README-FA.md) |
| Install & usage | [INSTALL.md](INSTALL.md) (this file) | [INSTALL-FA.md](INSTALL-FA.md) |
| Router setup | [ROUTER_SETUP.md](ROUTER_SETUP.md) | [ROUTER_SETUP-FA.md](ROUTER_SETUP-FA.md) |
| Router examples | [examples/router_config_examples.md](examples/router_config_examples.md) | [examples/router_config_examples-FA.md](examples/router_config_examples-FA.md) |
| CGNAT PBA / ASR | [CGNAT_ASR.md](CGNAT_ASR.md) | [CGNAT_ASR-FA.md](CGNAT_ASR-FA.md) |
| LEA / security | [LEA.md](LEA.md) | [LEA-FA.md](LEA-FA.md) |
| sFlow & sample rate | [SFLOW.md](SFLOW.md) | [SFLOW-FA.md](SFLOW-FA.md) |
| Durable HSL bridge | [HSL_BRIDGE.md](HSL_BRIDGE.md) | [HSL_BRIDGE-FA.md](HSL_BRIDGE-FA.md) |
