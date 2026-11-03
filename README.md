# IPDR — Internet Protocol Detail Record System

Collect, store, search, and analyze network traffic sessions. Built for Linux servers (Ubuntu, Debian, AlmaLinux) with **NetFlow / IPFIX / sFlow** intake from **Cisco**, **MikroTik**, and other exporters — **IPv4 and IPv6**.

> **Persian install & usage guide:** [INSTALL-FA.md](INSTALL-FA.md)

## Features

- IPDR records: source/destination (**IPv4 and IPv6**), ports, timing, volume, protocol, service, user id
- Full IANA IP protocol mapping (`GET /api/ipdr/protocols`) — TCP, UDP, ICMPv6, GRE, ESP, SCTP, …
- NetFlow **v1 / v5 / v7 / v8 / v9** and **IPFIX** collector (UDP 2055, dual-stack)
- **sFlow v2 / v4 / v5** collector (UDP 6343, dual-stack)
- Optional JSON flow collector for labs (UDP 9999)
- Deep Packet Inspection helpers (Scapy) for service / threat hints when packet bytes are available
- Statistics, traffic summaries, and advanced text search
- Security event tracking for suspicious sessions
- File logging with rotation under `logs/`
- Billing model fields: prepaid, postpaid, hybrid
- HTML dashboard and OpenAPI docs (`/docs`)

## Requirements

| Component | Version |
|-----------|---------|
| OS | Ubuntu 22.04+, Debian 12+, AlmaLinux 8/9 (or similar) |
| Python | 3.10+ |
| PostgreSQL | 14+ |

## Quick install (Linux)

```bash
sudo apt update   # or: sudo dnf install ...
# Install python3, venv, pip, postgresql, build tools — see INSTALL-FA.md for distro commands

git clone https://github.com/MrAriaNet/ipdr.git
cd ipdr
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Edit DATABASE_URL

python setup.py
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Production-style systemd unit: [deploy/ipdr.service](deploy/ipdr.service). Full Persian walkthrough (including firewall and systemd): [INSTALL-FA.md](INSTALL-FA.md).

### Environment

| Variable | Purpose | Default |
|----------|---------|---------|
| `DATABASE_URL` | PostgreSQL SQLAlchemy URL | `postgresql://ipdr_user:ipdr_pass@localhost:5432/ipdr_db` |
| `CORS_ORIGINS` | `*` or comma-separated origins | `*` |

Change default database credentials before any real deployment.

## Access

| URL | Description |
|-----|-------------|
| http://SERVER:8000 | Home |
| http://SERVER:8000/dashboard | Management dashboard |
| http://SERVER:8000/docs | Swagger UI |
| http://SERVER:8000/redoc | ReDoc |
| http://SERVER:8000/health | Health check |
| http://SERVER:8000/api/ipdr/protocols | IANA protocol list |

## API overview

### IPDR
- `GET /api/ipdr/protocols` — export all IANA protocol names/numbers
- `POST /api/ipdr/records`
- `GET /api/ipdr/records` — filters include `ip_version`, `protocol`, `protocol_number`
- `GET /api/ipdr/records/{id}`
- `GET /api/ipdr/statistics`
- `POST /api/ipdr/summaries/create`
- `GET /api/ipdr/search`
- `GET /api/ipdr/search/count`

### Collectors
- `POST /api/collector/start` — `netflow`, `sflow`, or `simple`
- `POST /api/collector/stop`
- `GET /api/collector/status`

### Security
- `GET /api/security/events`
- `POST /api/security/events`
- `PATCH /api/security/events/{id}/resolve`

## Router integration (Cisco, MikroTik, sFlow)

```bash
# NetFlow / IPFIX (all supported versions on one socket)
curl -X POST "http://127.0.0.1:8000/api/collector/start" \
  -H "Content-Type: application/json" \
  -d '{"collector_type":"netflow","host":"0.0.0.0","port":2055}'

# sFlow
curl -X POST "http://127.0.0.1:8000/api/collector/start" \
  -H "Content-Type: application/json" \
  -d '{"collector_type":"sflow","host":"0.0.0.0","port":6343}'
```

**Cisco IOS / IOS-XE (NetFlow v5 summary):**

```cisco
ip flow-export version 5
ip flow-export destination 192.168.1.100 2055
interface GigabitEthernet0/0
 ip flow ingress
 ip flow egress
```

**MikroTik RouterOS (summary):**

```mikrotik
/ip traffic-flow
set enabled=yes interfaces=all
/ip traffic-flow target
add dst-address=192.168.1.100:2055 version=5
```

Supports NetFlow v9 / IPFIX templates, Flexible NetFlow (IPv4/IPv6), IOS-XR, and sFlow agents.

- Full procedures: **[ROUTER_SETUP.md](ROUTER_SETUP.md)**
- Ready-to-paste snippets (Cisco, MikroTik, sFlow, firewall): **[examples/router_config_examples.md](examples/router_config_examples.md)**

## Examples

```bash
# Seed sample API records (includes IPv4/IPv6 and multiple protocols)
python examples/sample_data.py

# Send JSON flows to the simple collector (port 9999)
python examples/send_flow_data.py
```

## Project layout

```
ipdr/
├── app/
│   ├── main.py                 # FastAPI entry
│   ├── database.py / models.py / schemas.py
│   ├── routers/                # HTTP API
│   ├── services/               # Business logic
│   ├── collectors/             # NetFlow / IPFIX / sFlow / JSON
│   ├── dpi/                    # Packet analysis helpers
│   ├── utils/logger.py
│   └── static/dashboard.html
├── deploy/ipdr.service         # systemd unit
├── examples/
│   ├── router_config_examples.md
│   ├── sample_data.py
│   └── send_flow_data.py
├── INSTALL-FA.md               # Persian install & usage
├── ROUTER_SETUP.md             # Cisco / MikroTik / sFlow guide
├── requirements.txt
├── setup.py
├── .env.example
└── LICENSE
```

## Troubleshooting

- **Database:** ensure PostgreSQL is running and `DATABASE_URL` is correct; test with `psql`.
- **Port 8000 in use:** change the uvicorn `--port`.
- **No NetFlow records:** confirm collector status, `tcpdump -ni any udp port 2055`, and router export counters.
- **No sFlow records:** check UDP `6343` and agent sampling configuration.
- **Build errors:** install `build-essential` / `gcc` and `libpq-dev` (or `libpq-devel` on AlmaLinux).

## Security notes

- Restrict CORS and database access in production.
- Terminate TLS at a reverse proxy (Nginx/Caddy).
- Do not expose NetFlow, sFlow, or the API to the public Internet without controls.
- Keep `.env` out of git (already listed in `.gitignore`).

## License

MIT — see [LICENSE](LICENSE).
