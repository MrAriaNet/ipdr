# CGNAT HSL Bridge — complete ingest path (Cisco ASR PBA)

> **فارسی:** [HSL_BRIDGE-FA.md](HSL_BRIDGE-FA.md)

## Goal

With **CGNAT PBA** on ASR 1001-X, per-session NetFlow is not the right model.  
This bridge ensures **every** NAT HSL allocate/deallocate reaches PostgreSQL **without silent loss**.

```
ASR 1001-X
  ip nat log translations flow-export v9 udp destination IPDR:2055
        │
        ▼
  NetFlow v9 collector  (+ template cache + pending buffer)
        │
        ▼
  Durable ingest queue  (memory → DB; spill JSONL on outage)
        │
        ▼
  cgnat_port_blocks / ipdr_records
```

## Two deployment modes

### A) API process (lab / moderate rate)

```bash
curl -X POST http://127.0.0.1:8000/api/collector/start \
  -H "Content-Type: application/json" \
  -H "X-API-Key: change-me-admin" \
  -d '{"collector_type":"netflow","host":"0.0.0.0","port":2055}'
```

### B) Dedicated bridge process (recommended for production HSL)

Do **not** bind UDP 2055 twice. Either API collector **or** bridge:

```bash
# systemd
sudo cp deploy/ipdr-hsl-bridge.service /etc/systemd/system/
sudo systemctl enable --now ipdr-hsl-bridge

# or manually
source venv/bin/activate
python -m app.bridges.cgnat_hsl_bridge
```

ASR:

```cisco
ip nat settings mode cgn
ip nat settings pap bpa set-size 512 step-size 8
ip nat log translations flow-export v9 udp destination 192.168.1.100 2055
```

## Reliability features

| Feature | Behaviour |
|---------|-----------|
| Durable queue | Async DB writes; UDP receive never blocks on SQL |
| Disk spool | On DB error / full queue → `data/ingest_spool/{cgnat,flow}/*.jsonl` |
| Spool replay | Automatic on start; `POST /api/ingest/replay-spool` |
| Dedup | Same PBA event hash skipped (memory TTL + DB `content_hash`) |
| Template cache | Persisted to `data/netflow_templates.json` across restarts |
| Pending sets | Data before template arrives is buffered and replayed |
| Stats | `GET /api/ingest/status` · `GET /api/ingest/health` |

## Monitoring

```bash
curl -s http://127.0.0.1:8000/api/ingest/health
curl -s http://127.0.0.1:8000/api/ingest/status -H "X-API-Key: change-me-ops"
```

Watch for: `cgnat_failed`, growing `spool_cgnat_files`, `unknown_templates`, `pending_dropped`.

## Validation checklist

1. `tcpdump -ni any udp port 2055` — packets from ASR  
2. Logs show template IEs including `225,230,361,363,364`  
3. `cgnat_saved` increases on subscriber activity  
4. Lookup: `/api/cgnat/lookup?public_ip=…&public_port=…&at=…`  
5. Stop PostgreSQL briefly → spool files appear → start DB → replay clears spool  

See also: [CGNAT_ASR.md](CGNAT_ASR.md) · [LEA.md](LEA.md) · [INSTALL.md](INSTALL.md)
