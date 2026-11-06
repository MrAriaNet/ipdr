# sFlow sampling and “100% traffic”

> **فارسی:** [SFLOW-FA.md](SFLOW-FA.md)

## Short answer

**No.** sFlow does **not** log 100% of packets. It is designed as **sampled** telemetry (e.g. 1-in-128 or 1-in-1024 packets).

What this IPDR system does:

| What | Behavior |
|------|----------|
| Packet / session coverage | Still **sampled** — you only see flows that were sampled |
| **Volume** (`total_bytes` / `total_packets`) | By default **extrapolated**: `observed × sampling_rate` ≈ full traffic volume |
| Raw sample size | Stored in `sampled_bytes` / `sampled_packets` |
| Rate | Stored in `sampling_rate` (`is_sampled=true`) |

So logs can report **volume close to 100% of traffic** (statistically), but they are **not** a full packet capture or a complete list of every session.

## Example

- Agent sample rate = **128**
- One sampled Ethernet frame = **1500** bytes  
→ `sampled_bytes=1500`, `sampling_rate=128`  
→ `total_bytes=1500×128=192000` (estimated full volume for that sample)

## Enable / disable extrapolation

**Environment (default on):**

```env
SFLOW_EXTRAPOLATE=true
```

**API when starting the collector:**

```bash
curl -X POST "http://127.0.0.1:8000/api/collector/start" \
  -H "Content-Type: application/json" \
  -d '{
    "collector_type": "sflow",
    "host": "0.0.0.0",
    "port": 6343,
    "extrapolate": true
  }'
```

Set `"extrapolate": false` to store **only raw sample sizes** (clearly not 100% traffic).

Check status: `GET /api/collector/status` → `sflow.extrapolate`.

## For security / IPDR accuracy

1. Prefer lower sampling rates on critical links if you need more flow visibility (costs more CPU on the switch).  
2. Use **NetFlow/IPFIX** when you need closer-to-full flow records (not packet samples).  
3. Always keep `sampling_rate` with the record when presenting volumes to auditors.  
4. Extrapolation assumes uniform sampling; drops (`sflow_drops` in `additional_info`) mean underestimation.

## Related

- Router setup: [ROUTER_SETUP.md](ROUTER_SETUP.md)  
- Persian install: [INSTALL-FA.md](INSTALL-FA.md)
