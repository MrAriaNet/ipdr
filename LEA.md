# LEA / Network Security IPDR Guide

> **فارسی:** [LEA-FA.md](LEA-FA.md)

This system supports **ISP operations** and **lawful / security disclosure** for CGNAT **Port Block Allocation (PBA)** environments where there is **no per-connection NAT (XLATE) table**.

## Typical LEA question

> Who used public IP `203.0.113.10` port `1500` at time `T`, and what traffic did they generate?

Workflow:

1. **CGNAT PBA** — `public_ip:port + T` → `inside_ip` (port block allocate/deallocate only)
2. **AAA** — `inside_ip + T` → `subscriber_id` / username / MSISDN (if AAA sessions ingested)
3. **Flows** — IPDR records for that inside IP in a time window
4. **Export** — sealed package with manifest + SHA-256; optional legal hold

## Auth

```bash
# .env
IPDR_AUTH_REQUIRED=true
IPDR_API_KEYS=admin:...,lea:...,ops:...,collector:...
```

Send header: `X-API-Key: <secret>` (or `Authorization: Bearer <secret>`).

Roles: `collector` < `ops` < `lea` < `admin`.

## Key APIs

| Endpoint | Role | Purpose |
|----------|------|---------|
| `GET /api/cgnat/lookup` | lea | public → inside (multi-match / ambiguous aware) |
| `GET /api/cgnat/lookup/by-subscriber` | lea | inside → public blocks |
| `POST /api/lea/investigate` | lea | full bundle: CGNAT + AAA + flows |
| `POST /api/lea/export` | lea | warrant export + manifest hash |
| `POST /api/lea/aaa/sessions` | ops | ingest AAA/RADIUS/DHCP bindings |
| `GET /api/lea/aaa/resolve` | lea | framed_ip → subscriber |
| `GET /api/lea/audit` | admin | who queried what |
| `POST /api/lea/retention/purge?dry_run=true` | admin | retention (skips legal hold) |

### Investigate example

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

If `ambiguous: true`, **do not** treat a single subscriber as definitive — review `matches[]`.

## PBA vs NAT overload

| | NAT overload | CGNAT PBA |
|--|--------------|-----------|
| Connection table | Yes (XLATE) | **No** |
| Logged events | per session create/delete | port-block allocate/deallocate |
| LEA input | public IP + port (+ time) | same — matched to **port range** |

## Integrity & retention

- Each IPDR / CGNAT insert stores `content_hash` (SHA-256 of canonical fields).
- Export manifest includes `payload_sha256` / `bundle_hash`.
- `legal_hold` + `hold_case_id` protect rows from retention purge.
- Configure `IPDR_RETENTION_DAYS` / `CGNAT_RETENTION_DAYS` / `AAA_RETENTION_DAYS`.

## Ops checklist

1. NTP on ASR + IPDR host (health returns `utc_now`).
2. Enable auth in production.
3. Ingest AAA sessions for legal identity beyond inside IP.
4. Keep PBA allocate/deallocate for the full legal retention window.
5. Use ISO-8601 timestamps with `Z` or offset.

See also: [CGNAT_ASR.md](CGNAT_ASR.md) · [README.md](README.md)
