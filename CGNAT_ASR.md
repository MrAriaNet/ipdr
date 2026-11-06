# CGNAT Port Block Allocation (PBA) — Cisco ASR & IPDR

> **فارسی:** [CGNAT_ASR-FA.md](CGNAT_ASR-FA.md)

## Why PBA?

On platforms such as **Cisco ASR 1001-X**, Carrier-Grade NAT can use **Port Block Allocation (PBA)**:

- Instead of logging every single NAT translation, the CGN assigns a **contiguous block** of public ports (e.g. 512 or 1024) to a subscriber.
- High-speed logging (HSL) / IPFIX volume drops dramatically.
- Network security still needs IPDR: map `public_ip:public_port` → **subscriber (inside) IP** at incident time.

This IPDR system stores PBA allocate/deallocate events and exposes a **lookup API** for that mapping.

## Data model (what we store)

| Field | Meaning |
|-------|---------|
| `inside_ip` | Subscriber / pre-NAT address |
| `outside_ip` | Public / post-NAT address |
| `port_start` / `port_end` | Contiguous public port block |
| `port_block_size` | Usually `end - start + 1` (e.g. 512, 1024) |
| `event_type` | `allocate` / `deallocate` |
| `event_time` / `released_at` | When the block was given / returned |
| `is_active` | Block still held by subscriber |

## Ingest paths

### 1) IPFIX / NetFlow from ASR (recommended)

Start the NetFlow/IPFIX collector (same UDP **2055**). Templates that include NAT / port-range IEs are classified as CGNAT PBA and stored in `cgnat_port_blocks` (not as normal flow rows).

```bash
curl -X POST "http://127.0.0.1:8000/api/collector/start" \
  -H "Content-Type: application/json" \
  -d '{"collector_type":"netflow","host":"0.0.0.0","port":2055}'
```

Recognized IPFIX IEs (among others):

- `225` postNATSourceIPv4Address  
- `230` natEvent  
- `361`–`364` portRangeStart / End / Step / NumPorts  
- pre-NAT source from IE `8` / IPv6 `27`

### 2) REST API (HSL bridge / scripts)

```bash
curl -X POST "http://127.0.0.1:8000/api/cgnat/blocks" \
  -H "Content-Type: application/json" \
  -d '{
    "event_time": "2026-11-06T12:00:00",
    "event_type": "allocate",
    "inside_ip": "100.64.10.25",
    "outside_ip": "203.0.113.10",
    "port_start": 1024,
    "port_end": 2047,
    "port_block_size": 1024,
    "protocol": "ANY",
    "router_ip": "192.0.2.1",
    "source": "api"
  }'
```

Bulk: `POST /api/cgnat/blocks/bulk` with `{ "records": [ ... ] }`.

## Security lookup (LEA / SOC)

```bash
curl -s "http://127.0.0.1:8000/api/cgnat/lookup?public_ip=203.0.113.10&public_port=1500&at=2026-11-06T12:30:00"
```

Example response:

```json
{
  "found": true,
  "public_ip": "203.0.113.10",
  "public_port": 1500,
  "inside_ip": "100.64.10.25",
  "port_start": 1024,
  "port_end": 2047,
  "port_block_size": 1024,
  "event_time": "2026-11-06T12:00:00",
  "message": "OK"
}
```

List blocks: `GET /api/cgnat/blocks?outside_ip=203.0.113.10&is_active=true`

---

## Cisco ASR 1001-X — configuration outline

Exact CLI varies by IOS-XE / CGN feature set. Typical building blocks:

### Enable CGN with PBA

```cisco
! Example concepts — adapt to your IOS-XE / CGN guide
ip nat settings mode cgn
ip nat settings port-block-allocation size 1024
! or platform-specific:
! ip nat translation port-block-allocation enable
! ip nat translation port-block size 1024
```

Confirm with:

```cisco
show ip nat translations
show ip nat port-block
show platform hardware qfp active feature nat datapath …
```

### Export NAT / PBA logs via IPFIX (HSL → collector)

Point the exporter at the IPDR server (`192.168.1.100:2055` in examples):

```cisco
! Conceptual Flexible NetFlow / IPFIX exporter toward IPDR
flow exporter IPDR_CGN
 destination 192.168.1.100
 transport udp 2055
 export-protocol ipfix
 source Loopback0
!
! Bind exporter to CGN / NAT logging per your IOS-XE release
! (commands differ: "ip nat log …", "flow record" with NAT fields, etc.)
```

Firewall on the IPDR host: allow **UDP 2055** from the ASR management/CGN source.

> Always validate templates with a packet capture (`tcpdump -ni any udp port 2055`) and check IPDR logs for `CGNAT PBA allocate/deallocate`.

### Operational tips for security

1. Retain PBA logs at least as long as your legal retention policy for IPDR.  
2. Lookups must use the **time of the incident**, not “now”, if the block may have been released.  
3. Port block size (512/1024/…) must match ASR config so `port_end` is correct when only start+size are exported.  
4. Keep ASR and IPDR clocks on **NTP**.

---

## Sample script

```bash
python examples/cgnat_pba_sample.py
```

Persian docs: [CGNAT_ASR-FA.md](CGNAT_ASR-FA.md) · [INSTALL-FA.md](INSTALL-FA.md) · [ROUTER_SETUP-FA.md](ROUTER_SETUP-FA.md)  
English router guide: [ROUTER_SETUP.md](ROUTER_SETUP.md)
