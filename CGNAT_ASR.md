# CGNAT Port Block Allocation (PBA) — Cisco ASR 1001-X & IPDR

> **فارسی:** [CGNAT_ASR-FA.md](CGNAT_ASR-FA.md)

## The operational problem (why NetFlow “stops” with PBA)

On **Cisco ASR 1001-X** (and ASR 1000 CGN):

| Mode | Device load | Logging |
|------|-------------|---------|
| **NAT overload** (per-session XLATE) | High — device under pressure, often unstable at scale | Classic per-translation logs / heavy NetFlow-like HSL |
| **CGNAT PBA / Bulk Logging** | Stable — recommended for CGN | **Only** port-set **allocate / deallocate** via NAT **High-Speed Logging (HSL)** NetFlow v9 |

With PBA enabled Cisco **does not** log every NAT session and **does not** support Syslog for BPA. Destination is not logged. So “pulling NetFlow” of every connection from the CGN box is the wrong expectation.

**Correct IPDR path with PBA:**

1. **Identity (who used public IP:port)** ← ASR NAT HSL PBA records → this IPDR (`cgnat_port_blocks`)
2. **Optional traffic detail** ← Flexible NetFlow / sFlow on **inside** (pre-NAT) or another tap — correlate with `POST /api/lea/investigate`

This system is built for that model: complete and accurate **subscriber mapping** from PBA HSL, without needing a connection table.

## What Cisco exports (HSL fields)

Command (collector = IPDR server):

```cisco
ip nat log translations flow-export v9 udp destination 192.168.1.100 2055
```

| IE | Name | Meaning |
|----|------|---------|
| 8 | sourceIPv4Address | Inside / subscriber IP |
| 225 | postNATSourceIPv4Address | Public / outside IP |
| 234 | ingressVRFID | VRF |
| 4 | protocolIdentifier | Protocol |
| 230 | natEvent | `1` = allocate (add), `2` = deallocate (delete) |
| 323 | observationTimeMilliseconds | Event time |
| 361 | portRangeStart | First port in set |
| 363 | portRangeStepSize | Scattered step (e.g. 4 or 8) |
| 364 | portRangeNumPorts | Ports in set (e.g. 512, 1024) |

Ports in the set: `start`, `start+step`, `start+2*step`, … (count = numPorts).  
IPDR stores `port_step` and matches **only** ports that belong to that set (not every port between start and end when step > 1).

---

## ASR 1001-X — working PBA + HSL config

Adapt interfaces / pool / ACL to your network. Prerequisites: **CGN mode** + **paired-address pooling (PAP)**.

```cisco
configure terminal
!
interface GigabitEthernet0/0/0
 description INSIDE
 ip nat inside
!
interface GigabitEthernet0/0/1
 description OUTSIDE
 ip nat outside
!
ip nat settings mode cgn
!
! Public pool (example)
ip nat pool CGN_POOL 203.0.113.10 203.0.113.20 prefix-length 24
!
access-list 1 permit 100.64.0.0 0.63.255.255
ip nat inside source list 1 pool CGN_POOL
!
! Bulk Port Allocation (PBA) — set-size / step-size per design
! Example: 512 ports per block, step 8 (scattered)
ip nat settings pap bpa set-size 512 step-size 8
!
! === THIS is the IPDR feed (NOT interface NetFlow) ===
ip nat log translations flow-export v9 udp destination 192.168.1.100 2055
!
end
```

Verify on ASR:

```cisco
show ip nat bpa
show ip nat translations
show ip nat statistics
```

On IPDR host:

```bash
# Start collector (same UDP port as HSL destination)
curl -X POST "http://127.0.0.1:8000/api/collector/start" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: change-me-admin" \
  -d '{"collector_type":"netflow","host":"0.0.0.0","port":2055}'

sudo tcpdump -ni any udp port 2055 -c 20
# Expect NetFlow v9 templates with IEs 225, 230, 361, 363, 364

curl -s "http://127.0.0.1:8000/api/cgnat/lookup?public_ip=203.0.113.10&public_port=4000&at=2026-11-06T12:30:00Z" \
  -H "X-API-Key: change-me-lea"
```

Optional second exporter for **traffic volume** (separate from NAT HSL) — Flexible NetFlow on the **inside** interface, still toward IPDR port 2055 or another port. PBA identity stays on HSL; flows are correlated by inside IP + time via `/api/lea/investigate`.

---

## Security / LEA lookup

Inputs: **public IP + public port + time** (no inside_port, no XLATE table).

```bash
curl -s "http://127.0.0.1:8000/api/cgnat/lookup?public_ip=203.0.113.10&public_port=4008&at=2026-11-06T12:30:00Z" \
  -H "X-API-Key: change-me-lea"
```

Full package (CGNAT → AAA → flows):

```bash
curl -s -X POST "http://127.0.0.1:8000/api/lea/investigate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: change-me-lea" \
  -d '{
    "public_ip": "203.0.113.10",
    "public_port": 4008,
    "at": "2026-11-06T12:30:00Z",
    "case_ref": "CASE-001",
    "window_seconds": 300
  }'
```

If `ambiguous: true`, review `matches[]` — do not treat as unique.

---

## REST ingest (lab / bridge)

```bash
curl -X POST "http://127.0.0.1:8000/api/cgnat/blocks" \
  -H "Content-Type: application/json" \
  -d '{
    "event_time": "2026-11-06T12:00:00Z",
    "event_type": "allocate",
    "inside_ip": "100.64.10.25",
    "outside_ip": "203.0.113.10",
    "port_start": 4000,
    "port_end": 8088,
    "port_block_size": 512,
    "port_step": 8,
    "protocol": "ANY",
    "source": "api",
    "mapping_mode": "pba"
  }'
```

Sample: `python examples/cgnat_pba_sample.py`

---

## Ops checklist

1. Prefer **PBA + HSL** over overload for ASR scale.  
2. Point `ip nat log translations flow-export v9` at IPDR UDP **2055**.  
3. NTP on ASR and IPDR (`/health` → `utc_now`).  
4. Retain PBA allocate/deallocate for the legal retention window.  
5. For “who + what traffic”: HSL PBA + optional inside NetFlow/sFlow + AAA.  
6. Firewall: allow UDP 2055 only from ASR.

**Durable HSL bridge** (queue, spool, dedicated process): [HSL_BRIDGE.md](HSL_BRIDGE.md)

LEA guide: [LEA.md](LEA.md) · Install: [INSTALL.md](INSTALL.md) · فارسی: [CGNAT_ASR-FA.md](CGNAT_ASR-FA.md)
