# Router Integration Guide

Connect Cisco, MikroTik, and sFlow-capable devices to IPDR so traffic sessions are stored, searched, and analyzed.

Replace `192.168.1.100` with the IP address of your IPDR server in every example below.

## Architecture

```
Cisco / MikroTik / switch
   |-- UDP NetFlow v1/v5/v7/v8/v9 or IPFIX --> :2055 --|
   |-- UDP sFlow v2/v4/v5                  --> :6343 --+--> IPDR --> PostgreSQL
```

| Collector | Default port | Protocols |
|-----------|--------------|-----------|
| NetFlow / IPFIX | UDP `2055` | NetFlow **v1, v5, v7, v8, v9**, **IPFIX (v10)** |
| sFlow | UDP `6343` | sFlow **v2, v4, v5** |
| Simple JSON (lab) | UDP `9999` | custom JSON |

Template-based exporters (NetFlow v9 / IPFIX) are cached per exporter + observation domain. The first packets may only carry templates; data records are stored once templates are known.

---

## 1. Start collectors on the IPDR server

```bash
# NetFlow v1/v5/v7/v8/v9 + IPFIX
curl -X POST "http://127.0.0.1:8000/api/collector/start" \
  -H "Content-Type: application/json" \
  -d '{"collector_type":"netflow","host":"0.0.0.0","port":2055}'

# sFlow (switches / routers that export sFlow)
curl -X POST "http://127.0.0.1:8000/api/collector/start" \
  -H "Content-Type: application/json" \
  -d '{"collector_type":"sflow","host":"0.0.0.0","port":6343}'

curl "http://127.0.0.1:8000/api/collector/status"
```

Open the firewall:

**Ubuntu / Debian (UFW)**

```bash
sudo ufw allow 2055/udp comment 'IPDR NetFlow'
sudo ufw allow 6343/udp comment 'IPDR sFlow'
sudo ufw reload
```

**AlmaLinux / RHEL (firewalld)**

```bash
sudo firewall-cmd --permanent --add-port=2055/udp
sudo firewall-cmd --permanent --add-port=6343/udp
sudo firewall-cmd --reload
```

---

## 2. Cisco IOS / IOS-XE (classic NetFlow v5)

Recommended for older IOS and many edge routers that still export NetFlow v5.

```cisco
! Export NetFlow v5 to the IPDR server
ip flow-export version 5
ip flow-export destination 192.168.1.100 2055
! Prefer a stable source address if you have a loopback
ip flow-export source Loopback0

! Cache timeouts (minutes for active; seconds for inactive on many platforms)
ip flow-cache timeout active 1
ip flow-cache timeout inactive 15

! Enable on the interface that carries customer / WAN traffic
interface GigabitEthernet0/0
 description LAN or WAN facing
 ip flow ingress
 ip flow egress
!
```

### Verify on the router

```cisco
show ip flow export
show ip cache flow
show ip flow interface
```

Confirm `packets exported` increases and the destination matches the IPDR server.

### Cisco IOS-XE Flexible NetFlow (legacy-compatible export)

On platforms that use Flexible NetFlow, configure an exporter that still targets UDP 2055. Prefer NetFlow v5 when possible for this collector.

```cisco
flow exporter IPDR_EXPORTER
 description Export to IPDR
 destination 192.168.1.100
 transport udp 2055
 export-protocol netflow-v5
 source Loopback0
!

flow monitor IPDR_MONITOR
 description IPDR IPv4 monitor
 exporter IPDR_EXPORTER
 record netflow ipv4 original-input
 cache timeout active 60
 cache timeout inactive 15
!

interface GigabitEthernet0/0
 ip flow monitor IPDR_MONITOR input
 ip flow monitor IPDR_MONITOR output
!
```

### Cisco IOS-XR (exporter map)

```cisco
flow exporter-map IPDR_EXPORTER
 version v5
 destination 192.168.1.100
 transport udp 2055
 source Loopback0
!

sampler-map IPDR_SAMPLER
 random 1 out-of 1
!

flow monitor-map IPDR_MONITOR
 record ipv4
 exporter IPDR_EXPORTER
 cache entries 10000
 cache timeout active 60
 cache timeout inactive 15
!

interface GigabitEthernet0/0/0/0
 flow ipv4 monitor IPDR_MONITOR sampler IPDR_SAMPLER ingress
 flow ipv4 monitor IPDR_MONITOR sampler IPDR_SAMPLER egress
!
```

---

## 3. MikroTik RouterOS (Traffic Flow / NetFlow)

Works on RouterOS v6 and v7. Traffic Flow exports NetFlow-compatible packets.

### Basic setup (all interfaces)

```mikrotik
/ip traffic-flow
set enabled=yes interfaces=all cache-entries=1M active-flow-timeout=1m inactive-flow-timeout=15s

/ip traffic-flow target
add dst-address=192.168.1.100:2055 version=5
```

### Recommended: limit to WAN / customer interfaces

```mikrotik
# Example: only ether1 (WAN) and bridge (LAN)
/ip traffic-flow
set enabled=yes interfaces=ether1,bridge cache-entries=1M

/ip traffic-flow target
remove [find]
add dst-address=192.168.1.100:2055 version=5 src-address=0.0.0.0
```

If the router has multiple paths to the collector, pin the source:

```mikrotik
/ip traffic-flow target
set [find] src-address=192.168.1.1
```

### RouterOS v7 notes

- Use **IP → Traffic Flow** (same CLI path `/ip traffic-flow`).
- Prefer `version=5` for this IPDR release.
- High PPS links may need a dedicated collector host and larger `cache-entries`.

### Verify on MikroTik

```mikrotik
/ip traffic-flow print
/ip traffic-flow target print
/ip traffic-flow status
```

Generate traffic through the monitored interfaces and confirm the target shows packets / bytes increasing.

---

## 4. End-to-end verification

1. Collector status shows NetFlow running:
   ```bash
   curl -s http://127.0.0.1:8000/api/collector/status
   ```
2. Application logs:
   ```bash
   tail -f /opt/ipdr/logs/ipdr_*.log
   ```
3. Dashboard: `http://<server-ip>:8000/dashboard`
4. API sample:
   ```bash
   curl -s "http://127.0.0.1:8000/api/ipdr/records?limit=5"
   ```

### Capture on the server (optional)

```bash
sudo tcpdump -ni any udp port 2055 -c 20
```

If no packets arrive, check routing, NAT, and firewall on both the router and the server.

---

## 5. sFlow exporters

Start the sFlow collector on UDP **6343**, then point the agent at `192.168.1.100:6343`.

### Generic / Linux host sFlow (host-sflow / hsflowd)

Configure the collector IP and sampling rate in the agent (example concept):

```
collector.ip=192.168.1.100
collector.port=6343
sampling.rate=128
```

### Cisco (platform-dependent)

Many Nexus / IOS-XE platforms export sFlow or NetFlow; prefer NetFlow/IPFIX to UDP 2055 when available. If the platform only offers sFlow, set the collector to `192.168.1.100` port `6343` and enable sampling on the monitored interfaces per vendor docs.

### MikroTik

MikroTik **Traffic Flow** exports NetFlow (use section 3 → UDP 2055). Native sFlow is uncommon on RouterOS; use NetFlow v5/v9 toward the NetFlow collector.

sFlow records are *sampled*: IPDR multiplies frame size by the reported sampling rate for approximate byte/packet totals.

---

## 6. Optional: simple JSON collector

For labs or devices without NetFlow/sFlow:

```bash
curl -X POST "http://127.0.0.1:8000/api/collector/start" \
  -H "Content-Type: application/json" \
  -d '{"collector_type":"simple","host":"0.0.0.0","port":9999}'

python3 examples/send_flow_data.py
```

---

## 7. Troubleshooting

| Symptom | What to check |
|---------|----------------|
| Collector not receiving | `curl .../api/collector/status`, `tcpdump` on UDP 2055 or 6343, firewall |
| Cisco export counter stuck | Interface NetFlow enabled, ACL/NAT path to collector, `show ip flow export` |
| MikroTik target idle | Correct `interfaces=`, Traffic Flow enabled, reachable `dst-address` |
| v9/IPFIX no records | Wait for template packets; check `templates_cached` in `/api/collector/status` |
| sFlow no records | Confirm agent version 2/4/5, raw/IPv4 sampled headers enabled, port 6343 |
| No rows in dashboard | Database up, collector callback errors in logs, time filters on dashboard |
| Partial / wrong timestamps | Enable NTP on exporters; for uptime-based fields check exporter boot time |

Ready-to-paste snippets: [examples/router_config_examples.md](examples/router_config_examples.md)  
Persian install and usage (including routers): [INSTALL-FA.md](INSTALL-FA.md)
