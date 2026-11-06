# Router Configuration Examples

> **فارسی:** [router_config_examples-FA.md](router_config_examples-FA.md)

Companion snippets for [ROUTER_SETUP.md](../ROUTER_SETUP.md).  
Replace `192.168.1.100` with your IPDR server IP.

IPDR collectors:

| Collector | Port | Protocols |
|-----------|------|-----------|
| NetFlow / IPFIX | UDP `2055` | v1, v5, v7, v8, v9, IPFIX |
| sFlow | UDP `6343` | v2, v4, v5 |

---

## Cisco

### IOS / IOS-XE — classic NetFlow v5

```cisco
ip flow-export version 5
ip flow-export destination 192.168.1.100 2055
ip flow-export source Loopback0
ip flow-cache timeout active 1
ip flow-cache timeout inactive 15

interface GigabitEthernet0/0
 ip flow ingress
 ip flow egress
```

### IOS-XE — Flexible NetFlow (export as NetFlow v5)

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
```

### IOS-XE — Flexible NetFlow with IPv6 / IPFIX

```cisco
flow exporter IPDR_IPFIX
 destination 192.168.1.100
 transport udp 2055
 export-protocol ipfix
 source Loopback0
!
flow monitor IPDR_V6
 exporter IPDR_IPFIX
 record netflow ipv6 original-input
 cache timeout active 60
 cache timeout inactive 15
!
interface GigabitEthernet0/0
 ipv6 flow monitor IPDR_V6 input
 ipv6 flow monitor IPDR_V6 output
```

### IOS-XR

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
```

### Useful Cisco show commands

```cisco
show ip flow export
show ip cache flow
show flow exporter
show flow monitor
show flow interface
```

---

## MikroTik RouterOS

### All interfaces (NetFlow v5)

```mikrotik
/ip traffic-flow
set enabled=yes interfaces=all cache-entries=1M active-flow-timeout=1m inactive-flow-timeout=15s

/ip traffic-flow target
add dst-address=192.168.1.100:2055 version=5
```

### Specific interfaces only

```mikrotik
/ip traffic-flow
set enabled=yes interfaces=ether1,bridge cache-entries=1M

/ip traffic-flow target
remove [find]
add dst-address=192.168.1.100:2055 version=5
```

### NetFlow v9 (if supported by your RouterOS build)

```mikrotik
/ip traffic-flow target
add dst-address=192.168.1.100:2055 version=9
```

### Verify

```mikrotik
/ip traffic-flow print
/ip traffic-flow target print
/ip traffic-flow status
```

---

## sFlow (UDP 6343)

Start the IPDR sFlow collector first:

```bash
curl -X POST "http://127.0.0.1:8000/api/collector/start" \
  -H "Content-Type: application/json" \
  -d '{"collector_type":"sflow","host":"0.0.0.0","port":6343}'
```

Point the sFlow agent at `192.168.1.100:6343` (typical sampling rate: 128–1024).

MikroTik usually uses **Traffic Flow (NetFlow)** rather than sFlow — prefer UDP `2055` for RouterOS.

---

## Linux soft exporters (lab)

```bash
# softflowd → NetFlow v5
sudo softflowd -i eth0 -n 192.168.1.100:2055 -v 5

# nprobe → NetFlow v5
sudo nprobe -i eth0 -n 192.168.1.100:2055 -V 5
```

---

## Firewall on the IPDR host

```bash
# Ubuntu / Debian (UFW)
sudo ufw allow 2055/udp
sudo ufw allow 6343/udp

# AlmaLinux / RHEL (firewalld)
sudo firewall-cmd --permanent --add-port=2055/udp
sudo firewall-cmd --permanent --add-port=6343/udp
sudo firewall-cmd --reload
```

---

## Start collectors (API)

```bash
# NetFlow / IPFIX (all supported versions)
curl -X POST "http://127.0.0.1:8000/api/collector/start" \
  -H "Content-Type: application/json" \
  -d '{"collector_type":"netflow","host":"0.0.0.0","port":2055}'

# sFlow
curl -X POST "http://127.0.0.1:8000/api/collector/start" \
  -H "Content-Type: application/json" \
  -d '{"collector_type":"sflow","host":"0.0.0.0","port":6343}'

curl -s "http://127.0.0.1:8000/api/collector/status"
```

Full procedures: [ROUTER_SETUP.md](../ROUTER_SETUP.md) · فارسی: [ROUTER_SETUP-FA.md](../ROUTER_SETUP-FA.md)  
Persian install: [INSTALL-FA.md](../INSTALL-FA.md)
