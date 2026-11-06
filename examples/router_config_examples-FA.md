# نمونه‌های پیکربندی روتر

قطعه‌کدهای همراه [ROUTER_SETUP-FA.md](../ROUTER_SETUP-FA.md).  
`192.168.1.100` را با IP سرور IPDR عوض کنید.

> **English:** [router_config_examples.md](router_config_examples.md)

کالکتورهای IPDR:

| کالکتور | پورت | پروتکل‌ها |
|---------|------|-----------|
| NetFlow / IPFIX | UDP `2055` | v1، v5، v7، v8، v9، IPFIX |
| sFlow | UDP `6343` | v2، v4، v5 |

---

## Cisco

### IOS / IOS-XE — NetFlow v5 کلاسیک

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

### IOS-XE — Flexible NetFlow (خروجی NetFlow v5)

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

### IOS-XE — Flexible NetFlow با IPv6 / IPFIX

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

### دستورهای show مفید Cisco

```cisco
show ip flow export
show ip cache flow
show flow exporter
show flow monitor
show flow interface
```

---

## MikroTik RouterOS

### همه اینترفیس‌ها (NetFlow v5)

```mikrotik
/ip traffic-flow
set enabled=yes interfaces=all cache-entries=1M active-flow-timeout=1m inactive-flow-timeout=15s

/ip traffic-flow target
add dst-address=192.168.1.100:2055 version=5
```

### فقط اینترفیس‌های مشخص

```mikrotik
/ip traffic-flow
set enabled=yes interfaces=ether1,bridge cache-entries=1M

/ip traffic-flow target
remove [find]
add dst-address=192.168.1.100:2055 version=5
```

### NetFlow v9 (در صورت پشتیبانی RouterOS)

```mikrotik
/ip traffic-flow target
add dst-address=192.168.1.100:2055 version=9
```

### بررسی

```mikrotik
/ip traffic-flow print
/ip traffic-flow target print
/ip traffic-flow status
```

---

## sFlow (UDP 6343)

ابتدا کالکتور sFlow را روشن کنید:

```bash
curl -X POST "http://127.0.0.1:8000/api/collector/start" \
  -H "Content-Type: application/json" \
  -d '{"collector_type":"sflow","host":"0.0.0.0","port":6343}'
```

عامل sFlow را به `192.168.1.100:6343` بفرستید (نرخ نمونه‌برداری معمول: ۱۲۸ تا ۱۰۲۴).

MikroTik معمولاً **Traffic Flow (NetFlow)** دارد؛ برای RouterOS ترجیحاً UDP `2055`.

---

## exporter نرم لینوکس (آزمایشگاه)

```bash
sudo softflowd -i eth0 -n 192.168.1.100:2055 -v 5
sudo nprobe -i eth0 -n 192.168.1.100:2055 -V 5
```

---

## فایروال روی میزبان IPDR

```bash
# Ubuntu / Debian
sudo ufw allow 2055/udp
sudo ufw allow 6343/udp

# AlmaLinux / RHEL
sudo firewall-cmd --permanent --add-port=2055/udp
sudo firewall-cmd --permanent --add-port=6343/udp
sudo firewall-cmd --reload
```

---

## روشن کردن کالکتورها (API)

```bash
curl -X POST "http://127.0.0.1:8000/api/collector/start" \
  -H "Content-Type: application/json" \
  -d '{"collector_type":"netflow","host":"0.0.0.0","port":2055}'

curl -X POST "http://127.0.0.1:8000/api/collector/start" \
  -H "Content-Type: application/json" \
  -d '{"collector_type":"sflow","host":"0.0.0.0","port":6343}'

curl -s "http://127.0.0.1:8000/api/collector/status"
```

راهنمای کامل: [ROUTER_SETUP-FA.md](../ROUTER_SETUP-FA.md)  
نصب: [INSTALL-FA.md](../INSTALL-FA.md)  
CGNAT PBA: [CGNAT_ASR-FA.md](../CGNAT_ASR-FA.md)
