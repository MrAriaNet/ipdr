# راهنمای اتصال روتر به IPDR

اتصال دستگاه‌های Cisco، MikroTik و عامل‌های sFlow به IPDR برای ذخیره، جستجو و تحلیل نشست‌های ترافیک.

در همهٔ مثال‌ها `192.168.1.100` را با IP سرور IPDR عوض کنید.

> **English:** [ROUTER_SETUP.md](ROUTER_SETUP.md)

## معماری

```
Cisco / MikroTik / سوییچ
   |-- UDP NetFlow v1/v5/v7/v8/v9 یا IPFIX --> :2055 --|
   |-- UDP sFlow v2/v4/v5                  --> :6343 --+--> IPDR --> PostgreSQL
```

| کالکتور | پورت پیش‌فرض | پروتکل‌ها |
|---------|--------------|-----------|
| NetFlow / IPFIX | UDP `2055` | NetFlow **v1, v5, v7, v8, v9**، **IPFIX (v10)** |
| sFlow | UDP `6343` | sFlow **v2, v4, v5** |
| JSON ساده (آزمایشگاه) | UDP `9999` | JSON سفارشی |

Exporterهای مبتنی بر قالب (NetFlow v9 / IPFIX) به‌ازای هر exporter و observation domain کش می‌شوند. بسته‌های اول ممکن است فقط template باشند؛ بعد از دریافت template، رکورد داده ذخیره می‌شود.

---

## ۱. روشن کردن کالکتورها روی سرور IPDR

```bash
curl -X POST "http://127.0.0.1:8000/api/collector/start" \
  -H "Content-Type: application/json" \
  -d '{"collector_type":"netflow","host":"0.0.0.0","port":2055}'

curl -X POST "http://127.0.0.1:8000/api/collector/start" \
  -H "Content-Type: application/json" \
  -d '{"collector_type":"sflow","host":"0.0.0.0","port":6343}'

curl "http://127.0.0.1:8000/api/collector/status"
```

فایروال:

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

## ۲. Cisco IOS / IOS-XE (NetFlow v5 کلاسیک)

```cisco
ip flow-export version 5
ip flow-export destination 192.168.1.100 2055
ip flow-export source Loopback0

ip flow-cache timeout active 1
ip flow-cache timeout inactive 15

interface GigabitEthernet0/0
 description LAN or WAN facing
 ip flow ingress
 ip flow egress
!
```

### بررسی روی روتر

```cisco
show ip flow export
show ip cache flow
show ip flow interface
```

### Cisco IOS-XE Flexible NetFlow

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

### Cisco IOS-XR

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

## ۳. MikroTik RouterOS (Traffic Flow / NetFlow)

### همه اینترفیس‌ها

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
add dst-address=192.168.1.100:2055 version=5 src-address=0.0.0.0
```

### بررسی

```mikrotik
/ip traffic-flow print
/ip traffic-flow target print
/ip traffic-flow status
```

---

## ۴. تأیید انتها به انتها

1. وضعیت کالکتور: `curl -s http://127.0.0.1:8000/api/collector/status`
2. لاگ: `tail -f /opt/ipdr/logs/ipdr_*.log`
3. داشبورد: `http://<server-ip>:8000/dashboard`
4. نمونه API: `curl -s "http://127.0.0.1:8000/api/ipdr/records?limit=5"`

### Capture اختیاری روی سرور

```bash
sudo tcpdump -ni any udp port 2055 -c 20
```

---

## ۵. sFlow

کالکتور را روی UDP **6343** روشن کنید و عامل را به `192.168.1.100:6343` بفرستید.

MikroTik معمولاً **Traffic Flow (NetFlow)** دارد نه sFlow؛ برای RouterOS از UDP `2055` استفاده کنید.

رکوردهای sFlow نمونه‌برداری‌شده‌اند؛ IPDR حجم را با `sampling_rate` تقریبی می‌کند.

---

## ۶. کالکتور JSON ساده (اختیاری)

```bash
curl -X POST "http://127.0.0.1:8000/api/collector/start" \
  -H "Content-Type: application/json" \
  -d '{"collector_type":"simple","host":"0.0.0.0","port":9999}'

python3 examples/send_flow_data.py
```

---

## ۷. عیب‌یابی

| علامت | بررسی |
|-------|--------|
| کالکتور داده نمی‌گیرد | وضعیت API، tcpdump روی 2055/6343، فایروال |
| شمارنده Cisco ثابت است | NetFlow روی اینترفیس، مسیر تا collector، `show ip flow export` |
| هدف MikroTik بی‌حرکت | `interfaces=`، Traffic Flow، دسترسی به dst-address |
| v9/IPFIX بدون رکورد | صبر برای template؛ `templates_cached` در status |
| sFlow بدون رکورد | نسخه عامل، هدر raw/IPv4، پورت 6343 |
| داشبورد خالی | دیتابیس، خطای callback در لاگ، فیلتر زمان |

نمونه‌های آماده (فارسی): [examples/router_config_examples-FA.md](examples/router_config_examples-FA.md)  
نصب فارسی: [INSTALL-FA.md](INSTALL-FA.md)  
CGNAT PBA: [CGNAT_ASR-FA.md](CGNAT_ASR-FA.md)
