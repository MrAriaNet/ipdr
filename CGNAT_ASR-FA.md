# تخصیص بلوک پورت CGNAT (PBA) — Cisco ASR و IPDR

> **English:** [CGNAT_ASR.md](CGNAT_ASR.md)

## چرا PBA؟

روی پلتفرم‌هایی مثل **Cisco ASR 1001-X**، NAT سطح اپراتور (CGNAT) می‌تواند به‌صورت **Port Block Allocation (PBA)** کار کند:

- به‌جای لاگ هر translation جداگانه، به هر مشترک یک **بلوک پیوسته** از پورت‌های عمومی (مثلاً ۵۱۲ یا ۱۰۲۴ تایی) داده می‌شود.
- حجم High-Speed Logging (HSL) / IPFIX به‌شدت کم می‌شود.
- امنیت شبکه همچنان به IPDR نیاز دارد: نگاشت `public_ip:public_port` ← **IP داخلی مشترک** در زمان حادثه.

این سیستم رویدادهای allocate/deallocate را ذخیره می‌کند و API جستجو برای همان نگاشت را در اختیار می‌گذارد.

## مدل داده (چه چیزی ذخیره می‌شود)

| فیلد | معنی |
|------|------|
| `inside_ip` | آدرس مشترک / pre-NAT |
| `outside_ip` | آدرس عمومی / post-NAT |
| `port_start` / `port_end` | بلوک پیوسته پورت عمومی |
| `port_block_size` | معمولاً `end - start + 1` (۵۱۲، ۱۰۲۴، …) |
| `event_type` | `allocate` / `deallocate` |
| `event_time` / `released_at` | زمان اختصاص / آزادسازی |
| `is_active` | آیا بلوک هنوز در اختیار مشترک است |

## مسیرهای ورود داده

### ۱) IPFIX / NetFlow از ASR (پیشنهادی)

کالکتور NetFlow/IPFIX را روی UDP **2055** روشن کنید. قالب‌هایی که IEهای NAT / port-range دارند به‌عنوان CGNAT PBA شناخته و در `cgnat_port_blocks` ذخیره می‌شوند (نه به‌عنوان flow عادی).

```bash
curl -X POST "http://127.0.0.1:8000/api/collector/start" \
  -H "Content-Type: application/json" \
  -d '{"collector_type":"netflow","host":"0.0.0.0","port":2055}'
```

IEهای شناخته‌شده (از جمله):

- `225` postNATSourceIPv4Address  
- `230` natEvent  
- `361`–`364` portRangeStart / End / Step / NumPorts  
- منبع pre-NAT از IE `8` / IPv6 `27`

### ۲) REST API (پل HSL / اسکریپت)

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

دسته‌ای: `POST /api/cgnat/blocks/bulk` با `{ "records": [ ... ] }`.

## جستجوی امنیت (LEA / SOC)

```bash
curl -s "http://127.0.0.1:8000/api/cgnat/lookup?public_ip=203.0.113.10&public_port=1500&at=2026-11-06T12:30:00"
```

نمونه پاسخ:

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

لیست بلوک‌ها: `GET /api/cgnat/blocks?outside_ip=203.0.113.10&is_active=true`

---

## Cisco ASR 1001-X — اسکلت پیکربندی

دستور دقیق بسته به نسخه IOS-XE / قابلیت CGN فرق می‌کند. بلوک‌های رایج:

### فعال‌سازی CGN با PBA

```cisco
! مفاهیم نمونه — با راهنمای IOS-XE / CGN خودتان تطبیق دهید
ip nat settings mode cgn
ip nat settings port-block-allocation size 1024
! یا وابسته به پلتفرم:
! ip nat translation port-block-allocation enable
! ip nat translation port-block size 1024
```

بررسی:

```cisco
show ip nat translations
show ip nat port-block
show platform hardware qfp active feature nat datapath …
```

### خروجی لاگ NAT / PBA با IPFIX (HSL → collector)

Exporter را به سرور IPDR بفرستید (`192.168.1.100:2055`):

```cisco
flow exporter IPDR_CGN
 destination 192.168.1.100
 transport udp 2055
 export-protocol ipfix
 source Loopback0
!
! اتصال exporter به لاگ CGN/NAT طبق نسخه IOS-XE شما
```

روی سرور IPDR پورت **UDP 2055** را از سمت ASR باز کنید.

> همیشه با `tcpdump -ni any udp port 2055` قالب‌ها را ببینید و در لاگ IPDR پیام‌های `CGNAT PBA allocate/deallocate` را چک کنید.

### نکات عملی برای امنیت

1. لاگ PBA را حداقل به‌اندازه سیاست نگهداری قانونی IPDR نگه دارید.  
2. در lookup از **زمان حادثه** استفاده کنید، نه «الان»، اگر بلوک ممکن است آزاد شده باشد.  
3. اندازه بلوک (۵۱۲/۱۰۲۴/…) باید با تنظیم ASR یکی باشد.  
4. ASR و IPDR را روی **NTP** نگه دارید.

---

## اسکریپت نمونه

```bash
python examples/cgnat_pba_sample.py
```

نصب فارسی: [INSTALL-FA.md](INSTALL-FA.md)  
اتصال روتر: [ROUTER_SETUP-FA.md](ROUTER_SETUP-FA.md)
