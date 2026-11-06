# تخصیص بلوک پورت CGNAT (PBA) — Cisco ASR 1001-X و IPDR

> **English:** [CGNAT_ASR.md](CGNAT_ASR.md)

## مشکل عملیاتی (چرا با PBA دیگر NetFlow «کشیده نمی‌شود»)

روی **Cisco ASR 1001-X** (و سری ASR 1000 در حالت CGN):

| حالت | فشار روی دستگاه | لاگ |
|------|------------------|-----|
| **NAT Overload** (XLATE به‌ازای هر session) | زیاد — ناپایدار در مقیاس بالا | لاگ سنگین به‌ازای هر translation |
| **CGNAT PBA / Bulk Logging** | پایدار — مناسب CGN | **فقط** allocate / deallocate **مجموعه پورت** از طریق **HSL** NetFlow v9 |

با روشن بودن PBA، سیسکو **هر session را لاگ نمی‌کند** و برای BPA **Syslog پشتیبانی نمی‌شود**. مقصد (destination) هم لاگ نمی‌شود. پس انتظار «NetFlow تک‌تک کانکشن از خود CGN» اشتباه است.

**مسیر درست IPDR با PBA:**

1. **هویت (چه کسی public IP:port را داشته)** ← HSL رویدادهای PBA از ASR → همین سیستم (`cgnat_port_blocks`)
2. **جزئیات ترافیک (اختیاری)** ← Flexible NetFlow / sFlow روی اینترفیس **داخل** (pre-NAT) یا نقطهٔ دیگر — همبستگی با `POST /api/lea/investigate`

این IPDR دقیقاً برای همین مدل است: نگاشت کامل و دقیق مشترک از لاگ PBA، بدون جدول کانکشن.

## چه چیزی از ASR می‌آید (فیلدهای HSL)

```cisco
ip nat log translations flow-export v9 udp destination 192.168.1.100 2055
```

| IE | معنی |
|----|------|
| 8 | IP داخلی مشترک |
| 225 | IP عمومی (post-NAT) |
| 230 | رویداد: `1`=allocate ، `2`=deallocate |
| 323 | زمان (میلی‌ثانیه) |
| 361 | شروع بلوک پورت |
| 363 | **step** (پورت‌های پراکنده، مثلاً ۸) |
| 364 | تعداد پورت در بلوک (مثلاً ۵۱۲) |

پورت‌های مجموعه: `start`, `start+step`, …  
IPDR فیلد `port_step` را نگه می‌دارد و فقط پورت‌هایی که واقعاً در مجموعه هستند را به مشترک نسبت می‌دهد.

---

## پیکربندی ASR 1001-X (PBA + HSL)

پیش‌نیاز: حالت **CGN** + **paired-address pooling**.

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
ip nat pool CGN_POOL 203.0.113.10 203.0.113.20 prefix-length 24
access-list 1 permit 100.64.0.0 0.63.255.255
ip nat inside source list 1 pool CGN_POOL
!
! Bulk Port Allocation
ip nat settings pap bpa set-size 512 step-size 8
!
! === خوراک IPDR (نه NetFlow اینترفیس) ===
ip nat log translations flow-export v9 udp destination 192.168.1.100 2055
!
end
```

بررسی روی ASR:

```cisco
show ip nat bpa
show ip nat translations
show ip nat statistics
```

روی سرور IPDR:

```bash
curl -X POST "http://127.0.0.1:8000/api/collector/start" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: change-me-admin" \
  -d '{"collector_type":"netflow","host":"0.0.0.0","port":2055}'

sudo tcpdump -ni any udp port 2055 -c 20

curl -s "http://127.0.0.1:8000/api/cgnat/lookup?public_ip=203.0.113.10&public_port=4008&at=2026-11-06T12:30:00Z" \
  -H "X-API-Key: change-me-lea"
```

برای حجم ترافیک می‌توانید جداگانه NetFlow روی اینترفیس **inside** بفرستید؛ هویت مشترک همچنان از HSL PBA است.

---

## جستجوی امنیت / نهاد

ورودی: **IP عمومی + پورت عمومی + زمان** (بدون inside_port و بدون جدول کانکشن).

بسته کامل: `POST /api/lea/investigate` — راهنما: [LEA-FA.md](LEA-FA.md)

اگر `ambiguous: true` باشد پاسخ را قطعی ندانید.

نمونه تست: `python examples/cgnat_pba_sample.py`

**واسط پایدار لاگ (صف + اسپیل دیسک + bridge جدا):** [HSL_BRIDGE-FA.md](HSL_BRIDGE-FA.md)

نصب: [INSTALL-FA.md](INSTALL-FA.md) · انگلیسی: [CGNAT_ASR.md](CGNAT_ASR.md)
