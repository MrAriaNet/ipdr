# IPDR — سیستم ثبت جزئیات پروتکل اینترنت

جمع‌آوری، ذخیره، جستجو و تحلیل نشست‌های ترافیک شبکه. مناسب سرورهای لینوکس (Ubuntu، Debian، AlmaLinux) با ورودی **NetFlow / IPFIX / sFlow** از **Cisco**، **MikroTik** و سایر exporterها — پشتیبانی **IPv4 و IPv6**.

> **English:** [README.md](README.md)  
> **نصب و استفادهٔ کامل:** [INSTALL-FA.md](INSTALL-FA.md) · انگلیسی: [INSTALL.md](INSTALL.md)

## قابلیت‌ها

- رکوردهای IPDR: مبدأ/مقصد (**IPv4 و IPv6**)، پورت، زمان، حجم، پروتکل، سرویس، شناسه کاربر
- نگاشت کامل پروتکل‌های IANA (`GET /api/ipdr/protocols`) — TCP، UDP، ICMPv6، GRE، ESP، SCTP و …
- کالکتور NetFlow **v1 / v5 / v7 / v8 / v9** و **IPFIX** (UDP 2055، dual-stack)
- کالکتور **sFlow v2 / v4 / v5** (UDP 6343) با **تخمین حجم بر اساس sample rate** (≈۱۰۰٪ ترافیک؛ [SFLOW-FA.md](SFLOW-FA.md))
- کالکتور JSON آزمایشی (UDP 9999)
- کمک‌های DPI (Scapy) برای تشخیص سرویس / تهدید
- آمار، خلاصه ترافیک و جستجوی پیشرفته
- رویدادهای امنیتی
- لاگ فایل با چرخش در `logs/`
- مدل‌های صورتحساب: prepaid، postpaid، hybrid
- داشبورد HTML و مستندات OpenAPI (`/docs`)
- **CGNAT Port Block Allocation (PBA)** برای Cisco ASR (مثل 1001-X): ذخیره allocate/deallocate و جستجوی `public_ip:port` ← IP مشترک (بدون جدول کانکشن/XLATE)
- **گردش کار نهاد / امنیت**: AAA، investigate، export با هش، audit پرس‌وجو، legal hold، retention — [LEA-FA.md](LEA-FA.md)
- **واسط پایدار HSL برای PBA**: صف + اسپیل دیسک + کش قالب تا لاگ ASR از دست نرود — [HSL_BRIDGE-FA.md](HSL_BRIDGE-FA.md)

## پیش‌نیازها

| مورد | نسخه |
|------|------|
| سیستم‌عامل | Ubuntu 22.04+، Debian 12+، AlmaLinux 8/9 |
| Python | 3.10+ |
| PostgreSQL | 14+ |

## نصب سریع (لینوکس)

```bash
sudo apt update   # یا: sudo dnf install ...
# جزئیات بسته‌ها: INSTALL-FA.md

git clone https://github.com/MrAriaNet/ipdr.git
cd ipdr
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# DATABASE_URL را ویرایش کنید

python setup.py
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

واحد systemd: [deploy/ipdr.service](deploy/ipdr.service). راهنمای کامل فارسی: [INSTALL-FA.md](INSTALL-FA.md).

### متغیرهای محیط

| متغیر | کاربرد | پیش‌فرض |
|-------|--------|---------|
| `DATABASE_URL` | آدرس PostgreSQL | `postgresql://ipdr_user:ipdr_pass@localhost:5432/ipdr_db` |
| `CORS_ORIGINS` | `*` یا لیست مبدأها با ویرگول | `*` |

در محیط واقعی رمز دیتابیس را عوض کنید.

## دسترسی

| آدرس | توضیح |
|------|--------|
| http://SERVER:8000 | صفحه اصلی |
| http://SERVER:8000/dashboard | داشبورد |
| http://SERVER:8000/docs | Swagger |
| http://SERVER:8000/redoc | ReDoc |
| http://SERVER:8000/health | سلامت |
| http://SERVER:8000/api/ipdr/protocols | فهرست پروتکل‌ها |
| http://SERVER:8000/api/cgnat/lookup | جستجوی CGNAT PBA |

## خلاصه API

### IPDR
- `GET /api/ipdr/protocols`
- `POST /api/ipdr/records`
- `GET /api/ipdr/records` — فیلتر: `ip_version`، `protocol`، `protocol_number`
- `GET /api/ipdr/records/{id}`
- `GET /api/ipdr/statistics`
- `POST /api/ipdr/summaries/create`
- `GET /api/ipdr/search`
- `GET /api/ipdr/search/count`

### Collectors
- `POST /api/collector/start` — `netflow`، `sflow` یا `simple`
- `POST /api/collector/stop`
- `GET /api/collector/status`

### Security
- `GET /api/security/events`
- `POST /api/security/events`
- `PATCH /api/security/events/{id}/resolve`

### CGNAT PBA
- `POST /api/cgnat/blocks`
- `POST /api/cgnat/blocks/bulk`
- `GET /api/cgnat/blocks`
- `GET /api/cgnat/lookup?public_ip=&public_port=&at=` — نگاشت امنیتی PBA (بدون جدول کانکشن/XLATE؛ چندنتیجه/مبهم)
- `GET /api/cgnat/lookup/by-subscriber?inside_ip=&at=` — معکوس: مشترک ← بلوک‌های پورت عمومی
- `POST /api/lea/investigate` — بسته CGNAT ← AAA ← فلو
- `POST /api/lea/export` — خروجی پرونده + هش
- `GET /api/lea/audit` — ردپای پرس‌وجو (admin)

راهنمای ASR / PBA: **[CGNAT_ASR-FA.md](CGNAT_ASR-FA.md)** · نهاد: **[LEA-FA.md](LEA-FA.md)**

## اتصال روتر (Cisco، MikroTik، sFlow)

```bash
curl -X POST "http://127.0.0.1:8000/api/collector/start" \
  -H "Content-Type: application/json" \
  -d '{"collector_type":"netflow","host":"0.0.0.0","port":2055}'

curl -X POST "http://127.0.0.1:8000/api/collector/start" \
  -H "Content-Type: application/json" \
  -d '{"collector_type":"sflow","host":"0.0.0.0","port":6343}'
```

**Cisco (خلاصه NetFlow v5):**

```cisco
ip flow-export version 5
ip flow-export destination 192.168.1.100 2055
interface GigabitEthernet0/0
 ip flow ingress
 ip flow egress
```

**MikroTik (خلاصه):**

```mikrotik
/ip traffic-flow
set enabled=yes interfaces=all
/ip traffic-flow target
add dst-address=192.168.1.100:2055 version=5
```

- راهنمای کامل: **[ROUTER_SETUP-FA.md](ROUTER_SETUP-FA.md)** · [ROUTER_SETUP.md](ROUTER_SETUP.md)
- نمونه‌های آماده: **[examples/router_config_examples-FA.md](examples/router_config_examples-FA.md)** · [examples/router_config_examples.md](examples/router_config_examples.md)

## مثال‌ها

```bash
python examples/sample_data.py
python examples/send_flow_data.py
python examples/cgnat_pba_sample.py
```

## ساختار پروژه

```
ipdr/
├── app/ …
├── deploy/ipdr.service
├── examples/
├── README.md / README-FA.md
├── INSTALL-FA.md
├── ROUTER_SETUP.md / ROUTER_SETUP-FA.md
├── CGNAT_ASR.md / CGNAT_ASR-FA.md
├── requirements.txt
├── setup.py
└── LICENSE
```

## عیب‌یابی

- **دیتابیس:** سرویس PostgreSQL و `DATABASE_URL` را بررسی کنید.
- **پورت ۸۰۰۰:** پورت uvicorn را عوض کنید.
- **بدون رکورد NetFlow:** وضعیت کالکتور، `tcpdump` روی UDP 2055، شمارنده‌های روتر.
- **بدون sFlow:** UDP 6343 و تنظیم sampling عامل sFlow.
- **خطای build:** `build-essential` / `gcc` و `libpq-dev` (یا `libpq-devel`).

## نکات امنیتی

- در تولید CORS و دسترسی دیتابیس را محدود کنید.
- TLS را با reverse proxy (Nginx/Caddy) تمام کنید.
- NetFlow / sFlow / API را بدون کنترل به اینترنت باز نکنید.
- فایل `.env` را در گیت نگذارید.

## مجوز

MIT — [LICENSE](LICENSE).
