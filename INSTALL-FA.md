# راهنمای نصب و استفاده IPDR (فارسی)

این سند نصب روی **سرور لینوکس** (Ubuntu، Debian، AlmaLinux) و استفاده روزمره را به فارسی توضیح می‌دهد.  
متن برنامه، API و مستندات فنی اصلی به **انگلیسی** هستند.

> رمزهای نمونه فقط برای آزمایش هستند. در محیط واقعی حتماً آن‌ها را عوض کنید.

---

## پیش‌نیازها

| مورد | نسخه پیشنهادی |
|------|----------------|
| سیستم‌عامل | Ubuntu 22.04+ / Debian 12+ / AlmaLinux 8 یا 9 |
| Python | 3.10 یا بالاتر |
| PostgreSQL | 14 یا بالاتر |
| دسترسی | کاربر با sudo |

پورت‌های پیش‌فرض:

- API / داشبورد: TCP `8000`
- NetFlow v1/v5/v7/v8/v9 و IPFIX: UDP `2055`
- sFlow v2/v4/v5: UDP `6343`
- کالکتور JSON آزمایشی: UDP `9999`

---

## ۱. نصب بسته‌های سیستم

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip postgresql postgresql-contrib \
  build-essential libpq-dev curl git
sudo systemctl enable --now postgresql
```

### AlmaLinux / RHEL

```bash
sudo dnf install -y python3 python3-pip postgresql-server postgresql-contrib \
  gcc gcc-c++ libpq-devel curl git
sudo postgresql-setup --initdb
sudo systemctl enable --now postgresql
```

در AlmaLinux ممکن است لازم باشد در `pg_hba.conf` احراز هویت محلی را برای کاربر اپلیکیشن تنظیم کنید (مثلاً `md5` یا `scram-sha-256`).

---

## ۲. دریافت پروژه

```bash
sudo mkdir -p /opt/ipdr
sudo chown "$USER":"$USER" /opt/ipdr
cd /opt
git clone https://github.com/MrAriaNet/ipdr.git ipdr
cd /opt/ipdr
```

اگر مخزن را هنوز منتشر نکرده‌اید، پوشهٔ پروژه را روی سرور کپی کنید و `cd` به همان مسیر بزنید.

---

## ۳. پایگاه داده PostgreSQL

```bash
sudo -u postgres psql <<'SQL'
CREATE USER ipdr_user WITH PASSWORD 'CHANGE_ME_STRONG_PASSWORD';
CREATE DATABASE ipdr_db OWNER ipdr_user;
GRANT ALL PRIVILEGES ON DATABASE ipdr_db TO ipdr_user;
SQL
```

PostgreSQL 15+:

```bash
sudo -u postgres psql -d ipdr_db -c "GRANT ALL ON SCHEMA public TO ipdr_user;"
```

تست اتصال:

```bash
psql -h 127.0.0.1 -U ipdr_user -d ipdr_db -c 'SELECT 1;'
```

---

## ۴. محیط مجازی و وابستگی‌ها

```bash
cd /opt/ipdr
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

---

## ۵. تنظیم `.env`

```bash
cp .env.example .env
nano .env
```

نمونه:

```env
DATABASE_URL=postgresql://ipdr_user:CHANGE_ME_STRONG_PASSWORD@127.0.0.1:5432/ipdr_db
CORS_ORIGINS=*
```

در محیط واقعی به‌جای `*` آدرس‌های مجاز را با ویرگول بنویسید.

ایجاد جداول:

```bash
source venv/bin/activate
python setup.py
```

---

## ۶. اجرای موقت (تست)

```bash
source venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

بررسی:

```bash
curl http://127.0.0.1:8000/health
```

آدرس‌ها:

| آدرس | کاربرد |
|------|--------|
| `http://SERVER_IP:8000` | صفحهٔ اصلی |
| `http://SERVER_IP:8000/dashboard` | داشبورد |
| `http://SERVER_IP:8000/docs` | مستندات API (Swagger) |
| `http://SERVER_IP:8000/redoc` | ReDoc |
| `http://SERVER_IP:8000/health` | سلامت سرویس |
| `http://SERVER_IP:8000/api/ipdr/protocols` | فهرست کامل پروتکل‌های IANA |

---

## ۷. اجرای دائمی با systemd (پیشنهادی)

```bash
sudo useradd --system --home /opt/ipdr --shell /usr/sbin/nologin ipdr || true
sudo chown -R ipdr:ipdr /opt/ipdr
sudo cp deploy/ipdr.service /etc/systemd/system/ipdr.service
sudo systemctl daemon-reload
sudo systemctl enable --now ipdr
sudo systemctl status ipdr
```

لاگ سرویس:

```bash
journalctl -u ipdr -f
```

لاگ برنامه:

```bash
tail -f /opt/ipdr/logs/ipdr_*.log
```

---

## ۸. فایروال

### Ubuntu / Debian (UFW)

```bash
sudo ufw allow 8000/tcp comment 'IPDR API'
sudo ufw allow 2055/udp comment 'IPDR NetFlow'
sudo ufw allow 6343/udp comment 'IPDR sFlow'
sudo ufw reload
```

### AlmaLinux (firewalld)

```bash
sudo firewall-cmd --permanent --add-port=8000/tcp
sudo firewall-cmd --permanent --add-port=2055/udp
sudo firewall-cmd --permanent --add-port=6343/udp
sudo firewall-cmd --reload
```

فقط شبکهٔ مدیریت/روتر باید به این پورت‌ها دسترسی داشته باشد.

---

## ۹. استفاده از API و داشبورد

1. داشبورد را باز کنید و فیلتر IP، پروتکل، سرویس یا جستجوی متنی بزنید.
2. آمار را با دکمهٔ Statistics ببینید.
3. برای اسکریپت‌نویسی از `/docs` استفاده کنید.

ثبت یک رکورد نمونه:

```bash
curl -X POST "http://127.0.0.1:8000/api/ipdr/records" \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "192.168.1.10",
    "source_port": 54321,
    "destination_ip": "8.8.8.8",
    "destination_port": 53,
    "session_start_time": "2026-01-15T10:00:00",
    "session_end_time": "2026-01-15T10:00:05",
    "duration_seconds": 5,
    "bytes_uploaded": 1000,
    "bytes_downloaded": 2000,
    "total_bytes": 3000,
    "packets_uploaded": 10,
    "packets_downloaded": 20,
    "total_packets": 30,
    "protocol": "UDP",
    "service_type": "DNS",
    "user_id": "lab-user"
  }'
```

دادهٔ آزمایشی دسته‌ای:

```bash
source /opt/ipdr/venv/bin/activate
python /opt/ipdr/examples/sample_data.py
```

---

## ۱۰. اتصال روتر سیسکو (Cisco)

کالکتور NetFlow از نسخه‌های **v1، v5، v7، v8، v9** و **IPFIX** پشتیبانی می‌کند. روی سرور:

```bash
curl -X POST "http://127.0.0.1:8000/api/collector/start" \
  -H "Content-Type: application/json" \
  -d '{"collector_type":"netflow","host":"0.0.0.0","port":2055}'

# در صورت نیاز به sFlow:
curl -X POST "http://127.0.0.1:8000/api/collector/start" \
  -H "Content-Type: application/json" \
  -d '{"collector_type":"sflow","host":"0.0.0.0","port":6343}'
```

نمونهٔ پیکربندی Cisco IOS / IOS-XE (NetFlow v5):

```cisco
ip flow-export version 5
ip flow-export destination SERVER_IP 2055
ip flow-export source Loopback0
ip flow-cache timeout active 1
ip flow-cache timeout inactive 15

interface GigabitEthernet0/0
 ip flow ingress
 ip flow egress
```

بررسی روی روتر:

```cisco
show ip flow export
show ip cache flow
```

جزئیات بیشتر انگلیسی: [ROUTER_SETUP.md](ROUTER_SETUP.md)

---

## ۱۱. اتصال روتر میکروتیک (MikroTik)

روی RouterOS:

```mikrotik
/ip traffic-flow
set enabled=yes interfaces=all cache-entries=1M active-flow-timeout=1m inactive-flow-timeout=15s

/ip traffic-flow target
add dst-address=SERVER_IP:2055 version=5
```

به‌جای `interfaces=all` می‌توانید فقط اینترفیس WAN/LAN مورد نظر را بگذارید، مثلاً `ether1,bridge`.

بررسی:

```mikrotik
/ip traffic-flow print
/ip traffic-flow target print
/ip traffic-flow status
```

روی سرور:

```bash
curl -s http://127.0.0.1:8000/api/collector/status
sudo tcpdump -ni any udp port 2055 -c 10
```

---

## ۱۲. عیب‌یابی رایج

| مشکل | کار پیشنهادی |
|------|----------------|
| خطای اتصال دیتابیس | سرویس `postgresql`، مقدار `DATABASE_URL`، `pg_hba.conf` |
| پورت ۸۰۰۰ بسته | فایروال، `ss -lntp \| grep 8000` |
| روتر می‌فرستد ولی رکورد نیست | وضعیت کالکتور، `tcpdump`، لاگ `logs/` و `journalctl -u ipdr` |
| نصب scapy / وابستگی‌ها | `build-essential` یا `gcc` و `libpq-dev` را نصب کنید |

---

## ۱۳. امنیت تولید

1. رمز قوی برای PostgreSQL و محدود کردن دسترسی شبکهٔ DB
2. محدود کردن `CORS_ORIGINS`
3. قرار دادن API پشت reverse proxy با TLS (مثلاً Nginx)
4. باز نکردن پورت ۸۰۰۰ و ۲۰۵۵ به اینترنت عمومی بدون نیاز
5. بکاپ منظم از دیتابیس

---

## لینک‌های مرتبط

- معرفی و نصب انگلیسی: [README.md](README.md)
- اتصال روتر (انگلیسی، کامل): [ROUTER_SETUP.md](ROUTER_SETUP.md)
- نمونه‌های پیکربندی روتر: [examples/router_config_examples.md](examples/router_config_examples.md)
