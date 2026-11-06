# واسط HSL برای CGNAT PBA — مسیر کامل لاگ (Cisco ASR)

> **English:** [HSL_BRIDGE.md](HSL_BRIDGE.md)

## هدف

با **PBA** روی ASR دیگر NetFlow سشن‌به‌سشن مدل درستی نیست.  
این واسط تضمین می‌کند هر رویداد allocate/deallocate از **NAT HSL** بدون از دست رفتن خاموش به PostgreSQL برسد.

```
ASR 1001-X  →  UDP 2055 (NetFlow v9 HSL)
     →  کالکتور (+ کش قالب + بافر در انتظار قالب)
     →  صف پایدار (حافظه → DB؛ در خطا روی دیسک)
     →  جدول cgnat_port_blocks
```

## دو حالت اجرا

**الف) داخل API** — `POST /api/collector/start` با `netflow` روی ۲۰۵۵  

**ب) فرایند جدا (پیشنهادی در پروداکشن):**

```bash
sudo cp deploy/ipdr-hsl-bridge.service /etc/systemd/system/
sudo systemctl enable --now ipdr-hsl-bridge
# یا: python -m app.bridges.cgnat_hsl_bridge
```

روی ASR فقط **یک** مقصد HSL به همین سرور/پورت بفرستید (هم‌زمان API و bridge روی یک پورت bind نشوند).

```cisco
ip nat log translations flow-export v9 udp destination IPDR_SERVER 2055
```

## قابلیت‌های پایداری

- صف غیرمسدودکننده + اسپیل JSONL هنگام قطع DB  
- replay خودکار / دستی (`POST /api/ingest/replay-spool`)  
- حذف تکراری با `content_hash`  
- ذخیره قالب NetFlow روی دیسک  
- بافر رکورد تا رسیدن template  
- آمار: `GET /api/ingest/status` و `/api/ingest/health`

جزئیات CLI ASR: [CGNAT_ASR-FA.md](CGNAT_ASR-FA.md)
