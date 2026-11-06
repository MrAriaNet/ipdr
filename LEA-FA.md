# راهنمای IPDR برای نهاد / امنیت شبکه

> **English:** [LEA.md](LEA.md)

این سیستم برای **عملیات ISP** و **پاسخ به درخواست امنیت / نهاد** در محیط **CGNAT PBA** طراحی شده است؛ جایی که **جدول کانکشن NAT (XLATE) مثل overload وجود ندارد**.

## سؤال معمول نهاد

> چه کسی در زمان `T` از IP عمومی `203.0.113.10` پورت `1500` استفاده کرده و چه ترافیکی داشته؟

جریان کار:

1. **CGNAT PBA** — `public_ip:port + T` ← `inside_ip` (فقط allocate/deallocate بلوک)
2. **AAA** — `inside_ip + T` ← هویت مشترک (اگر سشن AAA وارد شده باشد)
3. **فلوها** — رکوردهای IPDR همان IP داخلی در بازهٔ زمانی
4. **Export** — بسته با manifest و SHA-256؛ امکان legal hold

## احراز هویت

```bash
IPDR_AUTH_REQUIRED=true
IPDR_API_KEYS=admin:...,lea:...,ops:...,collector:...
```

هدر: `X-API-Key: <secret>`

نقش‌ها: `collector` < `ops` < `lea` < `admin`

## APIهای کلیدی

| مسیر | نقش | کاربرد |
|------|-----|--------|
| `GET /api/cgnat/lookup` | lea | عمومی ← داخلی (با هشدار ambiguous) |
| `POST /api/lea/investigate` | lea | بسته کامل CGNAT+AAA+فلو |
| `POST /api/lea/export` | lea | خروجی پرونده + هش |
| `POST /api/lea/aaa/sessions` | ops | ورود سشن AAA |
| `GET /api/lea/audit` | admin | چه کسی چه چیزی پرسیده |
| `POST /api/lea/retention/purge` | admin | پاکسازی با احترام به legal hold |

اگر `ambiguous: true` باشد، پاسخ را قطعی ندانید — `matches[]` را بررسی کنید.

جزئیات PBA: [CGNAT_ASR-FA.md](CGNAT_ASR-FA.md)
