<div align="center">
  <img src="assets/logo.svg" width="88" alt="SecPath Radar" />

# SecPath Radar

**رصد غیرفعال امنیت سایبری** · داشبورد استاتیک، فارسی‌محور و read-only

Rust · Static HTML/CSS/JS · No framework · MIT

</div>

---

<div dir="rtl">

## چیست؟

یک «رادار مشاهده‌محور» برای رصد روزانه فضای تهدید: آسیب‌پذیری‌ها، اخبار، IOCها و تله‌متری عمومی تهدید — همه در یک صفحه استاتیک، بدون اسکن فعال و بدون جمع‌آوری داده از بازدیدکننده.

## روال کار

1. **جمع‌آوری** — خبرخوان‌های امنیتی، NVD، CISA KEV، EPSS و منابع عمومی تله‌متری (URLhaus، ThreatFox، DShield و ...)
2. **پردازش** — امتیازدهی ریسک، انباشت روزانه و ترجمه/خلاصه‌سازی فارسی (با فلگ اختیاری `--ai` از Gemini هم استفاده می‌شود)
3. **رندر** — خروجی استاتیک در `site/` (داشبورد، جمع‌بندی هفتگی، RSS و API ساده JSON)
4. **اجرای خودکار** — GitHub Actions هر ۳ ساعت + روزی یک اجرا با AI؛ خروجی در برنچ `radar-output`

## اجرا

</div>

```bash
cargo run -- --full        # full fetch + render into site/
cargo run -- --full --ai   # with Gemini polish (needs GEMINI_API_KEY)
```

<div dir="rtl">

خروجی را مستقیم از `site/index.html` باز کنید؛ به هیچ سروری نیاز نیست.

## اصول

- فقط مشاهده: بدون اسکن فعال، بدون فرم و ورودی، بدون ردیابی بازدیدکننده
- HTML/CSS/JS جدا و بدون فریم‌ورک؛ دوزبانه (فارسی/انگلیسی) و تم روشن/تیره
- کلید Gemini فقط از env/Secrets خوانده می‌شود و هرگز کامیت نمی‌شود

## مشارکت

چیزی کم است یا ایده‌ای دارید؟ یک [Issue](../../issues) باز کنید.

## لایسنس

[MIT](LICENSE) © Mahdi Alemi

</div>
