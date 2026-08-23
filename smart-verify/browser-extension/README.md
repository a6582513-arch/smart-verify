# إضافة متصفح Smart Verify

إضافة Chrome/Edge (Manifest V3) تتيح فحص أي رابط أو صفحة تتصفحها مباشرة عبر واجهة برمجة تطبيقات Smart Verify المنشورة على Vercel.

## خطوات التفعيل

1. افتح `config.js` وضع رابط موقعك الفعلي بدل `REPLACE-WITH-YOUR-VERCEL-DOMAIN`:
   ```js
   const SMART_VERIFY_API_BASE = "https://your-real-domain.vercel.app";
   ```

2. في Chrome/Edge: اذهب إلى `chrome://extensions` وفعّل **وضع المطوّر (Developer mode)**.

3. اضغط **تحميل غير مُعبأ (Load unpacked)** واختر مجلد `browser-extension` هذا بالكامل.

4. ستظهر أيقونة الدرع بجانب شريط العنوان:
   - اضغط عليها لفحص الصفحة الحالية فوراً.
   - أو انقر بزر الفأرس الأيمن على أي رابط واختر **"فحص هذا الرابط عبر Smart Verify"**.

## ملاحظة مهمة عن CORS

الباك-إند (`app.py`) مضبوط حالياً بـ `allow_origins=["*"]`، لذا يمكن للإضافة الاتصال بـ API مباشرة دون مشاكل CORS. إن قررت لاحقاً تقييد `allow_origins` لأسباب أمنية، تذكّر إضافة استثناء لمعرّف الإضافة (`chrome-extension://<extension-id>`).
