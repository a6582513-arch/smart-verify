import os
import re
import ssl
import socket
import io
import json
import random
import pathlib
import base64
import hashlib
import datetime
import requests
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from typing import Optional
from pydantic import BaseModel, Field
from PIL import Image
from PIL.ExifTags import TAGS
# استيراد مكتبة التحقق من جوجل
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

app = FastAPI(title="منصة Smart Verify للتحقق الرقمي")

# CORS: allow_credentials=True مع allow_origins=["*"] مزيج غير صالح فعلياً
# (المتصفحات ترفضه) وغير آمن أساساً. الواجهة لا تعتمد على كوكيز/جلسات
# (تسجيل الدخول يتم عبر Google ID Token يُرسل داخل جسم الطلب)، لذا لا حاجة
# لـ allow_credentials. نُبقي allow_origins="*" لأن إضافة المتصفح (extension)
# تستدعي الـ API من نطاق chrome-extension:// مختلف في كل تثبيت.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ضغط GZip لاستجابات الـ API والملفات الثابتة (يقلّص قاعدة كلمات السر
# الشائعة من ~1.3MB إلى ~290KB تقريباً على الشبكة) لتحميل أسرع خصوصاً على الجوال
app.add_middleware(GZipMiddleware, minimum_size=500)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """رؤوس أمان أساسية على كل استجابة (لا تغيّر أي سلوك وظيفي)."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# تحديد المسار بشكل متوافق تماماً مع البيئة السحابية لـ Vercel
BASE_DIR = pathlib.Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
STATIC_DIR = BASE_DIR / "static"
STATIC_DIR.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# معرف العميل الخاص بك الذي حصلت عليه من جوجل كلود
GOOGLE_CLIENT_ID = "873065114114-g9a11ts2a0nj41pulqg8v25dfpo22dec.apps.googleusercontent.com"

# ============================================================
#  مفاتيح مصادر التهديد الحية الخارجية (يجب ضبطها كمتغيرات بيئة
#  في لوحة تحكم Vercel: Settings > Environment Variables)
#  - VIRUSTOTAL_API_KEY: احصل عليه مجاناً من virustotal.com/gui/join-us
#  - GOOGLE_SAFE_BROWSING_API_KEY: من Google Cloud Console (فعّل Safe Browsing API)
# ============================================================
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")

# ============================================================
#  إعداد Google Gemini API (مجاني) لتشغيل مساعد "رقيب" بذكاء اصطناعي حقيقي
#  بدل الردود الجاهزة القديمة (keyword matching).
#
#  خطوات التفعيل:
#  1) أنشئ مفتاح API مجاني من aistudio.google.com (بدون بطاقة ائتمان)
#  2) ضعه كمتغير بيئة باسم GEMINI_API_KEY في إعدادات Vercel
#     (أو في ملف .env محلياً للتجربة فقط)
#  دون ضبط هذا المتغير، يعمل "رقيب" بالردود الاحتياطية القديمة تلقائياً.
# ============================================================
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
gemini_client = None
if GEMINI_API_KEY:
    try:
        from google import genai as google_genai
        gemini_client = google_genai.Client(api_key=GEMINI_API_KEY)
    except ImportError:
        gemini_client = None

# ============================================================
#  إعداد Firebase (Firestore) لتخزين "سجل التحقق" الخاص بكل مستخدم
#  مرتبطاً بحساب Google الذي سجّل به الدخول.
#
#  خطوات التفعيل:
#  1) أنشئ مشروع Firebase مجاني وفعّل خدمة Firestore Database.
#  2) من Project Settings > Service Accounts، ولّد مفتاح خدمة جديد (JSON).
#  3) انسخ محتوى ملف الـ JSON بالكامل وضعه كمتغير بيئة باسم
#     FIREBASE_SERVICE_ACCOUNT_JSON في إعدادات Vercel.
#  دون ضبط هذا المتغير، تعمل المنصة بشكل طبيعي لكن دون حفظ سجل تحقق دائم.
# ============================================================
firebase_db = None
try:
    firebase_creds_raw = os.environ.get("FIREBASE_SERVICE_ACCOUNT_JSON", "")
    if firebase_creds_raw:
        import firebase_admin
        from firebase_admin import credentials, firestore

        cred_dict = json.loads(firebase_creds_raw)
        if not firebase_admin._apps:
            cred = credentials.Certificate(cred_dict)
            firebase_admin.initialize_app(cred)
        firebase_db = firestore.client()
except Exception as _firebase_init_error:
    # في حال فشل الإعداد (مفتاح غير صالح مثلاً)، نستمر بدون سجل تحقق دائم
    firebase_db = None

stats = {
    "total_scans": 0, "safe_count": 0, "danger_count": 0,
    "phishing_urls": 0, "scam_texts": 0, "manipulated_images": 0
}

# ذاكرة مؤقتة لحفظ أكواد التحقق المرسلة عبر الواتساب
# ملاحظة معمارية: هذه الذاكرة داخل العملية (in-process) فقط، وعلى بيئة
# serverless مثل Vercel لا يوجد ضمان بأن نفس النسخة (instance) التي أرسلت
# الكود هي من ستتحقق منه لاحقاً. للاستخدام الفعلي في الإنتاج يُفضّل تخزين
# الأكواد في Firestore (متوفر أصلاً في المشروع) مع صلاحية زمنية (TTL).
temp_whatsapp_codes = {}
ULTRAMSG_INSTANCE_ID = os.environ.get("ULTRAMSG_INSTANCE_ID", "")
ULTRAMSG_TOKEN = os.environ.get("ULTRAMSG_TOKEN", "")


def save_scan_history(user_email: str, user_name: str, scan_type: str, subject: str, status: str, risk_score: int):
    """يحفظ نتيجة الفحص في سجل التحقق الخاص بالمستخدم على Firestore، إن كانت الخدمة مُفعّلة."""
    if not firebase_db or not user_email:
        return False
    try:
        from firebase_admin import firestore
        firebase_db.collection("scan_history").add({
            "user_email": user_email,
            "user_name": user_name or "",
            "scan_type": scan_type,
            "subject": subject[:300] if subject else "",
            "status": status,
            "risk_score": risk_score,
            "created_at": firestore.SERVER_TIMESTAMP
        })
        return True
    except Exception:
        return False


def get_scan_history(user_email: str, limit: int = 50):
    """يجلب آخر عمليات الفحص الخاصة بمستخدم معيّن من Firestore، مرتبة من الأحدث للأقدم."""
    if not firebase_db or not user_email:
        return []
    try:
        from firebase_admin import firestore
        query = (
            firebase_db.collection("scan_history")
            .where("user_email", "==", user_email)
            .order_by("created_at", direction=firestore.Query.DESCENDING)
            .limit(limit)
        )
        records = []
        for doc in query.stream():
            d = doc.to_dict()
            created_at = d.get("created_at")
            records.append({
                "scan_type": d.get("scan_type", ""),
                "subject": d.get("subject", ""),
                "status": d.get("status", ""),
                "risk_score": d.get("risk_score", 0),
                "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at)
            })
        return records
    except Exception:
        return []


# ============================================================
#  القائمة السوداء المجتمعية (Crowdsourced Blacklist)
#  يبلّغ المستخدمون عن نطاقات احتيالية، وبعد وصول عدد التبليغات
#  المستقلة لعتبة معيّنة، يُعامَل النطاق كخطر مؤكَّد في الفحوصات
#  اللاحقة — طبقة استخبارات محلية تنمو بمرور الوقت (تحتاج Firestore).
# ============================================================
COMMUNITY_REPORT_THRESHOLD = 3


def check_community_blacklist(domain: str):
    """يتحقق إن كان النطاق قد بلّغ عنه عدد كافٍ من المستخدمين المستقلين."""
    if not firebase_db or not domain:
        return {"checked": False, "report_count": 0, "flagged": False}
    try:
        doc = firebase_db.collection("community_reports").document(domain).get()
        if not doc.exists:
            return {"checked": True, "report_count": 0, "flagged": False}
        data = doc.to_dict()
        count = data.get("report_count", 0)
        return {"checked": True, "report_count": count, "flagged": count >= COMMUNITY_REPORT_THRESHOLD}
    except Exception:
        return {"checked": False, "report_count": 0, "flagged": False}


def report_domain_to_community(domain: str, reporter_email: str = ""):
    """يسجّل تبليغاً جديداً عن نطاق مشبوه من مستخدم، ويحدّث عدّاد التبليغات المستقلة."""
    if not firebase_db or not domain:
        return {"success": False, "report_count": 0, "flagged": False, "message": "ميزة التبليغ المجتمعي غير مفعّلة حالياً على الخادم (Firebase غير مضبوط)."}
    try:
        from firebase_admin import firestore
        doc_ref = firebase_db.collection("community_reports").document(domain)
        doc = doc_ref.get()

        if doc.exists and reporter_email:
            existing_reporters = doc.to_dict().get("reporter_emails", [])
            if reporter_email in existing_reporters:
                return {
                    "success": True, "already_reported": True,
                    "report_count": doc.to_dict().get("report_count", 0),
                    "flagged": doc.to_dict().get("report_count", 0) >= COMMUNITY_REPORT_THRESHOLD,
                    "message": "لقد قمت بالإبلاغ عن هذا النطاق مسبقاً."
                }

        update_data = {
            "domain": domain,
            "report_count": firestore.Increment(1),
            "last_reported_at": firestore.SERVER_TIMESTAMP,
        }
        if not doc.exists:
            update_data["first_reported_at"] = firestore.SERVER_TIMESTAMP
        if reporter_email:
            update_data["reporter_emails"] = firestore.ArrayUnion([reporter_email])

        doc_ref.set(update_data, merge=True)

        new_count = (doc.to_dict().get("report_count", 0) if doc.exists else 0) + 1
        return {
            "success": True, "already_reported": False,
            "report_count": new_count,
            "flagged": new_count >= COMMUNITY_REPORT_THRESHOLD,
            "message": "تم استلام بلاغك، شكراً لمساهمتك في حماية بقية المستخدمين."
        }
    except Exception as e:
        return {"success": False, "report_count": 0, "flagged": False, "message": f"تعذّر تسجيل البلاغ: {str(e)}"}




# أشهر خدمات اختصار الروابط - يتم فك تشفيرها تلقائياً قبل التحليل
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "cutt.ly", "rb.gy", "tiny.cc", "shorte.st", "rebrand.ly",
    "clck.ru", "shorturl.at", "s.id", "v.gd", "qr.ae", "tr.im", "cli.re",
    "lnkd.in", "soo.gd", "u.to", "shrtco.de", "1url.com", "tny.im"
}

# قائمة سوداء محلية توضيحية لأشهر أنماط النطاقات الاحتيالية المعروفة
# (تُستخدم كطبقة فحص إضافية سريعة لا تعتمد على استدعاء خارجي)
BLACKLIST_DOMAINS = {
    "paypa1.com", "paypal-secure-login.com", "paypal-account-verify.com",
    "amaz0n-verify.com", "amazon-account-update.com",
    "netflix-billing-update.com", "netflix-account-verify.net",
    "apple-id-verify-account.com", "appleid-support-verify.com",
    "bank-of-america-alert.com", "wellsfargo-alert-secure.com",
    "chase-bank-secure-login.com", "update-account-security.info",
    "signin-ebay-secure.com", "instagram-verify-account.net",
    "facebook-security-check.info", "microsoft-support-alert.com",
    "whatsapp-verify-account.net", "secure-bankofamerica.com",
    "google-account-recovery-alert.com", "verify-your-account-now.com"
}

# قائمة تبييض (Allowlist) للنطاقات الرسمية الحقيقية للجهات المذكورة في
# قائمة الكلمات الدلالية أدناه. بدون هذه القائمة، رابط تسجيل دخول حقيقي
# مثل instagram.com/accounts/login أو paypal.com/signin كان سيُعاقَب
# بنفس شدة رابط تصيّد ينتحل صفته فقط لاحتوائه على كلمة "login" — وهذا
# كان السبب الرئيسي لانخفاض دقة الفحص على الروابط السليمة.
LEGITIMATE_BRAND_DOMAINS = {
    "paypal.com", "netflix.com", "google.com", "accounts.google.com",
    "microsoft.com", "live.com", "apple.com", "icloud.com", "amazon.com",
    "facebook.com", "instagram.com", "whatsapp.com", "chase.com",
    "wellsfargo.com", "bankofamerica.com", "ebay.com", "twitter.com", "x.com",
    "linkedin.com", "github.com", "youtube.com", "stcpay.com.sa"
}


def is_domain_or_subdomain_of(domain: str, root: str) -> bool:
    return domain == root or domain.endswith("." + root)


def expand_url(url: str, max_redirects: int = 5):
    """
    يحاول فك تشفير الرابط المختصر عبر تتبّع سلسلة إعادة التوجيه HTTP بالكامل،
    ويعيد الرابط النهائي الحقيقي بالإضافة لسلسلة إعادة التوجيه التي مر بها.
    """
    redirect_chain = [url]
    try:
        session = requests.Session()
        session.max_redirects = max_redirects
        headers = {"User-Agent": "Mozilla/5.0 (compatible; SmartVerifyBot/1.0)"}

        response = session.head(url, allow_redirects=True, timeout=5, headers=headers)
        # بعض الخوادم لا تدعم HEAD بشكل صحيح، نجرب GET كخطة بديلة
        if response.status_code >= 400:
            response = session.get(url, allow_redirects=True, timeout=5, headers=headers, stream=True)

        for r in response.history:
            if r.url not in redirect_chain:
                redirect_chain.append(r.url)

        final_url = response.url
        if final_url not in redirect_chain:
            redirect_chain.append(final_url)

        return {
            "final_url": final_url,
            "redirect_chain": redirect_chain,
            "was_expanded": final_url != url,
            "error": None
        }
    except Exception as e:
        return {
            "final_url": url,
            "redirect_chain": redirect_chain,
            "was_expanded": False,
            "error": str(e)
        }


def get_domain(url: str) -> str:
    return url.split("//")[-1].split("/")[0].split(":")[0].lower()


# ============================================================
#  التحقق من أن المُدخل يشبه رابطاً فعلياً قبل تحليله
#  بدون هذا الفحص، أي نص عشوائي (مثلاً جملة كلام عادي) كان يُقبل
#  ويُضاف له https:// تلقائياً ثم يُعامَل كأنه نطاق حقيقي — فيعطي نتائج
#  عشوائية غير منطقية بدل رسالة واضحة بأن المُدخل ليس رابطاً أصلاً.
# ============================================================
_DOMAIN_PATTERN = re.compile(
    r'^([a-zA-Z0-9\u0600-\u06FF]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}$'
)


def is_plausible_url(raw_input: str) -> bool:
    candidate = (raw_input or "").strip()
    if not candidate or any(ch.isspace() for ch in candidate):
        return False
    stripped = re.sub(r'^https?://', '', candidate, flags=re.IGNORECASE)
    host = stripped.split('/')[0].split('?')[0].split('#')[0].split(':')[0]
    if not host or '.' not in host:
        return False
    return bool(_DOMAIN_PATTERN.match(host))


# ============================================================
#  فحص عمر تسجيل النطاق عبر WHOIS
#  أكثر من 90% من مواقع التصيّد تُنشأ قبل استخدامها في الهجوم بأيام
#  قليلة فقط، لذا نطاق حديث التسجيل جداً مؤشر خطر قوي ومستقل عن أي
#  مصدر خارجي آخر. الفحص محدود بمهلة زمنية قصيرة كي لا يُبطئ الاستجابة
#  أو يعلّق الدالة على بيئة serverless إن تأخر خادم WHOIS بالرد.
# ============================================================
DOMAIN_AGE_SUSPICIOUS_DAYS = 30


def check_domain_age(domain: str):
    try:
        import whois
    except ImportError:
        return {"checked": False, "age_days": None, "error": "مكتبة python-whois غير مثبتة على الخادم"}

    def _lookup():
        return whois.whois(domain)

    try:
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_lookup)
            w = future.result(timeout=6)

        creation_date = getattr(w, "creation_date", None)
        if isinstance(creation_date, list):
            creation_date = creation_date[0] if creation_date else None

        if not creation_date or not hasattr(creation_date, "year"):
            return {"checked": True, "age_days": None, "error": "لا يوجد تاريخ تسجيل موثوق متاح لهذا النطاق"}

        age_days = (datetime.datetime.now() - creation_date.replace(tzinfo=None)).days
        return {"checked": True, "age_days": max(age_days, 0), "error": None}
    except Exception as e:
        return {"checked": False, "age_days": None, "error": str(e)}


# ============================================================
#  التحقق من مصادر التهديد الحية الخارجية (نفس فلسفة VirusTotal:
#  تجميع أحكام عدة مصادر موثوقة بدل الاعتماد على قواعد محلية فقط)
# ============================================================

def check_google_safe_browsing(url: str):
    """
    يتحقق من الرابط عبر قاعدة بيانات Google Safe Browsing الحية،
    وهي نفس القاعدة التي تعتمد عليها متصفحات Chrome و Firefox لحماية المستخدمين.
    """
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        return {"checked": False, "malicious": False, "threats": [], "error": "لم يتم ضبط مفتاح Google Safe Browsing API"}
    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
        payload = {
            "client": {"clientId": "smart-verify", "clientVersion": "2.1"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        resp = requests.post(endpoint, json=payload, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        matches = data.get("matches", [])
        threats = sorted({m.get("threatType", "UNKNOWN") for m in matches})
        return {"checked": True, "malicious": len(matches) > 0, "threats": threats, "error": None}
    except Exception as e:
        return {"checked": False, "malicious": False, "threats": [], "error": str(e)}


def check_virustotal_url(url: str):
    """
    يستعلم من قاعدة بيانات VirusTotal (أكثر من 70 محرك مضاد فيروسات وقوائم حجب)
    عن سجل الرابط، وإن لم يكن موجوداً يرسله للفحص لأول مرة.
    """
    if not VIRUSTOTAL_API_KEY:
        return {"checked": False, "malicious": 0, "suspicious": 0, "total_engines": 0, "pending": False, "error": "لم يتم ضبط مفتاح VirusTotal API"}
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=6)

        if resp.status_code == 404:
            # الرابط غير موجود مسبقاً في قاعدة البيانات، نرسله لأول فحص
            requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url}, timeout=6)
            return {"checked": True, "malicious": 0, "suspicious": 0, "total_engines": 0, "pending": True, "error": None}

        resp.raise_for_status()
        stats_data = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "checked": True,
            "malicious": stats_data.get("malicious", 0),
            "suspicious": stats_data.get("suspicious", 0),
            "total_engines": sum(stats_data.values()),
            "pending": False,
            "error": None
        }
    except Exception as e:
        return {"checked": False, "malicious": 0, "suspicious": 0, "total_engines": 0, "pending": False, "error": str(e)}


def check_virustotal_file_hash(file_bytes: bytes):
    """يحسب بصمة SHA-256 للملف ويبحث عنها في قاعدة بيانات VirusTotal دون الحاجة لرفع الملف فعلياً."""
    file_hash = hashlib.sha256(file_bytes).hexdigest()
    if not VIRUSTOTAL_API_KEY:
        return {"checked": False, "malicious": 0, "total_engines": 0, "known": False, "hash": file_hash, "error": "لم يتم ضبط مفتاح VirusTotal API"}
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        resp = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers, timeout=6)
        if resp.status_code == 404:
            return {"checked": True, "malicious": 0, "total_engines": 0, "known": False, "hash": file_hash, "error": None}
        resp.raise_for_status()
        stats_data = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "checked": True,
            "malicious": stats_data.get("malicious", 0),
            "total_engines": sum(stats_data.values()),
            "known": True,
            "hash": file_hash,
            "error": None
        }
    except Exception as e:
        return {"checked": False, "malicious": 0, "total_engines": 0, "known": False, "hash": file_hash, "error": str(e)}


# ============================================================
#  تحليل الصور بالذكاء الاصطناعي الخفيف (OCR) لرصد النصوص
#  التحذيرية أو انتحال صفة الجهات الرسمية داخل الصور
#  (فواتير، رسائل، لقطات شاشة مزيفة...)
#
#  يعتمد على خدمة OCR.space السحابية الخفيفة (لها باقة مجانية).
#  اضبط متغير البيئة OCR_SPACE_API_KEY في Vercel لتفعيلها.
# ============================================================
OCR_SPACE_API_KEY = os.environ.get("OCR_SPACE_API_KEY", "")

BRAND_IMPERSONATION_KEYWORDS = [
    "بنك", "مصرف", "paypal", "visa", "mastercard", "بطاقة ائتمان", "stc pay",
    "instapay", "vodafone cash", "instagram", "facebook", "whatsapp",
    "apple id", "netflix", "أمازون", "amazon", "بريد السعودي", "ارامكس"
]

IMAGE_SCAM_TEXT_PATTERNS = {
    r"تحديث بيانات|تحديث الحساب": (22, "نص داخل الصورة يطلب تحديث بيانات حساسة، وهو أسلوب شائع في تصيّد الهوية."),
    r"تم حظر|إيقاف الحساب|تعليق الحساب": (22, "نص داخل الصورة يهدد بإيقاف أو حظر الحساب لدفع المستخدم للتصرف بذعر."),
    r"رمز التحقق|كود التحقق|OTP": (6, "نص داخل الصورة يعرض رمز تحقق — قد تكون هذه لقطة شاشة عادية تماماً لرسالة تحقق شرعية (مثل تأكيد دخول أو دفع)، وهذه إشارة ضعيفة جداً بمفردها لا تكفي وحدها للحكم بالخطر."),
    r"فزت بـ|ربحت جائزة|مبروك": (18, "نص داخل الصورة يستخدم أسلوب الجوائز الوهمية لإغراء الضحية."),
    r"اضغط هنا|يرجى الضغط": (8, "نص داخل الصورة يوجّه المستخدم لضغط رابط أو زر خارجي بشكل مباشر.")
}


def extract_text_from_image(image_bytes: bytes):
    """يستخرج أي نص موجود داخل الصورة عبر OCR سحابي خفيف."""
    if not OCR_SPACE_API_KEY:
        return {"checked": False, "text": "", "error": "لم يتم ضبط مفتاح OCR_SPACE_API_KEY"}
    try:
        resp = requests.post(
            "https://api.ocr.space/parse/image",
            files={"file": ("image.jpg", image_bytes)},
            data={"apikey": OCR_SPACE_API_KEY, "language": "ara", "OCREngine": 2, "scale": True},
            timeout=15
        )
        result = resp.json()
        parsed = result.get("ParsedResults") or []
        text = parsed[0].get("ParsedText", "") if parsed else ""
        return {"checked": True, "text": text.strip(), "error": None}
    except Exception as e:
        return {"checked": False, "text": "", "error": str(e)}


def analyze_image_text_content(ocr_text: str):
    """يحلل النص المستخرج من الصورة لرصد لغة احتيالية أو انتحال صفة جهة رسمية معروفة."""
    reasons = []
    risk_add = 0
    if not ocr_text:
        return risk_add, reasons

    text_lower = ocr_text.lower()
    matched_brand = [b for b in BRAND_IMPERSONATION_KEYWORDS if b.lower() in text_lower]

    for pattern, (weight, reason) in IMAGE_SCAM_TEXT_PATTERNS.items():
        if re.search(pattern, ocr_text):
            risk_add += weight
            reasons.append(reason)

    if matched_brand and risk_add > 0:
        risk_add += 15
        brands_str = "، ".join(matched_brand[:3])
        reasons.append(f"⚠️ تم رصد ذكر جهة معروفة ({brands_str}) داخل نص مشبوه بالصورة، وهو نمط شائع لانتحال الهوية البصرية للبنوك والمنصات.")

    return risk_add, reasons


def analyze_url(url: str):
    reasons = []
    risk_score = 0
    original_input = url

    if not is_plausible_url(url):
        stats["total_scans"] += 1
        return {
            "url": url,
            "original_url": original_input,
            "was_expanded": False,
            "redirect_chain": [],
            "status": "غير صالح",
            "risk_score": 0,
            "reasons": ["المُدخل الذي كتبته لا يبدو رابطاً صالحاً (لا يحتوي على نطاق واضح). تأكد من كتابة رابط حقيقي، مثل example.com أو https://example.com."],
            "external_sources": {}
        }

    # ملاحظة مهمة (إصلاح دقة): إذا كتب المستخدم رابطاً بدون بروتوكول
    # (مثلاً "google.com") كنا سابقاً نفترضه HTTP تلقائياً ثم نعاقبه على
    # كونه "غير مشفر" — وهذا خطأ منطقي لأن الغالبية العظمى من المواقع اليوم
    # تعمل بـ HTTPS افتراضياً. الافتراض الصحيح هو HTTPS ما لم يكتب
    # المستخدم http:// صراحةً، أو ينتهي مسار إعادة توجيه فعلي عند HTTP.
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    initial_domain = get_domain(url)
    clean_initial = initial_domain[4:] if initial_domain.startswith("www.") else initial_domain

    expansion_info = {"was_expanded": False, "redirect_chain": [url], "error": None}

    # --- 1) توسيع وفك الروابط المختصرة قبل أي تحليل آخر ---
    if clean_initial in SHORTENER_DOMAINS:
        expansion_info = expand_url(url)
        if expansion_info["was_expanded"]:
            risk_score += 10
            reasons.append(
                f"تم رصد رابط مختصر (Shortened URL)، وبعد فك تشفيره تبيّن أنه يُعيد التوجيه فعلياً إلى نطاق مختلف: {get_domain(expansion_info['final_url'])}"
            )
        if expansion_info["error"]:
            risk_score += 20
            reasons.append("تعذّر فكّ تشفير الرابط المختصر أو تتبع مساره الحقيقي، وهذا بحد ذاته مؤشر يستدعي الحذر.")
        url = expansion_info["final_url"]

    if url.startswith("http://"):
        risk_score += 20
        reasons.append("الرابط يستخدم بروتوكول HTTP غير المشفر والمكشوف للتنصت (وليس HTTPS).")

    domain = get_domain(url)
    clean_domain = domain[4:] if domain.startswith("www.") else domain

    # --- 2) فحص القائمة السوداء المحلية لأشهر النطاقات الاحتيالية ---
    if clean_domain in BLACKLIST_DOMAINS or domain in BLACKLIST_DOMAINS:
        risk_score += 60
        reasons.append(f"⚠️ النطاق ({clean_domain}) مسجّل ضمن القائمة السوداء المحلية لأشهر نطاقات التصيّد الاحتيالي المعروفة.")

    # --- 2ب) فحص القائمة السوداء المجتمعية (تبليغات مستخدمين مستقلين) ---
    community_result = check_community_blacklist(clean_domain)
    if community_result["flagged"]:
        risk_score = max(risk_score, 85)
        reasons.insert(0, f"🚩 بلّغ {community_result['report_count']} مستخدماً مستقلاً عن هذا النطاق كرابط احتيالي عبر منصتنا.")
    elif community_result["report_count"] > 0:
        reasons.append(f"ℹ️ تم الإبلاغ عن هذا النطاق مرة واحدة سابقاً من مستخدم آخر (لم يصل بعد لعتبة التأكيد المجتمعي).")

    # --- 3) أسماء جهات معروفة داخل النطاق (انتحال هوية) + كلمات عامة مشبوهة ---
    # إصلاح دقة إضافي: كلمة عامة واحدة مثل "verify" أو "update" شائعة جداً
    # في أسماء نطاقات مشروعة تماماً لا علاقة لها بالتصيد (مثال: مشروعك
    # نفسه "smart-verify" يحتوي كلمة verify وليس رابطاً احتيالياً). لذلك
    # فصلنا الفحص لمستويين: (أ) اسم جهة معروفة فعلياً (paypal, netflix...)
    # داخل نطاق ليس نطاقها الرسمي = إشارة انتحال قوية جداً. (ب) كلمات
    # عامة غامضة (verify, secure, update...) لا تُحتسب إلا إذا تكررت
    # أكثر من واحدة بنفس النطاق، لأن كلمة واحدة فقط ضعيفة جداً كدليل.
    is_known_legit_brand = any(is_domain_or_subdomain_of(clean_domain, root) for root in LEGITIMATE_BRAND_DOMAINS)

    if not is_known_legit_brand:
        brand_names = ["paypal", "netflix", "apple", "amazon", "google", "facebook",
                       "instagram", "whatsapp", "microsoft", "ebay", "chase",
                       "wellsfargo", "bankofamerica", "visa", "mastercard"]
        generic_words = ["login", "signin", "secure", "update", "verify", "account",
                          "confirm", "free-gift", "rewards"]

        brand_in_domain = [b for b in brand_names if b in clean_domain.lower()]
        generic_in_domain = [g for g in generic_words if g in clean_domain.lower()]

        if brand_in_domain:
            risk_score += 45
            reasons.append(f"النطاق يحتوي على اسم جهة معروفة ({', '.join(brand_in_domain)}) رغم أنه ليس نطاقها الرسمي — نمط شائع جداً في انتحال الهوية (مثال: paypal-secure-login.com بدل paypal.com).")
        elif len(generic_in_domain) >= 2:
            risk_score += 20
            reasons.append(f"النطاق يحتوي على أكثر من كلمة عامة مرتبطة بمحاولات التصيد معاً ({', '.join(generic_in_domain)})، وهذا التجمّع أكثر دلالة من كلمة واحدة بمفردها.")
        elif generic_in_domain:
            risk_score += 5
            reasons.append(f"النطاق يحتوي على كلمة عامة ({generic_in_domain[0]}) قد ترتبط أحياناً بالتصيد، لكنها إشارة ضعيفة جداً بمفردها وشائعة في نطاقات مشروعة كثيرة.")

    if len(url) > 100:
        risk_score += 8
        reasons.append("الرابط طويل بشكل غير معتاد، وهذا مؤشر ضعيف بحد ذاته وقد يكون بسبب معرّفات تتبّع عادية (UTM) لا علاقة لها بالتصيّد.")

    # --- 4) التحقق من شهادة SSL على النطاق النهائي بعد فك التشفير ---
    # نتخطى هذا الفحص للنطاقات الرسمية المعروفة تماماً (شهاداتها مؤكدة
    # أصلاً)، ونخفّف وزن الفشل لأن انقطاعاً شبكياً عابراً أو حجب مؤقت
    # للمنفذ لا يعني بالضرورة أن الموقع خطر.
    if not is_known_legit_brand:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    ssock.getpeercert()
        except Exception:
            risk_score += 10
            reasons.append("فشل التحقق من شهادة الأمان SSL للنطاق، أو أن الموقع غير متصل بالإنترنت حالياً، أو أن الفحص لم يتمكن من الوصول للمنفذ 443 (قد يكون بسبب قيود الشبكة على الخادم نفسه وليس بالضرورة خطأ من الموقع المفحوص).")

    # --- 4ب) فحص عمر تسجيل النطاق عبر WHOIS ---
    domain_age_result = {"checked": False, "age_days": None, "error": None}
    if not is_known_legit_brand:
        domain_age_result = check_domain_age(clean_domain)
        if domain_age_result["checked"] and domain_age_result["age_days"] is not None:
            age_days = domain_age_result["age_days"]
            if age_days <= DOMAIN_AGE_SUSPICIOUS_DAYS:
                risk_score += 35
                reasons.insert(0, f"🕐 النطاق تم تسجيله حديثاً جداً (منذ {age_days} يوماً فقط) — أكثر من 90% من مواقع التصيّد تُنشأ قبل استخدامها بأيام قليلة.")
            elif age_days <= 180:
                risk_score += 10
                reasons.append(f"⏳ النطاق حديث نسبياً (عمره {age_days} يوماً)، وهذا يستدعي حذراً إضافياً رغم عدم كونه دليلاً قاطعاً.")

    # --- 5) مصادر التهديد الحية الخارجية: Google Safe Browsing + VirusTotal ---
    gsb_result = check_google_safe_browsing(url)
    vt_result = check_virustotal_url(url)

    if gsb_result["checked"] and gsb_result["malicious"]:
        risk_score = 100
        threat_labels = ", ".join(gsb_result["threats"])
        reasons.insert(0, f"🚨 تحذير مباشر من Google Safe Browsing (نفس قاعدة بيانات Chrome): هذا الرابط مصنّف كتهديد فعلي ({threat_labels}).")

    if vt_result["checked"] and vt_result.get("total_engines", 0) > 0:
        vt_mal = vt_result["malicious"]
        vt_total = vt_result["total_engines"]
        if vt_mal > 0:
            risk_score = max(risk_score, min(100, 50 + vt_mal * 5))
            reasons.insert(0, f"🚨 رصد {vt_mal} من أصل {vt_total} محرك أمني عبر VirusTotal هذا الرابط كضار أو مشبوه.")
        else:
            reasons.append(f"✅ لم يرصد أي من {vt_total} محرك أمني عبر VirusTotal أي تهديد على هذا الرابط.")
    elif vt_result["checked"] and vt_result.get("pending"):
        reasons.append("ℹ️ الرابط جديد على قاعدة بيانات VirusTotal وتم إرساله للفحص لأول مرة.")

    risk_score = min(risk_score, 100)
    status = "خطر" if risk_score >= 50 else "آمن مبدئياً"
    stats["total_scans"] += 1
    if status == "خطر":
        stats["danger_count"] += 1
        stats["phishing_urls"] += 1
    else:
        stats["safe_count"] += 1

    return {
        "url": url,
        "original_url": original_input,
        "was_expanded": expansion_info["was_expanded"],
        "redirect_chain": expansion_info["redirect_chain"],
        "status": status,
        "risk_score": risk_score,
        "reasons": reasons if reasons else ["لا توجد مؤشرات خطر واضحة."],
        "external_sources": {
            "google_safe_browsing": gsb_result,
            "virustotal": vt_result,
            "community_blacklist": community_result,
            "domain_age": domain_age_result
        }
    }


def analyze_text(text: str):
    reasons = []
    risk_score = 0
    # إصلاح دقة: كانت كل عبارة تضيف +35 ثابتة بغض النظر عن مدى تحديدها،
    # فرسالة عادية جداً قد تصل لعتبة "احتيال" بمطابقة عبارة عامة واحدة فقط.
    # الآن كل نمط له وزن يعكس قوة دلالته الفعلية، والعتبة رُفعت قليلاً
    # حتى تحتاج المطابقة إشارتين متوسطتين أو إشارة قوية واحدة على الأقل.
    scam_patterns = {
        r"تحديث بيانات": (30, "محاولة انتحال صفة بنكية لتحديث البيانات وسرقة الحساب."),
        r"فزت ب|ربحت جائزة": (20, "أسلوب الهندسة الاجتماعية لإغراء الضحية بالجوائز الوهمية."),
        r"أدخل بياناتك|ادخل بياناتك|أدخل معلوماتك": (20, "طلب صريح لإدخال بيانات شخصية أو مالية، نمط شائع لسرقة الهوية."),
        r"تم حظر|إيقاف بطاقتك|تعليق بطاقتك": (30, "إثارة الذعر والخوف لإجبار المستخدم على التصرف السريع."),
        r"البريد السعودي|ارامكس": (25, "انتحال صفة شركة شحن معروفة بالاسم لإضفاء مصداقية زائفة."),
        r"شحنة معل|شحنتك معل": (10, "الإشارة لشحنة معلّقة دون تفاصيل، وقد تكون رسالة تسويقية عادية أو محاولة تصيد."),
        r"جمركية|رسوم إضافية": (20, "طلب دفع رسوم غير متوقعة، أسلوب شائع في احتيال الشحن الوهمي."),
        r"يرجى الضغط على الرابط|اضغط هنا لتفادي": (10, "توجيه لزيارة رابط خارجي، إشارة ضعيفة بمفردها لأنها شائعة أيضاً برسائل شرعية.")
    }
    for pattern, (weight, reason) in scam_patterns.items():
        if re.search(pattern, text):
            risk_score += weight
            reasons.append(reason)
    risk_score = min(risk_score, 100)
    status = "احتيال محتمل" if risk_score >= 40 else "يبدو طبيعياً"
    stats["total_scans"] += 1
    if status == "احتيال محتمل":
        stats["danger_count"] += 1
        stats["scam_texts"] += 1
    else:
        stats["safe_count"] += 1
    return {"text": text, "status": status, "risk_score": risk_score, "reasons": reasons if reasons else ["لم نكتشف عبارات احتيالية شائعة."]}


def analyze_image(image_bytes: bytes):
    reasons = []
    # إصلاح دقة مهم: كانت نقطة البداية 10% + عقوبة تلقائية +30% لغياب EXIF،
    # فأي صورة عادية توصل عبر واتساب أو انستقرام (تُزيل هذه التطبيقات بيانات
    # EXIF تلقائياً كإجراء خصوصية قياسي) كانت تبدأ من 40% دون أي سبب حقيقي.
    # كذلك وجود برنامج تحرير بالـ EXIF لا يعني بالضرورة تلاعباً ضاراً (فلاتر
    # وتصغير الحجم أمور طبيعية جداً)، فخُفّض وزنها وأصبحت مؤشراً وليس حكماً.
    risk_score = 0
    ocr_info = {"checked": False, "text": "", "error": None}

    try:
        with Image.open(io.BytesIO(image_bytes)) as img:
            info = img.getexif()
            if info:
                for tag, value in info.items():
                    decoded = TAGS.get(tag, tag)
                    if decoded == "Software":
                        risk_score += 15
                        reasons.append(f"تم تعديل هذه الصورة باستخدام برنامج خارجي: ({value}) — هذا لا يعني بالضرورة تلاعباً ضاراً (فلاتر أو تصغير حجم أمور شائعة)، لكنه مؤشر إضافي يُحتسب مع باقي عوامل الفحص.")
            if not info:
                risk_score += 8
                reasons.append("تمت إزالة بيانات EXIF من الصورة، وهذا أمر شائع وطبيعي جداً لأي صورة تُرسَل عبر تطبيقات التواصل (واتساب، انستقرام...) كإجراء خصوصية تلقائي من التطبيق نفسه، وليس بالضرورة علامة تلاعب.")
    except Exception as e:
        reasons.append(f"خطأ أثناء قراءة الصورة: {str(e)}")
        risk_score = 55

    # --- تحليل الصورة بالذكاء الاصطناعي الخفيف (OCR): رصد نصوص تحذيرية أو انتحال جهات رسمية ---
    ocr_info = extract_text_from_image(image_bytes)
    if ocr_info["checked"] and ocr_info["text"]:
        text_risk_add, text_reasons = analyze_image_text_content(ocr_info["text"])
        risk_score += text_risk_add
        reasons.extend(text_reasons)

    # --- مطابقة بصمة الملف مع قاعدة بيانات VirusTotal ---
    vt_file_result = check_virustotal_file_hash(image_bytes)
    if vt_file_result["checked"] and vt_file_result.get("known") and vt_file_result["malicious"] > 0:
        risk_score = max(risk_score, min(100, 50 + vt_file_result["malicious"] * 5))
        reasons.insert(0, f"🚨 رصد {vt_file_result['malicious']} من أصل {vt_file_result['total_engines']} محرك أمني عبر VirusTotal أن هذا الملف ضار.")

    risk_score = min(risk_score, 100)
    status = "معدلة/مشبوهة" if risk_score >= 50 else "سليمة"
    stats["total_scans"] += 1
    if status == "معدلة/مشبوهة":
        stats["danger_count"] += 1
        stats["manipulated_images"] += 1
    else:
        stats["safe_count"] += 1

    return {
        "status": status,
        "risk_score": risk_score,
        "reasons": reasons,
        "ocr_text_detected": bool(ocr_info.get("text")),
        "extracted_text_snippet": (ocr_info.get("text", "")[:200] if ocr_info.get("text") else ""),
        "external_sources": {"virustotal_file": vt_file_result}
    }


# ============================================================
#  المستشار الذكي المطور - سيناريوهات الطوارئ الأمنية
# ============================================================

EMERGENCY_SCENARIOS = [
    {
        "id": "hacked_account",
        "keywords": ["تم اختراقي", "اخترقوا حسابي", "تم اختراق حسابي", "هكر حسابي", "سرقوا حسابي", "حسابي مخترق", "اخترق حسابي"],
        "title": "🚨 حالة طوارئ: اختراق حساب",
        "steps": [
            "غيّر كلمة المرور فوراً من جهاز آخر تثق به إن أمكن.",
            "فعّل خاصية التحقق بخطوتين (2FA) إن لم تكن مفعّلة مسبقاً.",
            "راجع سجل الدخول الأخير على الحساب وأنهِ كل الجلسات النشطة غير المعروفة.",
            "تحقق من عدم تغيير البريد الإلكتروني أو رقم الاسترداد المرتبط بالحساب.",
            "بلّغ الجهة المعنية (البنك أو المنصة) فوراً إذا كان الحساب مالياً أو حساساً."
        ]
    },
    {
        "id": "sent_money",
        "keywords": ["حولت فلوس", "حولت مبلغ", "أرسلت فلوس لمحتال", "دفعت لمحتال", "سرقوا فلوسي", "احتالوا علي", "حولت لهم فلوس"],
        "title": "🚨 حالة طوارئ: تحويل مالي لمحتال",
        "steps": [
            "اتصل ببنكك فوراً وأبلغ عن العملية الاحتيالية لمحاولة إيقافها أو استرجاعها.",
            "وثّق كل تفاصيل العملية (الوقت، المبلغ، رقم الحساب المستلم إن توفر).",
            "بلّغ الجهات الرسمية المختصة بالجرائم الإلكترونية في بلدك.",
            "غيّر بيانات الدخول لتطبيق البنك والبريد الإلكتروني المرتبط فوراً.",
            "احذر من محاولات 'استرداد الأموال' الوهمية التي قد يتواصل بها محتالون آخرون بعدها."
        ]
    },
    {
        "id": "clicked_link",
        "keywords": ["ضغطت على رابط", "دخلت رابط مشبوه", "فتحت رابط احتيالي", "ضغطت رابط تصيد", "دخلت على رابط غريب"],
        "title": "⚠️ حالة طوارئ: الضغط على رابط تصيّد",
        "steps": [
            "لا تُدخل أي بيانات إضافية على الصفحة إن كانت لا تزال مفتوحة، وأغلقها فوراً.",
            "إذا أدخلت كلمة مرور أو بيانات بطاقة، غيّرها فوراً من مصدر رسمي موثوق.",
            "افحص جهازك ببرنامج مكافحة فيروسات محدث للتأكد من عدم وجود برمجيات خبيثة.",
            "راقب حساباتك المالية عن كثب خلال الأيام القادمة.",
            "استخدم أداة فحص الروابط في هذه المنصة للتحقق من أي رابط مشابه مستقبلاً."
        ]
    },
    {
        "id": "lost_phone",
        "keywords": ["فقدت هاتفي", "سرق هاتفي", "ضاع جوالي", "سرقوا جوالي", "ضاع تلفوني"],
        "title": "🚨 حالة طوارئ: فقدان أو سرقة الهاتف",
        "steps": [
            "استخدم خدمة تحديد الموقع عن بُعد (Find My Device / Find My iPhone) لتحديد الجهاز أو مسحه.",
            "غيّر كلمات مرور الحسابات المرتبطة بالهاتف فوراً (بريد، بنك، تواصل اجتماعي).",
            "أبلغ مزوّد خدمة الاتصالات لتعطيل خط الشريحة (SIM) لمنع استغلاله.",
            "فعّل قفل الجهاز عن بعد إن كانت الخدمة تدعم ذلك.",
            "أبلغ الجهات الأمنية الرسمية في حال السرقة."
        ]
    },
]


def check_emergency(message: str):
    for scenario in EMERGENCY_SCENARIOS:
        for kw in scenario["keywords"]:
            if kw in message:
                return scenario
    return None


class URLScanRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)
    user_email: Optional[str] = None
    user_name: Optional[str] = None


class TextScanRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=5000)
    user_email: Optional[str] = None
    user_name: Optional[str] = None


class ChatRequest(BaseModel):
    message: str = Field(default="", max_length=1000)


class GoogleAuthRequest(BaseModel):
    credential: str = Field(..., min_length=1)


class WhatsAppSendRequest(BaseModel):
    phone: str = Field(..., min_length=5, max_length=20)


class WhatsAppVerifyRequest(BaseModel):
    phone: str = Field(..., min_length=5, max_length=20)
    code: str = Field(..., min_length=1, max_length=10)


class ReportDomainRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048)
    user_email: Optional[str] = None


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    try:
        return templates.TemplateResponse(request=request, name="index.html")
    except Exception as e:
        return HTMLResponse(content=f"<h3>خطأ في العثور على index.html داخل مجلد templates</h3>", status_code=500)


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    try:
        return templates.TemplateResponse(request=request, name="dashboard.html")
    except Exception as e:
        return HTMLResponse(content=f"<h3>خطأ في العثور على dashboard.html داخل مجلد templates</h3>", status_code=500)


# ============================================================
#  صفحة تحميل تطبيق الجوال (APK)
#  ضع رابط ملف الـ APK الفعلي (مثلاً من GitHub Releases) في متغير
#  البيئة APK_DOWNLOAD_URL على Vercel. بدون ضبطه، تعرض الصفحة رسالة
#  توضّح أن الرابط غير جاهز بعد بدل رابط معطّل بصمت.
# ============================================================
APK_DOWNLOAD_URL = os.environ.get("APK_DOWNLOAD_URL", "")


@app.get("/download", response_class=HTMLResponse)
def download_page(request: Request):
    try:
        return templates.TemplateResponse(request=request, name="download.html", context={"apk_url": APK_DOWNLOAD_URL})
    except Exception as e:
        return HTMLResponse(content=f"<h3>خطأ في العثور على download.html داخل مجلد templates</h3>", status_code=500)


@app.get("/api/download-qr")
def download_qr():
    """يولّد صورة QR تشير لرابط تحميل التطبيق مباشرة، ليتمكن أي شخص من مسحها بجواله."""
    if not APK_DOWNLOAD_URL:
        raise HTTPException(status_code=404, detail="رابط تحميل التطبيق غير مضبوط بعد (APK_DOWNLOAD_URL)")
    try:
        import qrcode
        img = qrcode.make(APK_DOWNLOAD_URL)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        from fastapi.responses import StreamingResponse
        return StreamingResponse(buf, media_type="image/png")
    except ImportError:
        raise HTTPException(status_code=500, detail="مكتبة qrcode غير مثبتة على الخادم")


@app.get("/api/stats")
def get_stats():
    return stats


@app.get("/api/history")
def api_get_history(email: str = ""):
    if not email:
        raise HTTPException(status_code=400, detail="الرجاء تمرير البريد الإلكتروني")
    if not firebase_db:
        return {"enabled": False, "records": [], "message": "سجل التحقق غير مفعّل حالياً على الخادم (لم يتم ضبط Firebase)."}
    records = get_scan_history(email)
    return {"enabled": True, "records": records}


@app.post("/api/scan-url")
def api_scan_url(data: URLScanRequest):
    result = analyze_url(data.url)
    if data.user_email:
        save_scan_history(data.user_email, data.user_name or "", "رابط (URL)", result.get("original_url", data.url), result["status"], result["risk_score"])
    return result


@app.post("/api/report-domain")
def api_report_domain(data: ReportDomainRequest):
    """يسجّل بلاغاً مجتمعياً عن نطاق مشبوه؛ بعد وصول التبليغات المستقلة لعتبة معيّنة يُعامَل كخطر مؤكَّد بالفحوصات القادمة."""
    url = data.url if data.url.startswith(("http://", "https://")) else "http://" + data.url
    domain = get_domain(url)
    clean_domain = domain[4:] if domain.startswith("www.") else domain
    return report_domain_to_community(clean_domain, data.user_email or "")


@app.post("/api/scan-text")
def api_scan_text(data: TextScanRequest):
    result = analyze_text(data.text)
    if data.user_email:
        save_scan_history(data.user_email, data.user_name or "", "رسالة نصية", data.text, result["status"], result["risk_score"])
    return result


@app.post("/api/scan-image")
async def api_scan_image(file: UploadFile = File(...), user_email: str = Form(None), user_name: str = Form(None)):
    if not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="الملف يجب أن يكون صورة")
    file_bytes = await file.read()
    result = analyze_image(file_bytes)
    if user_email:
        save_scan_history(user_email, user_name or "", "صورة", file.filename or "صورة مرفوعة", result["status"], result["risk_score"])
    return result


RAQIB_SYSTEM_PROMPT = """أنت "رقيب 🛡️"، المساعد الأمني المدمج بمنصة Smart Verify للتحقق الرقمي.
مهمتك مساعدة المستخدمين على فهم مخاطر الاحتيال الرقمي (التصيّد، الروابط المشبوهة،
الرسائل الاحتيالية، انتحال الهوية) وشرح كيف تعمل أدوات المنصة (فحص الروابط،
فحص الرسائل، فحص الصور بالـ OCR).
تحدث بالعربية بأسلوب واضح ومباشر وودود، وردودك مختصرة (فقرة أو فقرتين، أو نقاط قصيرة عند الحاجة).
لا تقدّم أي معلومة تقنية تساعد على تنفيذ عملية احتيال أو اختراق فعلية.
إن سأل المستخدم عن شيء خارج نطاق الأمن الرقمي، أجب بإيجاز ثم أعد توجيهه بلطف نحو خدمات المنصة إن كان ذلك مناسباً."""


def raqib_fallback_reply(message: str) -> str:
    """رد احتياطي يعتمد على مطابقة كلمات مفتاحية بسيطة، يُستخدم فقط إذا لم يتوفر
    مفتاح Claude API أو تعذّر الاتصال به، حتى يبقى المساعد يعمل دون انقطاع كامل."""
    message_lower = message.lower()
    if any(w in message for w in ["من انت", "من أنت", "مين انت", "اسمك", "شو اسمك"]):
        return "أنا رقيب 🛡️، المساعد الأمني المدمج بمنصة Smart Verify. مهمتي مساعدتك بفحص الروابط والرسائل والصور، وتزويدك بخطوات فورية إن مررت بحالة طارئة."
    elif any(w in message for w in ["مرحبا", "اهلا", "أهلا", "السلام عليكم"]):
        return "مرحباً بك، أنا رقيب 🛡️. يمكنني مساعدتك في فحص الروابط والرسائل والصور، أو تقديم إرشادات فورية إن كنت تمر بحالة طارئة."
    elif "رابط" in message or "url" in message_lower:
        return "عند فحص الروابط أقوم بفك تشفير الروابط المختصرة، ومطابقتها مع قائمة سوداء محلية للنطاقات الاحتيالية، والتحقق من شهادات SSL والكلمات المخادعة."
    elif "رسالة" in message or "نص" in message:
        return "رسائل الاحتيال تعتمد على الهندسة الاجتماعية لإثارة الذعر أو الطمع، وأقوم بتحليلها لغوياً لرصد الأنماط المعروفة."
    elif "صورة" in message:
        return "أفحص ميتاداتا الصور (EXIF)، وأستخرج أي نص داخلها بالذكاء الاصطناعي (OCR) لرصد انتحال الجهات الرسمية."
    elif "مساعدة" in message or "help" in message_lower:
        return "يمكنني مساعدتك في: فحص الروابط، تحليل الرسائل الاحتيالية، وفحص ميتاداتا الصور. وإن كنت تمر بحالة طارئة، اكتب مثلاً 'تم اختراقي' وسأزودك بخطوات فورية."
    else:
        return "أنا رقيب، مساعدك الأمني. اسألني عن الروابط أو الرسائل أو الصور، أو أخبرني إن كنت تمر بحالة أمنية طارئة."


@app.post("/api/chat")
def api_chat(data: ChatRequest):
    message = data.message.strip()

    # --- الأولوية القصوى: سيناريوهات الطوارئ (منطق ثابت، لا يعتمد على API خارجي) ---
    emergency = check_emergency(message)
    if emergency:
        reply_text = emergency["title"] + "\n" + "\n".join([f"{i+1}. {s}" for i, s in enumerate(emergency["steps"])])
        return {
            "reply": reply_text,
            "type": "emergency",
            "title": emergency["title"],
            "steps": emergency["steps"]
        }

    # --- الرد عبر Gemini API إن كان مفعّلاً، وإلا نستخدم الردود الاحتياطية ---
    if gemini_client and message:
        try:
            from google.genai import types as genai_types
            response = gemini_client.models.generate_content(
                model="gemini-2.5-flash",
                contents=message,
                config=genai_types.GenerateContentConfig(
                    system_instruction=RAQIB_SYSTEM_PROMPT,
                    max_output_tokens=500,
                ),
            )
            reply = (response.text or "").strip()
            if reply:
                return {"reply": reply, "type": "normal"}
        except Exception:
            pass  # نسقط بهدوء إلى الرد الاحتياطي بدل كسر المحادثة

    return {"reply": raqib_fallback_reply(message) if message else "اكتب رسالتك وسأساعدك.", "type": "normal"}


# مسار استقبال وتحليل رمز التوثيق المرسل من جوجل (ID Token)
@app.post("/api/auth/google")
def google_auth(data: GoogleAuthRequest):
    token = data.credential
    try:
        # التحقق من صحة التوكن مباشرة مع خوادم جوجل لمنع التلاعب
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)

        # جلب بيانات المستخدم الموثقة والآمنة
        user_email = idinfo.get('email')
        user_name = idinfo.get('name')
        user_picture = idinfo.get('picture')

        return {
            "success": True,
            "user": {
                "name": user_name,
                "email": user_email,
                "picture": user_picture,
                "authType": "google"
            }
        }
    except ValueError:
        raise HTTPException(status_code=400, detail="رمز التحقق من جوجل غير صالح أو منتهي الصلاحية")


# مسار إرسال كود التحقق OTP إلى واتساب المستخدم
@app.post("/api/auth/whatsapp/send")
def send_whatsapp_otp(data: WhatsAppSendRequest):
    phone = data.phone

    otp_code = str(random.randint(100000, 999999))
    temp_whatsapp_codes[phone] = otp_code

    if not ULTRAMSG_INSTANCE_ID or not ULTRAMSG_TOKEN:
        # لم يتم ضبط بيانات UltraMsg بعد كمتغيرات بيئة -> وضع محاكاة محلي فوري
        return {"success": True, "fallback": True, "code": otp_code, "message": "تم تشغيل وضع المحاكاة المحلي (لم يتم ضبط UltraMsg بعد)."}

    message_text = f"🛡️ [Smart Verify]\n\nكود التحقق الخاص بك هو: *{otp_code}*\n\nيرجى إدخاله لتأكيد تسجيل الدخول."

    url = f"https://api.ultramsg.com/{ULTRAMSG_INSTANCE_ID}/messages/chat"
    payload = {
        "token": ULTRAMSG_TOKEN,
        "to": phone,
        "body": message_text,
        "priority": "10"
    }
    headers = {'content-type': 'application/x-www-form-urlencoded'}

    try:
        response = requests.post(url, data=payload, headers=headers)
        res_json = response.json()
        if res_json.get("sent") == "true" or "success" in res_json:
            return {"success": True, "message": "تم إرسال كود التحقق بنجاح!"}
        else:
            return {"success": True, "fallback": True, "code": otp_code, "message": "تم توليد الكود محلياً لعرضه بالمناقشة."}
    except Exception:
        return {"success": True, "fallback": True, "code": otp_code, "message": "تم تشغيل وضع المحاكاة المحلي بنجاح للمشروع."}


# مسار التحقق من الكود المدخل لواتساب
@app.post("/api/auth/whatsapp/verify")
def verify_whatsapp_otp(data: WhatsAppVerifyRequest):
    phone = data.phone
    code = data.code

    if phone in temp_whatsapp_codes and temp_whatsapp_codes[phone] == code:
        del temp_whatsapp_codes[phone]
        return {"success": True, "message": "تم تسجيل الدخول عبر واتساب بنجاح!"}

    raise HTTPException(status_code=400, detail="كود التحقق غير صحيح")
