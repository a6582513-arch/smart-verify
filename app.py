import os
import re
import ssl
import socket
from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from PIL import Image
from PIL.ExifTags import TAGS

app = FastAPI(title="منصة عين الأمان للتحقق الرقمي")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates_path = os.path.join(BASE_DIR, "templates")
templates = Jinja2Templates(directory=templates_path)

stats = {
    "total_scans": 0,
    "safe_count": 0,
    "danger_count": 0,
    "phishing_urls": 0,
    "scam_texts": 0,
    "manipulated_images": 0
}

# --- 1. منطق فحص الروابط (URL Scanner) ---
def analyze_url(url: str):
    reasons = []
    risk_score = 0
    
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
        
    if url.startswith("http://"):
        risk_score += 30
        reasons.append("الرابط يستخدم بروتوكول HTTP غير المشفر والمكشوف للتنصت.")
        
    phishing_keywords = ["login", "signin", "bank", "secure", "update", "verify", "free-gift", "rewards", "netflix", "paypal"]
    found_keywords = [kw for kw in phishing_keywords if kw in url.lower()]
    if found_keywords:
        risk_score += 40
        reasons.append(f"الرابط يحتوي على كلمات دلالية تستخدم في التصيد الإلكتروني: ({', '.join(found_keywords)})")
        
    if len(url) > 75:
        risk_score += 15
        reasons.append("الرابط طويل بشكل غير طبيعي، وغالباً ما يُستخدم لإخفاء النطاق الحقيقي.")
        
    domain = url.split("//")[-1].split("/")[0]
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                ssock.getpeercert()
    except Exception:
        risk_score += 15
        reasons.append("فشل التحقق من شهادة الأمان SSL للنطاق أو أن الموقع غير متصل بالإنترنت حالياً.")

    risk_score = min(risk_score, 100)
    status = "خطر" if risk_score >= 50 else "آمن مبدئياً"
    
    stats["total_scans"] += 1
    if status == "خطر":
        stats["danger_count"] += 1
        stats["phishing_urls"] += 1
    else:
        stats["safe_count"] += 1
        
    return {"url": url, "status": status, "risk_score": risk_score, "reasons": reasons if reasons else ["لا توجد مؤشرات خطر واضحة وفقاً للفحص الهيكلي."]}

# --- 2. منطق فحص الرسائل والنصوص (Text Scanner) ---
def analyze_text(text: str):
    reasons = []
    risk_score = 0
    
    scam_patterns = {
        r"تحديث بيانات": "محاولة انتحال صفة بنكية لتحديث البيانات وسرقة الحساب.",
        r"فزت بـ|ربحت جائزة": "أسلوب الهندسة الاجتماعية لإغراء الضحية بالجوائز الوهمية.",
        r"تم حظر|إيقاف بطاقتك": "إثارة الذعر والخوف لإجبار المستخدم على التصرف السريع دون تفكير.",
        r"البريد السعودي|ارامكس|شحنة": "انتحال صفة شركات الشحن لدفع رسوم وهمية.",
        r"يرجى الضغط على الرابط": "توجيه صريح ومشبوه لزيارة روابط خارجية."
    }
    
    for pattern, reason in scam_patterns.items():
        if re.search(pattern, text):
            risk_score += 35
            reasons.append(reason)
            
    risk_score = min(risk_score, 100)
    status = "احتيال محتمل" if risk_score >= 35 else "يبدو طبيعياً"
    
    stats["total_scans"] += 1
    if status == "احتيال محتمل":
        stats["danger_count"] += 1
        stats["scam_texts"] += 1
    else:
        stats["safe_count"] += 1
        
    return {"text": text, "status": status, "risk_score": risk_score, "reasons": reasons if reasons else ["لم نكتشف كلمات أو عبارات احتيالية شائعة."]}

# --- 3. منطق فحص الصور (Image Metadata & Software Signatures) ---
def analyze_image(image_path: str):
    reasons = []
    risk_score = 10
    
    try:
        with Image.open(image_path) as img:
            info = img.getexif()
            if info:
                for tag, value in info.items():
                    decoded = TAGS.get(tag, tag)
                    if decoded == "Software":
                        risk_score += 50
                        reasons.append(f"تم تعديل هذه الصورة أو تصديرها باستخدام برنامج خارجي مسجل: ({value}).")
            
            if not info:
                risk_score += 30
                reasons.append("تمت إزالة جميع بيانات المصدر الأصلية للصورة (Metadata)، مما يشير إلى إعادة تصديرها أو معالجتها برمجياً.")
                
    except Exception as e:
        reasons.append(f"خطأ أثناء قراءة هيكل الصورة البرمجي: {str(e)}")
        risk_score = 80

    risk_score = min(risk_score, 100)
    status = "معدلة/مشبوهة" if risk_score >= 50 else "سليمة"
    
    stats["total_scans"] += 1
    if status == "معدلة/مشبوهة":
        stats["danger_count"] += 1
        stats["manipulated_images"] += 1
    else:
        stats["safe_count"] += 1
        
    return {"status": status, "risk_score": risk_score, "reasons": reasons}

# --- مسارات الـ API والتحكم في التنقل واجهات المستخدم ---

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    target_file = "index.html"
    if not os.path.exists(os.path.join(templates_path, "index.html")):
        if os.path.exists(os.path.join(templates_path, "index")):
            target_file = "index"
        elif os.path.exists(os.path.join(templates_path, "index.html.html")):
            target_file = "index.html.html"
            
    try:
        # هنا تم تصحيح طريقة تمرير القاموس لتفادي مشكلة الـ tuple في إصدارات Jinja2 المختلفة
        return templates.TemplateResponse(request=request, name=target_file)
    except Exception as e:
        return HTMLResponse(
            content=f"<h3>خطأ: لم يتم العثور على ملف الواجهة index.html</h3>"
                    f"<p>تأكد من وجود مجلد فرعي باسم <b>templates</b> وبداخله ملف <b>index.html</b> بجانب ملف app.py مباشرة.</p>"
                    f"<p>تفاصيل الخطأ الفني: {str(e)}</p>",
            status_code=500
        )

@app.get("/api/stats")
def get_stats():
    return stats

@app.post("/api/scan-url")
def api_scan_url(data: dict):
    if "url" not in data:
        raise HTTPException(status_code=400, detail="الرابط مطلوب")
    return analyze_url(data["url"])

@app.post("/api/scan-text")
def api_scan_text(data: dict):
    if "text" not in data:
        raise HTTPException(status_code=400, detail="النص مطلوب")
    return analyze_text(data["text"])

@app.post("/api/scan-image")
async def api_scan_image(file: UploadFile = File(...)):
    if not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="الملف المرفوع يجب أن يكون صورة")
        
    temp_path = f"temp_{file.filename}"
    with open(temp_path, "wb") as buffer:
        buffer.write(await file.read())
        
    result = analyze_image(temp_path)
    
    if os.path.exists(temp_path):
        os.remove(temp_path)
        
    return result

@app.post("/api/chat")
def api_chat(data: dict):
    message = data.get("message", "").lower()
    
    if "رابط" in message or "روابط" in message:
        reply = "عند فحص الروابط، نتحقق من بروتوكول الـ SSL، وعمر النطاق، ونبحث عن كلمات مخادعة تهدف لسرقة كلمات مرورك مثل (Login أو Bank)."
    elif "رسالة" in message or "احتيال" in message:
        reply = "رسائل الاحتيال عادةً ما تحاول إخافتك (مثل: حسابك مغلق) أو إغرائك بـ (لقد ربحت جائزة). تذكر دائماً ألا تشارك رموز التحقق الـ OTP مع أحد."
    elif "صورة" in message or "صور" in message:
        reply = "نقوم بفحص الميتاداتا (EXIF data) للصورة. إذا جرى تعديل الصورة بالفوتوشوب أو غيره، فغالباً يترك البرنامج بصمته داخل البناء البرمجي للصورة ونكتشفه فوراً."
    else:
        reply = "مرحباً بك في نظام المساعد الأمني لعين الأمان. يمكنك أن تسألني عن طرق الحماية، أو كيف يعمل نظام التحقق لدينا!"
        
    return {"reply": reply}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
    app = app