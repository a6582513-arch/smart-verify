// background.js - Service Worker (Manifest V3)
importScripts('config.js');

chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({
        id: "smart-verify-scan-link",
        title: "🛡️ فحص هذا الرابط عبر Smart Verify",
        contexts: ["link"]
    });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
    if (info.menuItemId !== "smart-verify-scan-link" || !info.linkUrl) return;
    if (SMART_VERIFY_API_BASE.includes("REPLACE-WITH")) {
        chrome.notifications?.create?.({
            type: "basic",
            iconUrl: "icons/icon128.png",
            title: "Smart Verify",
            message: "يرجى ضبط رابط الخادم في config.js أولاً."
        });
        return;
    }

    try {
        const res = await fetch(`${SMART_VERIFY_API_BASE}/api/scan-url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: info.linkUrl })
        });
        const data = await res.json();
        const isDanger = data.risk_score >= 50;

        chrome.action.setBadgeText({ text: isDanger ? "⚠" : "✓" });
        chrome.action.setBadgeBackgroundColor({ color: isDanger ? "#f43f5e" : "#10b981" });

        chrome.notifications?.create?.({
            type: "basic",
            iconUrl: "icons/icon128.png",
            title: isDanger ? "⚠️ رابط خطر!" : "✅ رابط يبدو آمناً",
            message: `${data.status} — نسبة التهديد: ${data.risk_score}%`
        });
    } catch (e) {
        chrome.notifications?.create?.({
            type: "basic",
            iconUrl: "icons/icon128.png",
            title: "Smart Verify",
            message: "تعذّر الاتصال بالخادم. تحقق من الاتصال أو من رابط config.js."
        });
    }
});

// تحديث شارة الأيقونة عند وصول نتيجة من نافذة popup.js
chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === 'SCAN_RESULT') {
        chrome.action.setBadgeText({ text: msg.danger ? "⚠" : "✓" });
        chrome.action.setBadgeBackgroundColor({ color: msg.danger ? "#f43f5e" : "#10b981" });
    }
});
