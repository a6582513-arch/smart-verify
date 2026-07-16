// popup.js - يتصل بواجهة برمجة تطبيقات Smart Verify المنشورة على Vercel

let activeTabUrl = "";

async function init() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    activeTabUrl = tab && tab.url ? tab.url : "";
    const box = document.getElementById('current-url');

    if (!activeTabUrl || !activeTabUrl.startsWith("http")) {
        box.innerText = "لا يمكن فحص هذا النوع من الصفحات (صفحة داخلية للمتصفح).";
        document.getElementById('scan-btn').disabled = true;
    } else {
        box.innerText = activeTabUrl;
    }

    document.getElementById('open-dashboard').href = SMART_VERIFY_API_BASE + "/dashboard";
}

async function scanCurrentPage() {
    const btn = document.getElementById('scan-btn');
    const loader = document.getElementById('loader');
    const resultArea = document.getElementById('result-area');

    if (SMART_VERIFY_API_BASE.includes("REPLACE-WITH")) {
        alert("لم يتم ضبط رابط الخادم بعد. افتح ملف config.js داخل الإضافة وضع رابط موقعك على Vercel.");
        return;
    }

    btn.disabled = true;
    loader.style.display = 'block';
    resultArea.style.display = 'none';

    try {
        const res = await fetch(`${SMART_VERIFY_API_BASE}/api/scan-url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: activeTabUrl })
        });
        const data = await res.json();
        renderResult(data);

        // شارة على أيقونة الإضافة تعكس النتيجة فوراً
        chrome.runtime.sendMessage({
            type: 'SCAN_RESULT',
            danger: data.risk_score >= 50
        });
    } catch (e) {
        document.getElementById('current-url').innerText = "تعذّر الاتصال بخادم Smart Verify. تأكد من الرابط في config.js ومن أن الموقع يعمل.";
    } finally {
        loader.style.display = 'none';
        btn.disabled = false;
    }
}

function renderResult(data) {
    const resultArea = document.getElementById('result-area');
    const statusBadge = document.getElementById('status-badge');
    const scoreValue = document.getElementById('score-value');
    const reasonsList = document.getElementById('reasons');

    resultArea.style.display = 'block';
    statusBadge.innerText = data.status;
    statusBadge.className = 'status-badge ' + (data.risk_score >= 50 ? 'danger' : 'safe');
    scoreValue.innerText = data.risk_score + '%';
    scoreValue.style.color = data.risk_score >= 50 ? '#f43f5e' : '#10b981';

    reasonsList.innerHTML = '';
    (data.reasons || []).forEach(r => {
        const li = document.createElement('li');
        li.innerText = r;
        reasonsList.appendChild(li);
    });
}

document.getElementById('scan-btn').addEventListener('click', scanCurrentPage);
init();
