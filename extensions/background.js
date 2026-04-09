
const API_BASE = 'http://127.0.0.1:8000/api/v1';
const CACHE_TTL_MS = 5 * 60 * 1000;
const CACHE_CLEANUP_MINUTES = 60;

const resultCache = new Map();

chrome.runtime.onInstalled.addListener(() => {
chrome.action.setBadgeText({ text: '' });
chrome.alarms.create('phishnet-cache-cleanup', {
periodInMinutes: CACHE_CLEANUP_MINUTES,
});
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
// 🔒 Safety check
if (!tabId || tabId < 0 || !tab) return;

const url = changeInfo.url || (changeInfo.status === 'complete' ? tab.url : null);

if (!url || !shouldCheck(url)) {
clearBadge(tabId);
return;
}

try {
const result = await checkUrlWithCache(url);
updateBadge(tabId, result);

```
// 🔥 SAFE MESSAGE SENDING (FIXED)
if (result.verdict === 'phishing') {
  try {
    const tabInfo = await chrome.tabs.get(tabId);

    if (!tabInfo || !tabInfo.id) return;

    chrome.tabs.sendMessage(tabId, {
      type: 'PAGE_VERDICT',
      data: result,
    }).catch(() => {});
  } catch (err) {
    console.warn("[PhishNet] Tab no longer exists:", tabId);
  }
}
```

} catch (error) {
console.error('[PhishNet] Failed to check URL:', error);
clearBadge(tabId);
}
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
if (message.type === 'CHECK_URL') {
checkUrlWithCache(message.url)
.then((result) => sendResponse({ success: true, data: result }))
.catch((error) => sendResponse({ success: false, error: error.message }));
return true;
}

if (message.type === 'SCAN_RESULT') {
if (message.url && message.data) {
cacheResult(message.url, normalizeResult(message.url, message.data));
if (sender.tab?.id != null) {
updateBadge(sender.tab.id, message.data);
}
}
return false;
}

if (message.type === 'GET_CACHED') {
sendResponse({ data: getCachedResult(message.url) });
return false;
}

return false;
});

chrome.alarms.onAlarm.addListener((alarm) => {
if (alarm.name !== 'phishnet-cache-cleanup') return;

const now = Date.now();
for (const [url, entry] of resultCache.entries()) {
if (now - entry.timestamp > CACHE_TTL_MS) {
resultCache.delete(url);
}
}
});

async function checkUrlWithCache(url) {
const cached = getCachedResult(url);
if (cached) return cached;

const stored = await chrome.storage.local.get(['phishnet_api_key']);
const apiKey = stored.phishnet_api_key || '';

const headers = { 'Content-Type': 'application/json' };
if (apiKey) headers['X-API-Key'] = apiKey;

const response = await fetch(`${API_BASE}/extension/check`, {
method: 'POST',
headers,
body: JSON.stringify({ url, check_cache: true }),
});

if (!response.ok) {
let message = `API returned ${response.status}`;
try {
const errorData = await response.json();
if (typeof errorData?.detail === 'string') message = errorData.detail;
else if (typeof errorData?.message === 'string') message = errorData.message;
} catch {}

```
throw new Error(message);
```

}

const payload = await response.json();
const result = normalizeResult(url, payload);
cacheResult(url, result);
return result;
}

function normalizeResult(url, payload) {
const verdict = payload?.verdict || 'unknown';
const confidence =
typeof payload?.confidence === 'number'
? payload.confidence
: inferConfidenceFromVerdict(verdict);
const riskLevel = payload?.risk_level || inferRiskLevel(verdict, confidence);

return {
url: payload?.url || url,
verdict,
confidence,
risk_level: riskLevel,
cached: Boolean(payload?.cached),
details: payload?.details || null,
};
}

function cacheResult(url, result) {
resultCache.set(url, { result, timestamp: Date.now() });

if (resultCache.size <= 500) return;

const oldestEntries = [...resultCache.entries()]
.sort((a, b) => a[1].timestamp - b[1].timestamp)
.slice(0, 100);

for (const [key] of oldestEntries) {
resultCache.delete(key);
}
}

function getCachedResult(url) {
const entry = resultCache.get(url);
if (!entry) return null;

if (Date.now() - entry.timestamp > CACHE_TTL_MS) {
resultCache.delete(url);
return null;
}

return entry.result;
}

function updateBadge(tabId, result) {
if (tabId == null || !result?.verdict) return;

if (result.verdict === 'phishing') {
chrome.action.setBadgeText({ text: '!', tabId });
chrome.action.setBadgeBackgroundColor({ color: '#dc2626', tabId });
return;
}

if (result.verdict === 'suspicious') {
chrome.action.setBadgeText({ text: '?', tabId });
chrome.action.setBadgeBackgroundColor({ color: '#f59e0b', tabId });
return;
}

clearBadge(tabId);
}

function clearBadge(tabId) {
chrome.action.setBadgeText({ text: '', tabId });
}

function shouldCheck(url) {
if (!url) return false;

const skipPrefixes = [
'chrome://',
'chrome-extension://',
'edge://',
'about:',
'moz-extension://',
'file://',
'data:',
'blob:',
'devtools://',
'view-source:',
];

return !skipPrefixes.some((prefix) => url.startsWith(prefix));
}

function inferConfidenceFromVerdict(verdict) {
if (verdict === 'phishing') return 0.9;
if (verdict === 'suspicious') return 0.65;
if (verdict === 'safe') return 0.15;
return 0;
}

function inferRiskLevel(verdict, confidence) {
if (verdict === 'phishing') return confidence >= 0.9 ? 'high' : 'medium';
if (verdict === 'suspicious') return 'medium';
if (verdict === 'safe') return 'low';
return 'unknown';
}
