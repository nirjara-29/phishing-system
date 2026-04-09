const API_BASE = 'http://localhost:8000/api/v1';
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const CHECK_INTERVAL_MINUTES = 60;

// In-memory cache: url -> { result, timestamp }
const resultCache = new Map();

// -------------------------------------------------------------------------
// Navigation interception
// -------------------------------------------------------------------------

chrome.webNavigation.onCompleted.addListener(async (details) => {
  // Only check top-level frame navigations
  if (details.frameId !== 0) return;

  const url = details.url;
  if (!shouldCheck(url)) return;

  try {
    const result = await checkUrlWithCache(url);
    updateBadge(details.tabId, result);

    // Notify content script about the result
    chrome.tabs.sendMessage(details.tabId, {
      type: 'PAGE_VERDICT',
      url,
      data: result,
    }).catch(() => {
      // Content script may not be ready yet — ignore
    });
  } catch (err) {
    console.warn('[PhishNet] Background check failed:', err.message);
  }
});

// -------------------------------------------------------------------------
// Message handling from popup / content scripts
// -------------------------------------------------------------------------

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'CHECK_URL') {
    checkUrlWithCache(message.url)
      .then((result) => sendResponse({ success: true, data: result }))
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true; // async response
  }

  if (message.type === 'SCAN_RESULT') {
    // Popup forwarded a scan result — cache it and update badge
    if (message.url && message.data) {
      cacheResult(message.url, message.data);
      if (sender.tab) {
        updateBadge(sender.tab.id, message.data);
      }
    }
  }

  if (message.type === 'GET_CACHED') {
    const cached = getCachedResult(message.url);
    sendResponse({ data: cached });
    return false;
  }
});

// -------------------------------------------------------------------------
// API interaction
// -------------------------------------------------------------------------

async function checkUrlWithCache(url) {
  // Check cache first
  const cached = getCachedResult(url);
  if (cached) return cached;

  // Call PhishNet API
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
    throw new Error(`API returned ${response.status}`);
  }

  const result = await response.json();
  cacheResult(url, result);
  return result;
}

// -------------------------------------------------------------------------
// Cache management
// -------------------------------------------------------------------------

function cacheResult(url, result) {
  resultCache.set(url, { result, timestamp: Date.now() });

  // Prune old entries to avoid memory bloat
  if (resultCache.size > 500) {
    const oldest = [...resultCache.entries()]
      .sort((a, b) => a[1].timestamp - b[1].timestamp)
      .slice(0, 100);
    for (const [key] of oldest) {
      resultCache.delete(key);
    }
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

// -------------------------------------------------------------------------
// Badge management
// -------------------------------------------------------------------------

function updateBadge(tabId, result) {
  if (!result || !result.verdict) return;

  const verdict = result.verdict;
  let text = '';
  let color = '#6b7280'; // gray

  if (verdict === 'phishing') {
    text = '!';
    color = '#ef4444'; // red
  } else if (verdict === 'suspicious') {
    text = '?';
    color = '#f59e0b'; // amber
  } else if (verdict === 'safe') {
    text = '';
    color = '#22c55e'; // green
  }

  chrome.action.setBadgeText({ text, tabId });
  chrome.action.setBadgeBackgroundColor({ color, tabId });
}

// -------------------------------------------------------------------------
// URL filtering
// -------------------------------------------------------------------------

function shouldCheck(url) {
  if (!url) return false;

  // Skip browser internal pages
  const skipPrefixes = [
    'chrome://', 'chrome-extension://', 'about:', 'edge://',
    'moz-extension://', 'file://', 'data:', 'blob:',
    'devtools://', 'view-source:',
  ];

  for (const prefix of skipPrefixes) {
    if (url.startsWith(prefix)) return false;
  }

  // Skip localhost development servers (but allow localhost:8000 API)
  if (url.includes('localhost') && !url.includes('localhost:8000')) {
    return false;
  }

  return true;
}

// -------------------------------------------------------------------------
// Periodic cache cleanup
// -------------------------------------------------------------------------

chrome.alarms.create('phishnet-cache-cleanup', {
  periodInMinutes: CHECK_INTERVAL_MINUTES,
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'phishnet-cache-cleanup') {
    const now = Date.now();
    for (const [url, entry] of resultCache.entries()) {
      if (now - entry.timestamp > CACHE_TTL_MS) {
        resultCache.delete(url);
      }
    }
    console.log(`[PhishNet] Cache cleanup: ${resultCache.size} entries remaining`);
  }
});