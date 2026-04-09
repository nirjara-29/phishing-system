
const API_BASE = 'http://127.0.0.1:8000/api/v1';
const CACHE_TTL_MS = 5 * 60 * 1000;
const CACHE_CLEANUP_MINUTES = 60;
const SUSPICIOUS_KEYWORDS = ['login', 'verify', 'secure', 'account', 'update', 'bank', 'paypal'];
const SUSPICIOUS_TLDS = ['.xyz', '.tk', '.ml', '.cf', '.gq'];

const resultCache = new Map();

chrome.runtime.onInstalled.addListener(() => {
  chrome.action.setBadgeText({ text: '' });
  chrome.alarms.create('phishnet-cache-cleanup', {
    periodInMinutes: CACHE_CLEANUP_MINUTES,
  });
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (tabId == null || tabId < 0) {
    return;
  }

  const url = changeInfo.url || tab?.url;
  if (!url || !shouldCheck(url)) {
    clearBadge(tabId);
    return;
  }

  console.log('Checking URL:', url);

  try {
    const ruleTriggered = detectSuspiciousUrlPatterns(url);
    if (ruleTriggered) {
      const ruleResult = buildRuleResult(url);
      console.log('[PhishNet] Rule triggered before backend call:', ruleResult);
      cacheResult(url, ruleResult);
      updateBadge(tabId, ruleResult);
      notifyContentScript(tabId, ruleResult);
      console.log('Final verdict source:', ruleResult.source);
      return;
    }

    console.log('[PhishNet] No blocking rule triggered, using backend ML check');
    const result = await checkUrlWithCache(url);
    updateBadge(tabId, result);
    notifyContentScript(tabId, result);
    console.log('Final verdict source:', result.source || 'backend');
  } catch (error) {
    console.error('[PhishNet] Failed to check URL:', error);
    clearBadge(tabId);
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'CHECK_URL') {
    (async () => {
      try {
        const result = await checkUrl(message.url);
        sendResponse(result);
      } catch (error) {
        console.error('Error in CHECK_URL:', error);
        sendResponse({
          url: message.url,
          verdict: 'unknown',
          confidence: 0,
          risk_level: 'unknown',
        });
      }
    })();
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
  if (alarm.name !== 'phishnet-cache-cleanup') {
    return;
  }

  const now = Date.now();
  for (const [url, entry] of resultCache.entries()) {
    if (now - entry.timestamp > CACHE_TTL_MS) {
      resultCache.delete(url);
    }
  }
});

async function checkUrlWithCache(url) {
  const cached = getCachedResult(url);
  if (cached) {
    return applyHybridOverrides(url, cached);
  }

  const stored = await chrome.storage.local.get(['phishnet_api_key']);
  const apiKey = stored.phishnet_api_key || '';
  const headers = { 'Content-Type': 'application/json' };
  if (apiKey) {
    headers['X-API-Key'] = apiKey;
  }

  const response = await fetch(`${API_BASE}/extension/check`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ url, check_cache: true }),
  });

  if (!response.ok) {
    let message = `API returned ${response.status}`;
    try {
      const errorData = await response.json();
      if (typeof errorData?.detail === 'string') {
        message = errorData.detail;
      } else if (typeof errorData?.message === 'string') {
        message = errorData.message;
      }
    } catch {
      // Ignore JSON parse errors for backend failures.
    }

    throw new Error(message);
  }

  const payload = await response.json();
  const normalized = normalizeResult(url, payload);
  const result = applyHybridOverrides(url, normalized);
  console.log('[PhishNet] Backend ML used for URL:', url, result);
  cacheResult(url, result);
  return result;
}

async function checkUrl(url) {
  const ruleTriggered = detectSuspiciousUrlPatterns(url);
  if (ruleTriggered) {
    const ruleResult = buildRuleResult(url);
    console.log('Final verdict source:', ruleResult.source);
    return ruleResult;
  }

  const result = await checkUrlWithCache(url);
  console.log('Final verdict source:', result.source || 'backend');
  return normalizeResult(url, result);
}

function detectSuspiciousUrlPatterns(url) {
  if (!url) return false;

  const suspiciousKeywords = ['login', 'verify', 'secure', 'account', 'update', 'bank', 'paypal'];
  const suspiciousTlds = ['.xyz', '.tk', '.ml', '.cf', '.gq'];

  const lowerUrl = url.toLowerCase();
  const parsed = safeParseUrl(url);
  const hostname = parsed?.hostname?.toLowerCase() || '';
  const hasAtSymbol = url.includes('@');
  const hasKeyword = suspiciousKeywords.some((keyword) => lowerUrl.includes(keyword));
  const hasTld = suspiciousTlds.some((tld) => hostname.endsWith(tld) || lowerUrl.endsWith(tld));
  const isLong = url.length > 75;
  const hasIp = /(\d{1,3}\.){3}\d{1,3}/.test(url);

  return hasAtSymbol || hasKeyword || hasTld || isLong || hasIp;
}

function buildRuleResult(url) {
  return {
    url,
    verdict: 'phishing',
    confidence: 0.9,
    risk_level: 'high',
    source: 'rules',
  };
}

function applyHybridOverrides(url, result) {
  const normalized = normalizeResult(url, result);
  if (normalized.source === 'rules') {
    return normalized;
  }

  if (detectSuspiciousUrlPatterns(url)) {
    return buildRuleResult(url);
  }

  const lowerUrl = url.toLowerCase();
  const hasAtSymbol = lowerUrl.includes('@');
  const hasKeyword = SUSPICIOUS_KEYWORDS.some((keyword) => lowerUrl.includes(keyword));

  if (normalized.verdict === 'safe' && (hasAtSymbol || hasKeyword)) {
    console.log('[PhishNet] Hybrid override changed safe verdict to suspicious:', url);
    return {
      ...normalized,
      verdict: 'suspicious',
      risk_level: 'medium',
      source: normalized.source || 'backend',
    };
  }

  return normalized;
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
    source: payload?.source || 'backend',
    cached: Boolean(payload?.cached),
    details: payload?.details || null,
  };
}

function cacheResult(url, result) {
  resultCache.set(url, { result, timestamp: Date.now() });

  if (resultCache.size <= 500) {
    return;
  }

  const oldestEntries = [...resultCache.entries()]
    .sort((a, b) => a[1].timestamp - b[1].timestamp)
    .slice(0, 100);

  for (const [key] of oldestEntries) {
    resultCache.delete(key);
  }
}

function getCachedResult(url) {
  const entry = resultCache.get(url);
  if (!entry) {
    return null;
  }

  if (Date.now() - entry.timestamp > CACHE_TTL_MS) {
    resultCache.delete(url);
    return null;
  }

  return entry.result;
}

function updateBadge(tabId, result) {
  if (tabId == null || !result?.verdict) {
    return;
  }

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

function notifyContentScript(tabId, result) {
  if (tabId == null || !result || result.verdict !== 'phishing') {
    return;
  }

  chrome.tabs.sendMessage(tabId, {
    type: 'PAGE_VERDICT',
    data: result,
  }).catch(() => {
    // Ignore tabs where the content script is unavailable or the page failed.
  });
}

function clearBadge(tabId) {
  chrome.action.setBadgeText({ text: '', tabId });
}

function shouldCheck(url) {
  if (!url) {
    return false;
  }

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
  if (verdict === 'phishing') {
    return 0.9;
  }
  if (verdict === 'suspicious') {
    return 0.65;
  }
  if (verdict === 'safe') {
    return 0.15;
  }
  return 0;
}

function inferRiskLevel(verdict, confidence) {
  if (verdict === 'phishing') {
    return confidence >= 0.9 ? 'high' : 'medium';
  }
  if (verdict === 'suspicious') {
    return 'medium';
  }
  if (verdict === 'safe') {
    return 'low';
  }
  return 'unknown';
}

function safeParseUrl(url) {
  try {
    return new URL(url);
  } catch {
    return null;
  }
}

function hasIpAddress(hostname) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
}
