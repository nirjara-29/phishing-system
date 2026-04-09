/**
 * PhishNet Browser Extension popup logic.
 *
 * Shows the active URL, sends it to the backend, renders the verdict, and
 * stores a small local scan history.
 */

const MAX_HISTORY = 15;

const currentUrlEl = document.getElementById('currentUrl');
const checkBtn = document.getElementById('checkBtn');
const resultSection = document.getElementById('resultSection');
const loadingSection = document.getElementById('loadingSection');
const errorSection = document.getElementById('errorSection');
const errorMessage = document.getElementById('errorMessage');
const resultVerdict = document.getElementById('resultVerdict');
const resultConfidence = document.getElementById('resultConfidence');
const resultRisk = document.getElementById('resultRisk');
const resultLabel = document.getElementById('resultLabel');
const historyList = document.getElementById('historyList');
const apiKeyInput = document.getElementById('apiKeyInput');
const saveSettingsBtn = document.getElementById('saveSettings');

let currentTabUrl = '';

document.addEventListener('DOMContentLoaded', async () => {
  const stored = await chrome.storage.local.get(['phishnet_api_key']);
  if (stored.phishnet_api_key) {
    apiKeyInput.value = stored.phishnet_api_key;
  }

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.url) {
    currentTabUrl = tab.url;
    currentUrlEl.textContent = truncate(currentTabUrl, 60);
    currentUrlEl.title = currentTabUrl;
    checkBtn.disabled = isUnsupportedUrl(currentTabUrl);
  } else {
    currentUrlEl.textContent = 'Unable to read tab URL';
    checkBtn.disabled = true;
  }

  loadHistory();
});

checkBtn.addEventListener('click', () => checkUrl(currentTabUrl));

saveSettingsBtn.addEventListener('click', async () => {
  const key = apiKeyInput.value.trim();
  await chrome.storage.local.set({ phishnet_api_key: key });
  saveSettingsBtn.textContent = 'Saved!';
  setTimeout(() => {
    saveSettingsBtn.textContent = 'Save';
  }, 1500);
});

async function checkUrl(url) {
  if (!url || isUnsupportedUrl(url)) {
    showError('Cannot scan this page type. Open a regular website tab.');
    return;
  }

  showLoading();

  try {
    const rawData = await new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({
        type: 'CHECK_URL',
        url,
      }, (response) => {
        console.log('Popup received:', response);

        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }

        if (!response) {
          showError('No response from background');
          reject(new Error('No response from background'));
          return;
        }

        resolve(response);
      });
    });
    const data = normalizeResult(url, rawData);
    showResult(data);
    saveToHistory(url, data);
  } catch (error) {
    showError(error.message || 'Failed to connect to PhishNet API');
  }
}

function showLoading() {
  resultSection.classList.add('hidden');
  errorSection.classList.add('hidden');
  loadingSection.classList.remove('hidden');
  checkBtn.disabled = true;
}

function showResult(data) {
  loadingSection.classList.add('hidden');
  errorSection.classList.add('hidden');
  resultSection.classList.remove('hidden');
  checkBtn.disabled = false;

  const verdict = data.verdict || 'unknown';
  const confidence = data.confidence != null ? Math.round(data.confidence * 100) : null;
  const risk = data.risk_level || 'unknown';

  resultVerdict.textContent = verdict === 'safe'
    ? 'This page appears safe'
    : verdict === 'phishing'
    ? 'Warning: likely phishing'
    : verdict === 'suspicious'
    ? 'Suspicious page: proceed with caution'
    : 'Unable to classify this page';

  resultVerdict.className = `result-verdict verdict-${verdict}`;
  resultConfidence.textContent = confidence == null ? '--' : `${confidence}%`;
  resultRisk.textContent = risk;
  resultLabel.textContent = verdict;

  chrome.runtime.sendMessage({ type: 'SCAN_RESULT', url: currentTabUrl, data });
}

function showError(message) {
  loadingSection.classList.add('hidden');
  resultSection.classList.add('hidden');
  errorSection.classList.remove('hidden');
  errorMessage.textContent = message;
  checkBtn.disabled = false;
}

async function saveToHistory(url, result) {
  const stored = await chrome.storage.local.get(['phishnet_history']);
  const history = stored.phishnet_history || [];

  history.unshift({
    url: truncate(url, 50),
    verdict: result.verdict || 'unknown',
    confidence: result.confidence,
    timestamp: Date.now(),
  });

  if (history.length > MAX_HISTORY) {
    history.length = MAX_HISTORY;
  }

  await chrome.storage.local.set({ phishnet_history: history });
  renderHistory(history);
}

async function loadHistory() {
  const stored = await chrome.storage.local.get(['phishnet_history']);
  renderHistory(stored.phishnet_history || []);
}

function renderHistory(history) {
  if (history.length === 0) {
    historyList.innerHTML = '<li class="history-empty">No recent checks</li>';
    return;
  }

  historyList.innerHTML = history
    .map(
      (entry) => `
      <li class="history-item">
        <span class="history-dot dot-${entry.verdict || 'unknown'}"></span>
        <span class="history-url" title="${entry.url}">${entry.url}</span>
        <span class="history-verdict">${entry.verdict || 'unknown'}</span>
      </li>
    `
    )
    .join('');
}

function normalizeResult(url, payload) {
  const verdict = payload?.verdict || 'unknown';
  const confidence = typeof payload?.confidence === 'number'
    ? payload.confidence
    : inferConfidenceFromVerdict(verdict);
  const riskLevel = payload?.risk_level || inferRiskLevel(verdict, confidence);

  return {
    url: payload?.url || url,
    verdict,
    confidence,
    risk_level: riskLevel,
  };
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

  return null;
}

function inferRiskLevel(verdict, confidence) {
  if (verdict === 'phishing') {
    return confidence >= 0.9 ? 'critical' : 'high';
  }

  if (verdict === 'suspicious') {
    return 'medium';
  }

  if (verdict === 'safe') {
    return 'low';
  }

  return 'unknown';
}

function isUnsupportedUrl(url) {
  return [
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
  ].some((prefix) => url.startsWith(prefix));
}

function truncate(value, length) {
  if (!value) {
    return '';
  }

  return value.length > length ? `${value.slice(0, length)}...` : value;
}
