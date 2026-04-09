
const API_BASE = 'http://localhost:8000/api/v1';
const MAX_HISTORY = 15;

// DOM elements
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

// State
let currentTabUrl = '';

// -------------------------------------------------------------------------
// Initialisation
// -------------------------------------------------------------------------

document.addEventListener('DOMContentLoaded', async () => {
  // Load saved API key
  const stored = await chrome.storage.local.get(['phishnet_api_key']);
  if (stored.phishnet_api_key) {
    apiKeyInput.value = stored.phishnet_api_key;
  }

  // Get current tab URL
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab && tab.url) {
    currentTabUrl = tab.url;
    currentUrlEl.textContent = truncate(currentTabUrl, 60);
    currentUrlEl.title = currentTabUrl;
  } else {
    currentUrlEl.textContent = 'Unable to read tab URL';
    checkBtn.disabled = true;
  }

  loadHistory();
});

// -------------------------------------------------------------------------
// Event handlers
// -------------------------------------------------------------------------

checkBtn.addEventListener('click', () => checkUrl(currentTabUrl));

saveSettingsBtn.addEventListener('click', async () => {
  const key = apiKeyInput.value.trim();
  await chrome.storage.local.set({ phishnet_api_key: key });
  saveSettingsBtn.textContent = 'Saved!';
  setTimeout(() => { saveSettingsBtn.textContent = 'Save'; }, 1500);
});

// -------------------------------------------------------------------------
// API call
// -------------------------------------------------------------------------

async function checkUrl(url) {
  if (!url || url.startsWith('chrome://') || url.startsWith('chrome-extension://')) {
    showError('Cannot scan browser internal pages.');
    return;
  }

  showLoading();

  try {
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
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.message || `HTTP ${response.status}`);
    }

    const data = await response.json();
    showResult(data);
    saveToHistory(url, data);
  } catch (err) {
    showError(err.message || 'Failed to connect to PhishNet API');
  }
}

// -------------------------------------------------------------------------
// UI helpers
// -------------------------------------------------------------------------

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
  const confidence = data.confidence != null ? Math.round(data.confidence * 100) : '--';
  const risk = data.risk_level || 'unknown';

  resultVerdict.textContent = verdict === 'safe'
    ? 'This page appears safe'
    : verdict === 'phishing'
    ? 'WARNING: Likely phishing!'
    : 'Suspicious — proceed with caution';

  resultVerdict.className = 'result-verdict verdict-' + verdict;
  resultConfidence.textContent = confidence + '%';
  resultRisk.textContent = risk;
  resultLabel.textContent = verdict;

  // Notify background script
  chrome.runtime.sendMessage({ type: 'SCAN_RESULT', url: currentTabUrl, data });
}

function showError(msg) {
  loadingSection.classList.add('hidden');
  resultSection.classList.add('hidden');
  errorSection.classList.remove('hidden');
  errorMessage.textContent = msg;
  checkBtn.disabled = false;
}

// -------------------------------------------------------------------------
// History management
// -------------------------------------------------------------------------

async function saveToHistory(url, result) {
  const stored = await chrome.storage.local.get(['phishnet_history']);
  const history = stored.phishnet_history || [];

  history.unshift({
    url: truncate(url, 50),
    verdict: result.verdict || 'unknown',
    confidence: result.confidence,
    timestamp: Date.now(),
  });

  // Cap history size
  if (history.length > MAX_HISTORY) history.length = MAX_HISTORY;

  await chrome.storage.local.set({ phishnet_history: history });
  renderHistory(history);
}

async function loadHistory() {
  const stored = await chrome.storage.local.get(['phishnet_history']);
  const history = stored.phishnet_history || [];
  renderHistory(history);
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
        <span class="history-dot dot-${entry.verdict}"></span>
        <span class="history-url" title="${entry.url}">${entry.url}</span>
        <span class="history-verdict">${entry.verdict}</span>
      </li>
    `
    )
    .join('');
}

// -------------------------------------------------------------------------
// Utility
// -------------------------------------------------------------------------

function truncate(str, len) {
  if (!str) return '';
  return str.length > len ? str.slice(0, len) + '...' : str;
}