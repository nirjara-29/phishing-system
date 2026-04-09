(function () {
  'use strict';

  if (window !== window.top) {
    return;
  }

  const SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.buzz'];
  const BRAND_KEYWORDS = [
    'paypal', 'apple', 'microsoft', 'google', 'amazon', 'netflix',
    'facebook', 'chase', 'wellsfargo', 'bankofamerica', 'coinbase',
  ];
  const SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'secure', 'account', 'update',
    'confirm', 'suspend', 'password', 'credential',
  ];

  let warningOverlay = null;
  const scannedLinks = new WeakSet();

  function scanPageLinks() {
    const links = document.querySelectorAll('a[href]');
    let suspiciousCount = 0;

    links.forEach((link) => {
      if (scannedLinks.has(link)) {
        return;
      }

      scannedLinks.add(link);

      const href = link.href;
      if (!href || href.startsWith('javascript:') || href.startsWith('#')) {
        return;
      }

      const score = computeLinkSuspicion(href, link.textContent || '');
      if (score >= 3) {
        markSuspicious(link, score);
        suspiciousCount += 1;
      }
    });

    if (suspiciousCount > 0) {
      console.log(`[PhishNet] Found ${suspiciousCount} suspicious links on this page.`);
    }
  }

  function computeLinkSuspicion(href, visibleText) {
    let score = 0;

    try {
      const url = new URL(href);
      const hostname = url.hostname.toLowerCase();
      const fullPath = `${url.pathname}${url.search}`.toLowerCase();

      if (SUSPICIOUS_TLDS.some((tld) => hostname.endsWith(tld))) {
        score += 2;
      }

      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
        score += 3;
      }

      for (const brand of BRAND_KEYWORDS) {
        if (hostname.includes(brand) && !hostname.endsWith(`${brand}.com`)) {
          score += 2;
          break;
        }
      }

      if (SUSPICIOUS_KEYWORDS.some((keyword) => fullPath.includes(keyword))) {
        score += 1;
      }

      const textLower = visibleText.trim().toLowerCase();
      if (textLower && (textLower.startsWith('http') || textLower.includes('.com'))) {
        try {
          const visibleUrl = new URL(textLower.startsWith('http') ? textLower : `https://${textLower}`);
          if (visibleUrl.hostname !== hostname) {
            score += 3;
          }
        } catch {
          // Ignore visible text that is not actually a URL.
        }
      }

      if (hostname.length > 40) {
        score += 1;
      }

      if (hostname.split('.').length - 2 >= 3) {
        score += 1;
      }
    } catch {
      // Ignore invalid URLs.
    }

    return score;
  }

  function markSuspicious(link, score) {
    link.classList.add('phishnet-suspicious');
    link.dataset.phishnetScore = String(score);

    if (!link.querySelector('.phishnet-warn-icon')) {
      const icon = document.createElement('span');
      icon.className = 'phishnet-warn-icon';
      icon.textContent = '\u26A0';
      icon.title = `PhishNet: Suspicious link (score: ${score})`;
      link.prepend(icon);
    }

    link.addEventListener('mouseenter', showWarningTooltip);
    link.addEventListener('mouseleave', hideWarningTooltip);
  }

  function showWarningTooltip(event) {
    const link = event.currentTarget;
    const score = link.dataset.phishnetScore || '?';

    if (!warningOverlay) {
      warningOverlay = document.createElement('div');
      warningOverlay.className = 'phishnet-tooltip';
      document.body.appendChild(warningOverlay);
    }

    warningOverlay.innerHTML = `
      <strong>PhishNet Warning</strong><br>
      This link appears suspicious (score: ${score}).<br>
      <small>${link.href.slice(0, 80)}${link.href.length > 80 ? '...' : ''}</small>
    `;

    const rect = link.getBoundingClientRect();
    warningOverlay.style.top = `${window.scrollY + rect.bottom + 8}px`;
    warningOverlay.style.left = `${window.scrollX + rect.left}px`;
    warningOverlay.style.display = 'block';
  }

  function hideWarningTooltip() {
    if (warningOverlay) {
      warningOverlay.style.display = 'none';
    }
  }

  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === 'PAGE_VERDICT' && message.data?.verdict === 'phishing') {
      showPageWarningBanner(message.data);
    }
  });

  function showPageWarningBanner(data) {
    if (document.getElementById('phishnet-page-warning')) {
      return;
    }

    const banner = document.createElement('div');
    banner.id = 'phishnet-page-warning';
    banner.className = 'phishnet-warning-banner';
    const confidence = Math.round((data.confidence || 0) * 100);

    banner.innerHTML = `
      <div class="phishnet-banner-content">
        <span class="phishnet-banner-icon">\u26A0</span>
        <div>
          <strong>PhishNet Warning:</strong> This page has been identified as a phishing site
          (confidence: ${confidence}%).
          <br><small>Proceed with extreme caution. Do not enter any personal information.</small>
        </div>
        <button id="phishnet-dismiss-banner" class="phishnet-banner-dismiss">\u2715</button>
      </div>
    `;

    document.body.prepend(banner);
    document.getElementById('phishnet-dismiss-banner')?.addEventListener('click', () => {
      banner.remove();
    });
  }

  function start() {
    scanPageLinks();

    if (!document.body) {
      return;
    }

    const observer = new MutationObserver((mutations) => {
      let hasNewLinks = false;

      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node.nodeType === Node.ELEMENT_NODE && (node.tagName === 'A' || node.querySelector?.('a'))) {
            hasNewLinks = true;
            break;
          }
        }

        if (hasNewLinks) {
          break;
        }
      }

      if (hasNewLinks) {
        scanPageLinks();
      }
    });

    observer.observe(document.body, { childList: true, subtree: true });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start, { once: true });
  } else {
    start();
  }
})();
