(function () {
  'use strict';

  // Avoid running in iframes
  if (window !== window.top) return;

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
  let scannedLinks = new WeakSet();

  // -----------------------------------------------------------------------
  // Link scanning
  // -----------------------------------------------------------------------

  function scanPageLinks() {
    const links = document.querySelectorAll('a[href]');
    let suspiciousCount = 0;

    links.forEach((link) => {
      if (scannedLinks.has(link)) return;
      scannedLinks.add(link);

      const href = link.href;
      if (!href || href.startsWith('javascript:') || href.startsWith('#')) return;

      const score = computeLinkSuspicion(href, link.textContent);
      if (score >= 3) {
        markSuspicious(link, score);
        suspiciousCount++;
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
      const fullPath = (url.pathname + url.search).toLowerCase();

      // Check suspicious TLDs
      for (const tld of SUSPICIOUS_TLDS) {
        if (hostname.endsWith(tld)) { score += 2; break; }
      }

      // Check for IP address in hostname
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
        score += 3;
      }

      // Check for brand keyword in domain that is not the real brand domain
      for (const brand of BRAND_KEYWORDS) {
        if (hostname.includes(brand) && !hostname.endsWith(`${brand}.com`)) {
          score += 2;
          break;
        }
      }

      // Check for suspicious path keywords
      for (const kw of SUSPICIOUS_KEYWORDS) {
        if (fullPath.includes(kw)) { score += 1; break; }
      }

      // Check for mismatch between visible text and actual URL
      if (visibleText) {
        const textLower = visibleText.trim().toLowerCase();
        // Visible text looks like a URL but points elsewhere
        if (textLower.startsWith('http') || textLower.includes('.com')) {
          try {
            const visibleUrl = new URL(
              textLower.startsWith('http') ? textLower : `https://${textLower}`
            );
            if (visibleUrl.hostname !== hostname) {
              score += 3; // URL mismatch is very suspicious
            }
          } catch {
            // not a valid URL in text — ignore
          }
        }
      }

      // Very long hostname
      if (hostname.length > 40) score += 1;

      // Too many subdomains
      const subdomains = hostname.split('.').length - 2;
      if (subdomains >= 3) score += 1;

    } catch {
      // Invalid URL — skip
    }

    return score;
  }

  // -----------------------------------------------------------------------
  // Visual marking
  // -----------------------------------------------------------------------

  function markSuspicious(link, score) {
    link.classList.add('phishnet-suspicious');
    link.dataset.phishnetScore = score;

    // Add warning icon before the link text
    if (!link.querySelector('.phishnet-warn-icon')) {
      const icon = document.createElement('span');
      icon.className = 'phishnet-warn-icon';
      icon.textContent = '\u26A0';
      icon.title = `PhishNet: Suspicious link (score: ${score})`;
      link.prepend(icon);
    }

    // Add hover tooltip
    link.addEventListener('mouseenter', showWarningTooltip);
    link.addEventListener('mouseleave', hideWarningTooltip);
  }

  function showWarningTooltip(e) {
    const link = e.currentTarget;
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

  // -----------------------------------------------------------------------
  // Message handling from background script
  // -----------------------------------------------------------------------

  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === 'PAGE_VERDICT' && message.data) {
      const verdict = message.data.verdict;
      if (verdict === 'phishing') {
        showPageWarningBanner(message.data);
      }
    }
  });

  function showPageWarningBanner(data) {
    // Avoid duplicate banners
    if (document.getElementById('phishnet-page-warning')) return;

    const banner = document.createElement('div');
    banner.id = 'phishnet-page-warning';
    banner.className = 'phishnet-warning-banner';
    banner.innerHTML = `
      <div class="phishnet-banner-content">
        <span class="phishnet-banner-icon">\u26A0</span>
        <div>
          <strong>PhishNet Warning:</strong> This page has been identified as a phishing site
          (confidence: ${Math.round((data.confidence || 0) * 100)}%).
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

  // -----------------------------------------------------------------------
  // Run on page load and observe DOM changes
  // -----------------------------------------------------------------------

  scanPageLinks();

  // Re-scan when new links are added dynamically (SPA navigations, AJAX)
  const observer = new MutationObserver((mutations) => {
    let hasNewLinks = false;
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType === 1 && (node.tagName === 'A' || node.querySelector?.('a'))) {
          hasNewLinks = true;
          break;
        }
      }
      if (hasNewLinks) break;
    }
    if (hasNewLinks) scanPageLinks();
  });

  observer.observe(document.body, { childList: true, subtree: true });
})();