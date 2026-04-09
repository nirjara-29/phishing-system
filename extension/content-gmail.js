(function () {
  'use strict';

  if (window !== window.top) {
    return;
  }

  const BANNER_ID = 'phishnet-warning';
  const SCAN_DEBOUNCE_MS = 500;

  let lastSeenUrl = window.location.href;
  let lastScannedUrl = '';
  let lastScannedContent = '';
  let pendingTimer = null;
  let observerStarted = false;
  let activeScanToken = 0;

  function removeBanner() {
    const existing = document.getElementById(BANNER_ID);
    if (existing) {
      existing.remove();
    }
  }

  function getOpenEmailContent() {
    const bodyNodes = Array.from(document.querySelectorAll('.a3s, .a3s.aiL, .ii.gt'));
    if (bodyNodes.length === 0) {
      return null;
    }

    const subjectNode = document.querySelector('h2');
    const subject = subjectNode?.textContent?.trim() || '';
    const bodyParts = bodyNodes
      .map((node) => node.innerText?.trim() || '')
      .filter(Boolean)
      .join('\n\n');
    const links = Array.from(document.querySelectorAll('.a3s a[href]'))
      .map((link) => link.href?.trim())
      .filter(Boolean)
      .slice(0, 10);
    const visibleText = [subject, bodyParts].filter(Boolean).join('\n');
    const emailText = [visibleText, ...links].filter(Boolean).join('\n');

    if (emailText.length < 50) {
      return null;
    }

    console.log('EMAIL TEXT:', emailText);

    return {
      subject,
      body: [bodyParts, ...links].filter(Boolean).join('\n'),
      links,
    };
  }

  function buildContentSignature(email) {
    return `${email.subject}\n${email.body}\n${email.links.join('\n')}`.trim();
  }

  function getBannerConfig(verdict) {
    if (verdict === 'phishing') {
      return {
        text: '\u26A0\uFE0F Phishing Email Detected',
        background: '#dc2626',
      };
    }

    if (verdict === 'suspicious') {
      return {
        text: '\u26A0\uFE0F Suspicious Email',
        background: '#f59e0b',
      };
    }

    return {
      text: '\u2705 Email is Safe',
      background: '#16a34a',
    };
  }

  function showBanner(result) {
    removeBanner();

    const { text, background } = getBannerConfig(result?.verdict);
    const banner = document.createElement('div');
    banner.id = BANNER_ID;
    banner.textContent = text;
    banner.style.position = 'fixed';
    banner.style.top = '16px';
    banner.style.left = '50%';
    banner.style.transform = 'translateX(-50%)';
    banner.style.zIndex = '2147483647';
    banner.style.padding = '12px 18px';
    banner.style.borderRadius = '10px';
    banner.style.background = background;
    banner.style.color = '#ffffff';
    banner.style.fontSize = '14px';
    banner.style.fontWeight = '600';
    banner.style.boxShadow = '0 10px 25px rgba(0, 0, 0, 0.2)';
    banner.style.maxWidth = 'min(90vw, 640px)';
    banner.style.textAlign = 'center';
    banner.style.pointerEvents = 'none';

    document.body.appendChild(banner);
  }

  function handleEmailResult(result, scanToken) {
    if (scanToken !== activeScanToken) {
      return;
    }

    showBanner(result || {});
  }

  function maybeScanEmail() {
    const currentUrl = window.location.href;
    const urlChanged = currentUrl !== lastSeenUrl;
    if (urlChanged) {
      lastSeenUrl = currentUrl;
    }

    const email = getOpenEmailContent();
    if (!email) {
      lastScannedUrl = '';
      lastScannedContent = '';
      removeBanner();
      return;
    }

    const contentSignature = buildContentSignature(email);
    const contentChanged = contentSignature !== lastScannedContent;

    if (!urlChanged && currentUrl === lastScannedUrl && !contentChanged) {
      return;
    }

    lastScannedUrl = currentUrl;
    lastScannedContent = contentSignature;
    removeBanner();
    activeScanToken += 1;
    const scanToken = activeScanToken;

    try {
      chrome.runtime.sendMessage({
        type: 'SCAN_EMAIL',
        email,
      }, (response) => {
        if (chrome.runtime.lastError) {
          return;
        }

        if (response?.success && response.data) {
          handleEmailResult(response.data, scanToken);
        }
      });
    } catch {
      // Ignore runtime failures so Gmail stays usable.
    }
  }

  function scheduleScan() {
    if (pendingTimer) {
      clearTimeout(pendingTimer);
    }

    pendingTimer = window.setTimeout(() => {
      pendingTimer = null;
      maybeScanEmail();
    }, SCAN_DEBOUNCE_MS);
  }

  chrome.runtime.onMessage.addListener((message) => {
    if (message?.type === 'EMAIL_RESULT') {
      handleEmailResult(message.data || {}, activeScanToken);
    }
  });

  function startObserver() {
    if (observerStarted || !document.body) {
      return;
    }

    observerStarted = true;
    scheduleScan();

    const observer = new MutationObserver((mutations) => {
      const currentUrl = window.location.href;
      if (currentUrl !== lastSeenUrl) {
        lastSeenUrl = currentUrl;
        scheduleScan();
        return;
      }

      for (const mutation of mutations) {
        if (mutation.type !== 'childList') {
          continue;
        }

        for (const node of mutation.addedNodes) {
          if (node.nodeType !== Node.ELEMENT_NODE) {
            continue;
          }

          if (node.matches?.('.a3s, h2') || node.querySelector?.('.a3s, h2')) {
            scheduleScan();
            return;
          }
        }

        for (const node of mutation.removedNodes) {
          if (node.nodeType !== Node.ELEMENT_NODE) {
            continue;
          }

          if (node.matches?.('.a3s, h2') || node.querySelector?.('.a3s, h2')) {
            scheduleScan();
            return;
          }
        }
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true,
    });

    window.addEventListener('popstate', scheduleScan);
    window.addEventListener('hashchange', scheduleScan);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', startObserver, { once: true });
  } else {
    startObserver();
  }
})();
