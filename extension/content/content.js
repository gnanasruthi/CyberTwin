/**
 * CyberTwin — Content Script (Stage 2)
 * Intercepts link clicks, shows pre-flight loading overlay, requests analysis from backend,
 * and displays Stage 1 & Stage 2 reputation and static analysis heuristics with Proceed / Cancel.
 */

(function () {
  'use strict';

  if (window.__CYBERTWIN_INITIALIZED__) return;
  window.__CYBERTWIN_INITIALIZED__ = true;

  console.log('[CyberTwin] Link Pre-Flight Interceptor loaded (Stage 2 Static Analysis).');

  let isEnabled = true;
  let activeOverlay = null;
  let isNavigatingFromCyberTwin = false;

  try {
    if (chrome.storage && chrome.storage.local) {
      chrome.storage.local.get('enabled', (res) => {
        if (res && res.enabled !== undefined) {
          isEnabled = res.enabled;
        }
      });
      chrome.storage.onChanged.addListener((changes) => {
        if (changes.enabled) {
          isEnabled = changes.enabled.newValue;
        }
      });
    }
  } catch (e) {
    console.warn('[CyberTwin] Storage sync error:', e);
  }

  // Listen for risky-download warnings from background.js
  chrome.runtime.onMessage.addListener((request) => {
    if (request.type === 'DOWNLOAD_RISK') {
      openDownloadRiskModal(request.data);
    }
  });

  function openDownloadRiskModal(data) {
    closeOverlay();

    const host = document.createElement('div');
    host.id = 'cybertwin-root-host';
    host.style.position = 'fixed';
    host.style.inset = '0';
    host.style.zIndex = '2147483647';
    host.style.pointerEvents = 'auto';

    const shadow = host.attachShadow({ mode: 'open' });

    const style = document.createElement('style');
    style.textContent = getOverlayStyles();
    shadow.appendChild(style);

    const container = document.createElement('div');
    container.className = 'ct-backdrop';

    const reasonsHtml = (data.reasons && data.reasons.length)
      ? data.reasons.map(r => escapeHtml(r)).join('<br>')
      : 'Suspicious file characteristics detected.';

    container.innerHTML = `
      <div class="ct-modal ct-animate-in">
        <div class="ct-header">
          <div class="ct-brand">
            <span class="ct-logo-icon">🛡️</span>
            <div>
              <div class="ct-title">CyberTwin Download Alert</div>
              <div class="ct-subtitle">High-Risk File Detected</div>
            </div>
          </div>
          <button class="ct-close-btn" id="ct-dl-close" title="Close overlay">&times;</button>
        </div>

        <div class="ct-body">
          <div class="ct-target-box">
            <span class="ct-target-label">FILE</span>
            <div class="ct-target-url" title="${escapeHtml(data.filename || '')}">${escapeHtml(data.filename || 'Unknown file')}</div>
          </div>

          <div class="ct-score-card ct-risk-high">
            <div class="ct-score-ring">
              <span class="ct-score-num">${data.score}</span>
              <span class="ct-score-max">/100</span>
            </div>
            <div class="ct-score-meta">
              <div class="ct-score-verdict">
                <span class="ct-badge ct-risk-high">${escapeHtml(data.risk || 'HIGH')}</span>
              </div>
              <div class="ct-score-reason"><strong>File type:</strong> ${escapeHtml(data.mime || 'unknown')}</div>
            </div>
          </div>

          <div class="ct-explanation-card">
            <div class="ct-explanation-title">Why this was flagged:</div>
            <p class="ct-explanation-text">${reasonsHtml}</p>
          </div>

          <div class="ct-notice">
            ${data.fileAlreadyLanded
              ? '⚠️ <strong>Note:</strong> This file downloaded too quickly for CyberTwin to pause it in time. Choosing Cancel below will delete it from your computer immediately.'
              : '⚠️ <strong>High Risk Warning:</strong> This file type is commonly used to deliver malware. Only proceed if you trust the source.'}
          </div>
        </div>

        <div class="ct-footer">
          <button class="ct-btn ct-btn-cancel" id="ct-dl-cancel">
            <span class="ct-btn-icon">✖</span> ${data.fileAlreadyLanded ? 'Delete File' : 'Cancel Download'}
          </button>
          <button class="ct-btn ct-btn-proceed-danger" id="ct-dl-allow">
            <span class="ct-btn-icon">➜</span> ${data.fileAlreadyLanded ? 'Keep File' : 'Allow Anyway'}
          </button>
        </div>
      </div>
    `;

    shadow.appendChild(container);
    (document.body || document.documentElement).appendChild(host);
    activeOverlay = host;

    const cancelBtn = shadow.getElementById('ct-dl-cancel');
    const closeBtn = shadow.getElementById('ct-dl-close');
    const allowBtn = shadow.getElementById('ct-dl-allow');

    const handleCancel = () => {
      chrome.runtime.sendMessage({ type: 'CANCEL_RISKY_DOWNLOAD', downloadId: data.id });
      closeOverlay();
    };

    if (cancelBtn) cancelBtn.addEventListener('click', handleCancel);
    if (closeBtn) closeBtn.addEventListener('click', handleCancel);

    if (allowBtn) {
      allowBtn.addEventListener('click', () => {
        chrome.runtime.sendMessage({ type: 'ALLOW_RISKY_DOWNLOAD', downloadId: data.id });
        closeOverlay();
      });
    }
  }

  document.addEventListener('click', handleDocumentClick, true);

  function handleDocumentClick(event) {
    if (!isEnabled) return;
    if (isNavigatingFromCyberTwin) return;

    if (event.button !== 0) return;

    const anchor = event.target.closest('a');
    if (!anchor) return;

    if (anchor.dataset.cybertwinBypass === 'true') {
      delete anchor.dataset.cybertwinBypass;
      return;
    }

    const rawHref = anchor.getAttribute('href');
    if (!rawHref) return;

    if (
      rawHref.startsWith('#') ||
      rawHref.startsWith('javascript:') ||
      rawHref.startsWith('mailto:') ||
      rawHref.startsWith('tel:') ||
      rawHref.trim() === ''
    ) {
      return;
    }

    const targetUrl = anchor.href;
    if (!targetUrl || (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://'))) {
      return;
    }

    event.preventDefault();
    event.stopPropagation();
    event.stopImmediatePropagation();

    const targetWindow = anchor.getAttribute('target') || '_self';

    console.log('[CyberTwin] Intercepted navigation to:', targetUrl);
    openCyberTwinModal(targetUrl, targetWindow, anchor);
  }

  function openCyberTwinModal(targetUrl, targetWindow, originalAnchor) {
    closeOverlay();

    const host = document.createElement('div');
    host.id = 'cybertwin-root-host';
    host.style.position = 'fixed';
    host.style.inset = '0';
    host.style.zIndex = '2147483647';
    host.style.pointerEvents = 'auto';

    const shadow = host.attachShadow({ mode: 'open' });

    const style = document.createElement('style');
    style.textContent = getOverlayStyles();
    shadow.appendChild(style);

    const container = document.createElement('div');
    container.className = 'ct-backdrop';
    container.innerHTML = getLoadingHtml(targetUrl);
    shadow.appendChild(container);

    (document.body || document.documentElement).appendChild(host);
    activeOverlay = host;

    const onKeyDown = (e) => {
      if (e.key === 'Escape') {
        closeOverlay();
        document.removeEventListener('keydown', onKeyDown);
      }
    };
    document.addEventListener('keydown', onKeyDown);

    const startTime = Date.now();

    sendMessageToBackend(targetUrl, (response) => {
      const elapsed = Date.now() - startTime;
      const delay = Math.max(0, 450 - elapsed);

      setTimeout(() => {
        if (!activeOverlay) return;

        if (response && response.success && response.data) {
          renderResult(shadow, container, response.data, targetUrl, targetWindow, originalAnchor);
        } else {
          renderError(shadow, container, response?.error || 'Unable to connect to CyberTwin backend', targetUrl, targetWindow, originalAnchor);
        }
      }, delay);
    });
  }

  function sendMessageToBackend(url, callback) {
    if (chrome.runtime && chrome.runtime.sendMessage) {
      try {
        chrome.runtime.sendMessage({ type: 'ANALYZE_URL', url }, (res) => {
          if (chrome.runtime.lastError) {
            console.warn('[CyberTwin] Runtime message error:', chrome.runtime.lastError);
            fallbackDirectFetch(url, callback);
          } else {
            callback(res);
          }
        });
        return;
      } catch (e) {
        console.warn('[CyberTwin] Message dispatch error:', e);
      }
    }
    fallbackDirectFetch(url, callback);
  }

  function fallbackDirectFetch(url, callback) {
    fetch('http://localhost:3001/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    })
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.json();
      })
      .then((data) => callback({ success: true, data }))
      .catch((err) => callback({ success: false, error: err.message }));
  }

  function renderResult(shadow, container, data, targetUrl, targetWindow, originalAnchor) {
    const riskScore = typeof data.riskScore === 'number' ? data.riskScore : 20;
    const reason = data.reason || 'test';
    const verdict = data.verdict || 'safe';
    const tier = data.tier || 'fast';
    const plainEnglish = data.plainEnglish || 'Pre-flight evaluation complete.';
    const metadata = data.metadata || {};
    const staticMeta = metadata.staticAnalysis || {};
    const staticDetails = staticMeta.details || {};

    const riskLevel = riskScore < 30 ? 'low' : riskScore < 70 ? 'medium' : 'high';
    const riskColorClass = `ct-risk-${riskLevel}`;

    // Tier badge formatting
    let tierBadgeHtml = '';
    if (tier === 'fast') {
      tierBadgeHtml = '<span class="ct-tier-tag ct-tier-fast">⚡ FAST PASS</span>';
    } else if (tier === 'static-pass') {
      tierBadgeHtml = '<span class="ct-tier-tag ct-tier-fast">🛡️ STATIC PASS</span>';
    } else if (tier === 'stage2-escalated') {
      tierBadgeHtml = '<span class="ct-tier-tag ct-tier-escalated">⚠️ STAGE 2 ESCALATED</span>';
    } else if (tier === 'sandbox-executed') {
      tierBadgeHtml = '<span class="ct-tier-tag ct-tier-escalated">🧪 SANDBOX EXECUTED</span>';
    } else if (tier === 'reputation-flagged') {
      tierBadgeHtml = '<span class="ct-tier-tag ct-tier-threat">🚨 FLAGGED THREAT</span>';
    } else {
      tierBadgeHtml = `<span class="ct-tier-tag">${escapeHtml(tier)}</span>`;
    }

    const verdictLabel = verdict.toUpperCase();

    // Domain age display
    let ageString = 'Verified';
    if (metadata.domainAgeMonths !== undefined) {
      if (metadata.domainAgeMonths >= 12) {
        ageString = `${Math.floor(metadata.domainAgeMonths / 12)}+ yrs (${metadata.creationDate || ''})`;
      } else {
        ageString = `${metadata.domainAgeMonths} mo (${metadata.creationDate || 'recent'})`;
      }
    }

    // Safe browsing status
    const isSbClean = metadata.safeBrowsing === 'clean' || (metadata.safeBrowsing && metadata.safeBrowsing.isClean);
    const sbString = isSbClean ? '🛡️ Safe Browsing: Clean' : `🚨 Threat: ${metadata.safeBrowsing?.threatType || 'Detected'}`;

    // Build heuristic chips for Stage 2
    const heuristicChips = [];
    heuristicChips.push(`<div class="ct-chip">📅 Domain Age: <strong>${escapeHtml(ageString)}</strong></div>`);
    heuristicChips.push(`<div class="ct-chip ${isSbClean ? '' : 'ct-chip-danger'}">${escapeHtml(sbString)}</div>`);

    if (staticDetails.passwordField?.detected) {
      heuristicChips.push(`<div class="ct-chip ct-chip-warn">🔑 Password Field</div>`);
    }
    if (staticDetails.brandMismatch?.detected) {
      heuristicChips.push(`<div class="ct-chip ct-chip-danger">🏷️ Brand Mismatch: ${escapeHtml(staticDetails.brandMismatch.info?.brand || 'Brand')}</div>`);
    }
    if (staticDetails.obfuscatedScripts?.detected) {
      heuristicChips.push(`<div class="ct-chip ct-chip-warn">📜 Obfuscated JS (${staticDetails.obfuscatedScripts.count})</div>`);
    }
    if (staticMeta.redirectHops > 0) {
      heuristicChips.push(`<div class="ct-chip ct-chip-info">🔀 ${staticMeta.redirectHops} Redirect Hop${staticMeta.redirectHops > 1 ? 's' : ''}</div>`);
    }

    container.innerHTML = `
      <div class="ct-modal ct-animate-in">
        <div class="ct-header">
          <div class="ct-brand">
            <span class="ct-logo-icon">🛡️</span>
            <div>
              <div class="ct-title">CyberTwin Pre-Flight Report</div>
              <div class="ct-subtitle">Stage 2 Static Analysis Pipeline</div>
            </div>
          </div>
          <button class="ct-close-btn" id="ct-btn-close" title="Close overlay">&times;</button>
        </div>

        <div class="ct-body">
          <div class="ct-target-box">
            <span class="ct-target-label">DESTINATION</span>
            <div class="ct-target-url" title="${escapeHtml(targetUrl)}">${escapeHtml(targetUrl)}</div>
          </div>

          <div class="ct-score-card ${riskColorClass}">
            <div class="ct-score-ring">
              <span class="ct-score-num">${riskScore}</span>
              <span class="ct-score-max">/100</span>
            </div>
            <div class="ct-score-meta">
              <div class="ct-score-verdict">
                <span class="ct-badge ${riskColorClass}">${verdictLabel}</span>
                ${tierBadgeHtml}
              </div>
              <div class="ct-score-reason"><strong>Reason:</strong> ${escapeHtml(reason)}</div>
            </div>
          </div>

          <!-- Telemetry & Heuristic Chips -->
          <div class="ct-telemetry-chips">
            ${heuristicChips.join('')}
          </div>

                  ${metadata.sandbox && metadata.sandbox.screenshotBase64 ? `
          <div class="ct-explanation-card" style="border-left-color: #c084fc;">
            <div class="ct-explanation-title" style="color: #c084fc;">Digital Twin — Live Sandbox Screenshot</div>
            <img src="${metadata.sandbox.screenshotBase64}" style="width: 100%; border-radius: 6px; margin-top: 8px; border: 1px solid #334155;" />
            <p style="font-size: 11px; color: #64748b; margin-top: 6px;">Rendered in ${metadata.sandbox.executionTimeSeconds}s in an isolated environment — never touched your real browser.</p>
          </div>
          ` : ''}

          
          <div class="ct-explanation-card">
            <div class="ct-explanation-title">Plain-English Security Explanation:</div>
            <p class="ct-explanation-text">${escapeHtml(plainEnglish)}</p>
          </div>

          <div class="ct-notice">
            ${riskScore >= 70
              ? '⚠️ <strong>High Risk Warning:</strong> Proceeding to this page carries significant risk of phishing or malware.'
              : 'Review the pre-flight telemetry and click <strong>Proceed</strong> or <strong>Cancel</strong>.'}
          </div>
        </div>

        <div class="ct-footer">
          <button class="ct-btn ct-btn-cancel ${riskScore >= 70 ? 'ct-btn-cancel-safe' : ''}" id="ct-btn-cancel">
            <span class="ct-btn-icon">✖</span> ${riskScore >= 70 ? 'Cancel (Recommended)' : 'Cancel'}
          </button>
          <button class="ct-btn ${riskScore >= 70 ? 'ct-btn-proceed-danger' : 'ct-btn-proceed'}" id="ct-btn-proceed">
            <span class="ct-btn-icon">➜</span> ${riskScore >= 70 ? 'Proceed Anyway (Unsafe)' : 'Proceed to Site'}
          </button>
        </div>
      </div>
    `;

    const cancelBtn = shadow.getElementById('ct-btn-cancel');
    const closeBtn = shadow.getElementById('ct-btn-close');
    const handleCancel = () => {
      console.log('[CyberTwin] Navigation cancelled.');
      closeOverlay();
    };
    if (cancelBtn) cancelBtn.addEventListener('click', handleCancel);
    if (closeBtn) closeBtn.addEventListener('click', handleCancel);

    const proceedBtn = shadow.getElementById('ct-btn-proceed');
    if (proceedBtn) {
      proceedBtn.addEventListener('click', () => {
        console.log('[CyberTwin] User chose PROCEED to:', targetUrl);
        closeOverlay();
        executeNavigation(targetUrl, targetWindow, originalAnchor);
      });
    }
  }

  function renderError(shadow, container, errorMsg, targetUrl, targetWindow, originalAnchor) {
    container.innerHTML = `
      <div class="ct-modal ct-animate-in">
        <div class="ct-header">
          <div class="ct-brand">
            <span class="ct-logo-icon">⚠️</span>
            <div>
              <div class="ct-title">CyberTwin Backend Offline</div>
              <div class="ct-subtitle">Connection to http://localhost:3001 failed</div>
            </div>
          </div>
          <button class="ct-close-btn" id="ct-btn-close">&times;</button>
        </div>

        <div class="ct-body">
          <div class="ct-target-box">
            <span class="ct-target-label">DESTINATION</span>
            <div class="ct-target-url">${escapeHtml(targetUrl)}</div>
          </div>

          <div class="ct-error-card">
            <div class="ct-error-title">Backend Service Unavailable</div>
            <p class="ct-error-text">
              Could not communicate with the local CyberTwin analyzer (${escapeHtml(errorMsg)}).
              Please ensure the backend server is running via <code>npm start</code> in <code>cybertwin/backend</code>.
            </p>
          </div>
        </div>

        <div class="ct-footer">
          <button class="ct-btn ct-btn-cancel" id="ct-btn-cancel">
            <span class="ct-btn-icon">✖</span> Cancel Navigation
          </button>
          <button class="ct-btn ct-btn-proceed-warning" id="ct-btn-proceed">
            <span class="ct-btn-icon">⚠️</span> Proceed Anyway
          </button>
        </div>
      </div>
    `;

    const cancelBtn = shadow.getElementById('ct-btn-cancel');
    const closeBtn = shadow.getElementById('ct-btn-close');
    const handleCancel = () => closeOverlay();
    if (cancelBtn) cancelBtn.addEventListener('click', handleCancel);
    if (closeBtn) closeBtn.addEventListener('click', handleCancel);

    const proceedBtn = shadow.getElementById('ct-btn-proceed');
    if (proceedBtn) {
      proceedBtn.addEventListener('click', () => {
        closeOverlay();
        executeNavigation(targetUrl, targetWindow, originalAnchor);
      });
    }
  }

  function executeNavigation(url, targetWindow, originalAnchor) {
    isNavigatingFromCyberTwin = true;

    if (originalAnchor) {
      originalAnchor.dataset.cybertwinBypass = 'true';
    }

    if (targetWindow === '_blank') {
      window.open(url, '_blank', 'noopener,noreferrer');
    } else {
      window.location.assign(url);
    }

    setTimeout(() => {
      isNavigatingFromCyberTwin = false;
    }, 1500);
  }

  function closeOverlay() {
    if (activeOverlay && activeOverlay.parentNode) {
      activeOverlay.parentNode.removeChild(activeOverlay);
    }
    activeOverlay = null;
  }

  function getLoadingHtml(targetUrl) {
    return `
      <div class="ct-modal ct-modal-loading ct-animate-in">
        <div class="ct-loading-body">
          <div class="ct-radar-scanner">
            <div class="ct-radar-sweep"></div>
            <span class="ct-radar-shield">🛡️</span>
          </div>
          <div class="ct-loading-title">CyberTwin Pre-Flight</div>
          <div class="ct-loading-subtitle">Running Static HTML Heuristics & Reputation Scan...</div>
          <div class="ct-loading-url" title="${escapeHtml(targetUrl)}">${escapeHtml(targetUrl)}</div>
          <div class="ct-loading-status">Inspecting forms, brands, scripts, and redirect hops...</div>
        </div>
        <div class="ct-loading-footer">
          <button class="ct-btn ct-btn-cancel ct-btn-sm" id="ct-btn-loading-cancel">Cancel</button>
        </div>
      </div>
    `;
  }

  function getOverlayStyles() {
    return `
      * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      }

      .ct-backdrop {
        position: fixed;
        inset: 0;
        background: rgba(10, 15, 29, 0.78);
        backdrop-filter: blur(8px);
        -webkit-backdrop-filter: blur(8px);
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 20px;
        z-index: 2147483647;
      }

      .ct-modal {
        background: #0f172a;
        color: #f8fafc;
        width: 100%;
        max-width: 530px;
        border-radius: 16px;
        border: 1px solid rgba(56, 189, 248, 0.25);
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.6), 0 0 30px rgba(56, 189, 248, 0.15);
        overflow: hidden;
        display: flex;
        flex-direction: column;
      }

      .ct-animate-in {
        animation: ctFadeScale 0.22s cubic-bezier(0.16, 1, 0.3, 1);
      }

      @keyframes ctFadeScale {
        from {
          opacity: 0;
          transform: scale(0.96) translateY(6px);
        }
        to {
          opacity: 1;
          transform: scale(1) translateY(0);
        }
      }

      .ct-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 16px 20px;
        background: #1e293b;
        border-bottom: 1px solid rgba(255, 255, 255, 0.08);
      }

      .ct-brand {
        display: flex;
        align-items: center;
        gap: 12px;
      }

      .ct-logo-icon {
        font-size: 26px;
        line-height: 1;
      }

      .ct-title {
        font-size: 16px;
        font-weight: 700;
        letter-spacing: -0.01em;
        color: #f1f5f9;
      }

      .ct-subtitle {
        font-size: 11px;
        color: #94a3b8;
        margin-top: 2px;
      }

      .ct-close-btn {
        background: transparent;
        border: none;
        color: #94a3b8;
        font-size: 24px;
        line-height: 1;
        cursor: pointer;
        padding: 4px 8px;
        border-radius: 6px;
        transition: all 0.15s ease;
      }

      .ct-close-btn:hover {
        color: #f8fafc;
        background: rgba(255, 255, 255, 0.1);
      }

      .ct-body {
        padding: 20px;
        display: flex;
        flex-direction: column;
        gap: 14px;
      }

      .ct-target-box {
        background: #090d16;
        border: 1px solid #1e293b;
        border-radius: 10px;
        padding: 10px 14px;
      }

      .ct-target-label {
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 0.08em;
        color: #38bdf8;
        display: block;
        margin-bottom: 4px;
      }

      .ct-target-url {
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
        font-size: 13px;
        color: #e2e8f0;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }

      .ct-score-card {
        display: flex;
        align-items: center;
        gap: 16px;
        padding: 14px 18px;
        border-radius: 12px;
        background: #1e293b;
        border: 1px solid rgba(255, 255, 255, 0.08);
      }

      .ct-score-card.ct-risk-low {
        background: linear-gradient(135deg, rgba(34, 197, 94, 0.12), rgba(15, 23, 42, 0.6));
        border-color: rgba(34, 197, 94, 0.35);
      }

      .ct-score-card.ct-risk-medium {
        background: linear-gradient(135deg, rgba(234, 179, 8, 0.12), rgba(15, 23, 42, 0.6));
        border-color: rgba(234, 179, 8, 0.35);
      }

      .ct-score-card.ct-risk-high {
        background: linear-gradient(135deg, rgba(239, 68, 68, 0.18), rgba(15, 23, 42, 0.6));
        border-color: rgba(239, 68, 68, 0.45);
      }

      .ct-score-ring {
        display: flex;
        align-items: baseline;
        justify-content: center;
        min-width: 80px;
        padding: 10px 12px;
        background: rgba(0, 0, 0, 0.3);
        border-radius: 10px;
      }

      .ct-score-num {
        font-size: 32px;
        font-weight: 800;
        line-height: 1;
        color: #22c55e;
      }

      .ct-risk-medium .ct-score-num {
        color: #eab308;
      }

      .ct-risk-high .ct-score-num {
        color: #ef4444;
      }

      .ct-score-max {
        font-size: 14px;
        color: #64748b;
        margin-left: 2px;
      }

      .ct-score-meta {
        flex: 1;
        display: flex;
        flex-direction: column;
        gap: 6px;
      }

      .ct-score-verdict {
        display: flex;
        align-items: center;
        gap: 8px;
        flex-wrap: wrap;
      }

      .ct-badge {
        font-size: 11px;
        font-weight: 800;
        letter-spacing: 0.04em;
        padding: 3px 8px;
        border-radius: 9999px;
        text-transform: uppercase;
      }

      .ct-badge.ct-risk-low {
        background: #22c55e;
        color: #052e16;
      }

      .ct-badge.ct-risk-medium {
        background: #eab308;
        color: #422006;
      }

      .ct-badge.ct-risk-high {
        background: #ef4444;
        color: #ffffff;
      }

      .ct-tier-tag {
        font-size: 10px;
        font-weight: 700;
        padding: 3px 7px;
        border-radius: 4px;
        text-transform: uppercase;
      }

      .ct-tier-fast {
        background: rgba(34, 197, 94, 0.2);
        color: #4ade80;
        border: 1px solid rgba(34, 197, 94, 0.4);
      }

      .ct-tier-escalated {
        background: rgba(234, 179, 8, 0.2);
        color: #facc15;
        border: 1px solid rgba(234, 179, 8, 0.4);
      }

      .ct-tier-threat {
        background: rgba(239, 68, 68, 0.2);
        color: #f87171;
        border: 1px solid rgba(239, 68, 68, 0.4);
      }

      .ct-score-reason {
        font-size: 12px;
        color: #cbd5e1;
      }

      .ct-telemetry-chips {
        display: flex;
        gap: 8px;
        flex-wrap: wrap;
      }

      .ct-chip {
        background: #1e293b;
        border: 1px solid #334155;
        border-radius: 6px;
        padding: 6px 10px;
        font-size: 11px;
        color: #94a3b8;
      }

      .ct-chip strong {
        color: #f1f5f9;
      }

      .ct-chip-warn {
        border-color: rgba(234, 179, 8, 0.4);
        background: rgba(234, 179, 8, 0.1);
        color: #facc15;
      }

      .ct-chip-danger {
        border-color: rgba(239, 68, 68, 0.4);
        background: rgba(239, 68, 68, 0.1);
        color: #f87171;
      }

      .ct-chip-info {
        border-color: rgba(56, 189, 248, 0.4);
        background: rgba(56, 189, 248, 0.1);
        color: #38bdf8;
      }

      .ct-explanation-card {
        background: #131d31;
        border-left: 3px solid #38bdf8;
        border-radius: 0 8px 8px 0;
        padding: 12px 14px;
      }

      .ct-explanation-title {
        font-size: 11px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        color: #38bdf8;
        margin-bottom: 4px;
      }

      .ct-explanation-text {
        font-size: 13px;
        color: #cbd5e1;
        line-height: 1.5;
      }

      .ct-notice {
        font-size: 12px;
        color: #94a3b8;
        text-align: center;
      }

      .ct-error-card {
        background: rgba(239, 68, 68, 0.1);
        border: 1px solid rgba(239, 68, 68, 0.3);
        border-radius: 10px;
        padding: 14px;
      }

      .ct-error-title {
        font-size: 14px;
        font-weight: 700;
        color: #f87171;
        margin-bottom: 6px;
      }

      .ct-error-text {
        font-size: 12px;
        color: #cbd5e1;
        line-height: 1.5;
      }

      .ct-error-text code {
        background: #0f172a;
        color: #38bdf8;
        padding: 2px 5px;
        border-radius: 4px;
        font-family: monospace;
      }

      .ct-footer {
        display: flex;
        gap: 12px;
        padding: 16px 20px;
        background: #1e293b;
        border-top: 1px solid rgba(255, 255, 255, 0.08);
      }

      .ct-btn {
        flex: 1;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        padding: 12px 16px;
        font-size: 14px;
        font-weight: 600;
        border-radius: 10px;
        border: none;
        cursor: pointer;
        transition: all 0.15s ease;
      }

      .ct-btn-icon {
        font-size: 14px;
      }

      .ct-btn-cancel {
        background: #334155;
        color: #f1f5f9;
      }

      .ct-btn-cancel:hover {
        background: #475569;
        color: #ffffff;
      }

      .ct-btn-cancel-safe {
        background: #16a34a;
        color: #ffffff;
      }

      .ct-btn-cancel-safe:hover {
        background: #15803d;
      }

      .ct-btn-proceed {
        background: #16a34a;
        color: #ffffff;
        box-shadow: 0 4px 12px rgba(22, 163, 74, 0.35);
      }

      .ct-btn-proceed:hover {
        background: #15803d;
      }

      .ct-btn-proceed-danger {
        background: #dc2626;
        color: #ffffff;
      }

      .ct-btn-proceed-danger:hover {
        background: #b91c1c;
      }

      .ct-btn-proceed-warning {
        background: #d97706;
        color: #ffffff;
      }

      .ct-btn-proceed-warning:hover {
        background: #b45309;
      }

      .ct-btn-sm {
        flex: none;
        padding: 6px 14px;
        font-size: 12px;
      }

      .ct-modal-loading {
        max-width: 420px;
        text-align: center;
      }

      .ct-loading-body {
        padding: 36px 24px 24px;
        display: flex;
        flex-direction: column;
        align-items: center;
      }

      .ct-radar-scanner {
        position: relative;
        width: 80px;
        height: 80px;
        border-radius: 50%;
        background: radial-gradient(circle, rgba(56, 189, 248, 0.15) 0%, rgba(15, 23, 42, 0.8) 70%);
        border: 2px solid rgba(56, 189, 248, 0.4);
        display: flex;
        align-items: center;
        justify-content: center;
        margin-bottom: 20px;
        overflow: hidden;
      }

      .ct-radar-sweep {
        position: absolute;
        inset: 0;
        border-radius: 50%;
        background: conic-gradient(from 0deg, transparent 0deg, rgba(56, 189, 248, 0.4) 60deg, transparent 61deg);
        animation: ctRadarRotate 1.4s linear infinite;
      }

      @keyframes ctRadarRotate {
        from { transform: rotate(0deg); }
        to { transform: rotate(360deg); }
      }

      .ct-radar-shield {
        position: relative;
        font-size: 34px;
        z-index: 2;
        filter: drop-shadow(0 0 8px rgba(56, 189, 248, 0.6));
      }

      .ct-loading-title {
        font-size: 18px;
        font-weight: 700;
        color: #f1f5f9;
        margin-bottom: 6px;
      }

      .ct-loading-subtitle {
        font-size: 13px;
        color: #94a3b8;
        margin-bottom: 16px;
      }

      .ct-loading-url {
        font-family: ui-monospace, SFMono-Regular, monospace;
        font-size: 12px;
        color: #38bdf8;
        background: #090d16;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 8px 12px;
        width: 100%;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        margin-bottom: 14px;
      }

      .ct-loading-status {
        font-size: 11px;
        color: #64748b;
        letter-spacing: 0.02em;
        text-transform: uppercase;
      }

      .ct-loading-footer {
        padding: 12px 20px 16px;
        display: flex;
        justify-content: center;
      }
    `;
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
})();
