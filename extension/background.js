/**
 * CyberTwin — Background Service Worker (Manifest V3)
 * Handles backend communication, bypassing webpage Content Security Policy (CSP).
 */

const DEFAULT_BACKEND_URL = 'https://cybertwin-backend.onrender.com';

// Initialize default storage settings on installation
chrome.runtime.onInstalled.addListener(async () => {
  const current = await chrome.storage.local.get(['enabled', 'backendUrl']);

  if (current.enabled === undefined) {
    await chrome.storage.local.set({ enabled: true });
  }

  // Use the live Render backend instead of the old localhost backend
  if (
    !current.backendUrl ||
    current.backendUrl === 'http://localhost:3001'
  ) {
    await chrome.storage.local.set({
      backendUrl: DEFAULT_BACKEND_URL
    });
  }

  console.log('[CyberTwin] Service Worker initialized with settings:', {
    enabled: current.enabled ?? true,
    backendUrl: current.backendUrl || DEFAULT_BACKEND_URL
  });
});

// Message listener for content scripts & popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {

  if (request.type === 'ALLOW_RISKY_DOWNLOAD') {
    const downloadId = request.downloadId;

    if (!downloadId) {
      sendResponse({ success: false, error: 'Missing download ID' });
      return true;
    }

    (async () => {
      try {
        await chrome.downloads.resume(downloadId);
        console.log('[CyberTwin] Risky download resumed:', downloadId);
      } catch (error) {
        // resume() fails if the file already finished (nothing to resume) —
        // that's fine, it just means the file is already sitting there and
        // the user chose to keep it. Nothing more to do.
        console.log('[CyberTwin] Download already complete, nothing to resume — keeping file:', downloadId);
      }

      await chrome.storage.local.remove('pendingDownload');
      sendResponse({ success: true });
    })();

    return true;
  }

  if (request.type === 'CANCEL_RISKY_DOWNLOAD') {
    const downloadId = request.downloadId;

    if (!downloadId) {
      sendResponse({ success: false, error: 'Missing download ID' });
      return true;
    }

    (async () => {
      try {
        // Try to cancel first — works if the download is still in progress
        await chrome.downloads.cancel(downloadId);
        console.log('[CyberTwin] Risky download cancelled:', downloadId);
      } catch (error) {
        // cancel() fails if the file already finished downloading —
        // fall back to deleting it from disk instead.
        console.warn('[CyberTwin] Cancel failed (likely already complete), trying removeFile:', error.message);
        try {
          await chrome.downloads.removeFile(downloadId);
          console.log('[CyberTwin] Already-downloaded risky file deleted:', downloadId);
        } catch (delErr) {
          console.error('[CyberTwin] Could not delete file either:', delErr);
          sendResponse({ success: false, error: delErr.message });
          return;
        }
      }

      await chrome.storage.local.remove('pendingDownload');
      sendResponse({ success: true });
    })();

    return true;
  }

  if (request.type === 'ANALYZE_URL') {
    handleAnalyzeUrl(request.url).then(sendResponse).catch(err => {
      sendResponse({
        success: false,
        error: err.message || 'Failed to reach CyberTwin backend'
      });
    });
    return true; // Keep message channel open for async response
  }

  if (request.type === 'CHECK_HEALTH') {
    handleCheckHealth().then(sendResponse).catch(err => {
      sendResponse({
        healthy: false,
        error: err.message || 'Backend unreachable'
      });
    });
    return true;
  }
});

async function getBackendUrl() {
  const stored = await chrome.storage.local.get('backendUrl');
  return stored.backendUrl || DEFAULT_BACKEND_URL;
}

async function handleAnalyzeUrl(url) {
  const baseUrl = await getBackendUrl();
  console.log(`[CyberTwin] Forwarding URL analysis to ${baseUrl}/analyze:`, url);

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);

    const response = await fetch(`${baseUrl}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      const errText = await response.text();
      return {
        success: false,
        error: `Backend returned ${response.status}: ${errText}`
      };
    }

    const data = await response.json();
    return { success: true, data };
  } catch (error) {
    console.warn('[CyberTwin] Analyze request failed:', error);
    return {
      success: false,
      error: error.name === 'AbortError' ? 'Analysis timed out' : 'CyberTwin backend is not running at ' + baseUrl
    };
  }
}

async function handleCheckHealth() {
  const baseUrl = await getBackendUrl();
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2000);

    const res = await fetch(`${baseUrl}/health`, { signal: controller.signal });
    clearTimeout(timeoutId);

    if (res.ok) {
      const json = await res.json();
      return { healthy: true, data: json };
    }
    return { healthy: false, status: res.status };
  } catch (err) {
    return { healthy: false, error: err.message };
  }
}

// ============================================================
// CyberTwin Download Risk Classifier
// ============================================================

function classifyDownload(downloadInfo) {
  const filename = (downloadInfo.filename || '').toLowerCase();
  const mime = (downloadInfo.mime || '').toLowerCase();
  const danger = (downloadInfo.danger || '').toLowerCase();

  let score = 0;
  const reasons = [];

  const highRiskExtensions = ['.exe', '.scr', '.bat', '.cmd', '.com', '.msi', '.ps1', '.vbs', '.js'];
  const reviewExtensions = ['.zip', '.rar', '.7z', '.iso'];

  if (highRiskExtensions.some(ext => filename.endsWith(ext))) {
    score += 50;
    reasons.push('Executable or script file type');
  } else if (reviewExtensions.some(ext => filename.endsWith(ext))) {
    score += 20;
    reasons.push('Archive or disk-image file type');
  }

  if (mime.includes('octet-stream') || mime.includes('x-msdownload')) {
    score += 20;
    reasons.push('Generic or executable MIME type');
  }

  if (danger && danger !== 'safe' && danger !== 'accepted') {
    score += 40;
    reasons.push(`Chrome marked download as ${danger}`);
  }

  score = Math.min(score, 100);

  let risk = 'LOW';
  if (score >= 70) {
    risk = 'HIGH';
  } else if (score >= 40) {
    risk = 'MEDIUM';
  }

  return { score, risk, reasons };
}

// ============================================================
// CyberTwin Download Detection
// ============================================================

// Shared handler — called from BOTH onCreated (fastest possible reaction)
// and onChanged (catches cases where danger/filename weren't known yet).
// Deduped via pendingDownload storage so it only acts once per download.
async function handleRiskyDownload(downloadInfo, risk) {
  const stored = await chrome.storage.local.get('pendingDownload');
  const alreadyTracked = stored.pendingDownload && stored.pendingDownload.id === downloadInfo.id;
  if (alreadyTracked) return;

  let fileAlreadyLanded = false;

  // Re-check the ACTUAL current state right now — the state passed in
  // (from onCreated or onChanged) can already be stale by the time this
  // async code runs, especially for instant in-memory Blob downloads.
  let currentState = downloadInfo.state;
  try {
    const fresh = await chrome.downloads.search({ id: downloadInfo.id });
    if (fresh.length > 0) {
      currentState = fresh[0].state;
    }
  } catch (e) {
    console.warn('[CyberTwin] Could not re-check current download state:', e);
  }

  try {
    if (currentState === 'in_progress') {
      await chrome.downloads.pause(downloadInfo.id);
      console.log('[CyberTwin] HIGH-RISK download paused:', downloadInfo.id);
    } else {
      // Already complete (or interrupted) — too fast to pause. Delete it
      // from disk so the user never ends up keeping an unapproved file.
      fileAlreadyLanded = true;
      try {
        await chrome.downloads.removeFile(downloadInfo.id);
        console.log('[CyberTwin] Risky file already landed — deleted from disk:', downloadInfo.id);
      } catch (delErr) {
        console.warn('[CyberTwin] Could not delete already-landed file:', delErr);
      }
    }
  } catch (error) {
    // pause() itself failed (e.g. it finished between our check and this
    // call) — fall back to delete as a last resort.
    console.warn('[CyberTwin] Pause failed, attempting delete instead:', error.message);
    fileAlreadyLanded = true;
    try {
      await chrome.downloads.removeFile(downloadInfo.id);
      console.log('[CyberTwin] Risky file deleted after failed pause:', downloadInfo.id);
    } catch (delErr) {
      console.warn('[CyberTwin] Could not delete file either:', delErr);
    }
  }

  await chrome.storage.local.set({
    pendingDownload: {
      id: downloadInfo.id,
      url: downloadInfo.url,
      filename: downloadInfo.filename,
      mime: downloadInfo.mime,
      danger: downloadInfo.danger,
      risk: risk,
      fileAlreadyLanded
    }
  });

  console.log('[CyberTwin] Pending risky download saved.');

  const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  if (tabs.length > 0) {
    const tabId = tabs[0].id;
    chrome.tabs.sendMessage(tabId, {
      type: 'DOWNLOAD_RISK',
      data: {
        id: downloadInfo.id,
        ...risk,
        filename: downloadInfo.filename,
        mime: downloadInfo.mime,
        danger: downloadInfo.danger,
        url: downloadInfo.url,
        fileAlreadyLanded
      }
    }).catch(() => {
      console.warn('[CyberTwin] Could not send download warning to active tab.');
    });
  }
}

chrome.downloads.onCreated.addListener(async (downloadItem) => {
  const downloadInfo = {
    id: downloadItem.id,
    url: downloadItem.url,
    finalUrl: downloadItem.finalUrl,
    referrer: downloadItem.referrer,
    filename: downloadItem.filename,
    mime: downloadItem.mime,
    fileSize: downloadItem.fileSize,
    state: downloadItem.state,
    danger: downloadItem.danger
  };

  console.log('[CyberTwin] Download detected:', downloadInfo);

  const risk = classifyDownload(downloadInfo);
  console.log('[CyberTwin] Download Risk:', { ...risk, filename: downloadInfo.filename, mime: downloadInfo.mime });

  // React immediately — don't wait for onChanged. This is our best shot
  // at pausing before a small file finishes writing to disk.
  if (risk.score >= 70) {
    await handleRiskyDownload(downloadInfo, risk);
  }
});

chrome.downloads.onChanged.addListener(async (delta) => {
  const changes = {};
  if (delta.filename) changes.filename = delta.filename.current;
  if (delta.url) changes.url = delta.url.current;
  if (delta.danger) changes.danger = delta.danger.current;
  if (delta.state) changes.state = delta.state.current;

  if (Object.keys(changes).length > 0) {
    console.log('[CyberTwin] Download updated:', { id: delta.id, ...changes });
  }

  // Re-check the download once Chrome provides the final metadata
  if (delta.filename || delta.danger || delta.state) {
    try {
      const downloadItem = await chrome.downloads.search({ id: delta.id });
      if (downloadItem.length === 0) return;

      const item = downloadItem[0];
      const downloadInfo = {
        id: item.id,
        tabId: item.tabId,
        url: item.url,
        finalUrl: item.finalUrl,
        referrer: item.referrer,
        filename: item.filename,
        mime: item.mime,
        fileSize: item.fileSize,
        state: item.state,
        danger: item.danger
      };

      const risk = classifyDownload(downloadInfo);

      console.log('[CyberTwin] Updated Download Risk:', {
        ...risk,
        filename: downloadInfo.filename,
        mime: downloadInfo.mime,
        danger: downloadInfo.danger
      });

      // Handle HIGH-risk downloads — catches cases where onCreated didn't
      // yet have the danger/filename info (Chrome fills these in slightly
      // later, after its own Safe Browsing check). Deduped inside the
      // shared function, so this is safe even if onCreated already acted.
      if (risk.score >= 70 && downloadInfo.state !== 'interrupted') {
        await handleRiskyDownload(downloadInfo, risk);
      }
    } catch (error) {
      console.warn('[CyberTwin] Could not re-check download:', error);
    }
  }
});
