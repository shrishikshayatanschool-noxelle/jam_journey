const DEFAULT_BACKEND = 'https://bodyguard-ai.onrender.com';

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === 'BODYGUARD_TAB_URL' && sender.tab?.id && /^https?:\/\//i.test(message.url || '')) {
    chrome.storage.local.set({ [`tab:${sender.tab.id}`]: { url: message.url, observedAt: Date.now() } });
    return;
  }
  if (message?.type !== 'BODYGUARD_CHECK_ACTIVE_TAB') return;
  (async () => {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url || !/^https?:\/\//i.test(tab.url)) throw new Error('This page type cannot be checked.');
      const settings = await chrome.storage.local.get('backendUrl');
      const backend = (settings.backendUrl || DEFAULT_BACKEND).replace(/\/$/, '');
      const response = await fetch(`${backend}/api/scan`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ url: tab.url }), signal: AbortSignal.timeout(90_000),
      });
      const report = await response.json().catch(() => null);
      if (!report) throw new Error(`The scanner returned an unreadable response (HTTP ${response.status}). Check that the backend is deployed.`);
      if (!response.ok) throw new Error(report.error || 'The scan could not be completed.');
      await chrome.storage.local.set({ [`tab:${tab.id}`]: { url: tab.url, checkedAt: Date.now(), report } });
      sendResponse({ ok: true, report });
    } catch (error) {
      const message = error.name === 'TimeoutError' || error.name === 'AbortError'
        ? 'The scan took too long. The hosted service may be waking up; wait a moment and try again.'
        : error.message === 'Failed to fetch'
          ? 'Could not connect to the scanner. Check your internet connection and confirm the Bodyguard backend is online.'
          : error.message || 'The scan could not be completed.';
      sendResponse({ ok: false, error: message });
    }
  })();
  return true;
});

chrome.tabs.onRemoved.addListener((tabId) => chrome.storage.local.remove(`tab:${tabId}`));
