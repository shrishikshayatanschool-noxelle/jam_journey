const DEFAULT_BACKEND = 'http://127.0.0.1:4173';

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
        body: JSON.stringify({ url: tab.url }), signal: AbortSignal.timeout(35_000),
      });
      const report = await response.json();
      if (!response.ok) throw new Error(report.error || 'The scan could not be completed.');
      await chrome.storage.local.set({ [`tab:${tab.id}`]: { url: tab.url, checkedAt: Date.now(), report } });
      sendResponse({ ok: true, report });
    } catch (error) { sendResponse({ ok: false, error: error.message }); }
  })();
  return true;
});

chrome.tabs.onRemoved.addListener((tabId) => chrome.storage.local.remove(`tab:${tabId}`));
