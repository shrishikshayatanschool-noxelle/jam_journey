// Observes the current page address and hands it to the extension worker.
// It does not read page contents or send anything to the backend automatically.
chrome.runtime.sendMessage({ type: 'BODYGUARD_TAB_URL', url: window.location.href });
