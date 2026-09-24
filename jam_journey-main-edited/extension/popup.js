const urlBox = document.querySelector('#url');
const resultBox = document.querySelector('#result');
const button = document.querySelector('#check');
chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => { urlBox.textContent = tab?.url || 'No web page selected'; });
button.addEventListener('click', () => {
  button.disabled = true;
  resultBox.textContent = 'Checking URL and page signals…';
  chrome.runtime.sendMessage({ type: 'BODYGUARD_CHECK_ACTIVE_TAB' }, (response) => {
    button.disabled = false;
    if (chrome.runtime.lastError || !response?.ok) {
      resultBox.className = 'error';
      resultBox.textContent = response?.error || chrome.runtime.lastError?.message || 'Check failed.';
      return;
    }
    const report = response.report;
    resultBox.textContent = `${report.title} — ${report.summary}${report.aiAssessment?.status === 'complete' ? ` Gemini: ${report.aiAssessment.verdict} (${report.aiAssessment.confidence}%).` : ''}`;
  });
});
