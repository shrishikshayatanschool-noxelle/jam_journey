const urlBox = document.querySelector('#url');
const resultBox = document.querySelector('#result');
const button = document.querySelector('#check');

function showError(message) {
  resultBox.hidden = false;
  resultBox.className = 'error';
  resultBox.textContent = message;
}

chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
  const pageUrl = tab?.url || '';
  urlBox.textContent = pageUrl || 'No active page found.';
  if (!/^https?:\/\//i.test(pageUrl)) {
    button.disabled = true;
    button.title = 'Chrome internal pages and local files cannot be scanned.';
    urlBox.textContent = pageUrl ? `${pageUrl} (This page type cannot be scanned.)` : 'No active page found.';
  }
});

button.addEventListener('click', () => {
  button.disabled = true;
  button.innerHTML = '<span class="button-icon" aria-hidden="true">◌</span> Checking this page…';
  resultBox.hidden = false;
  resultBox.className = '';
  resultBox.textContent = 'Connecting to the scanner. It may take up to 90 seconds if the hosted service is waking up.';

  chrome.runtime.sendMessage({ type: 'BODYGUARD_CHECK_ACTIVE_TAB' }, (response) => {
    button.disabled = false;
    button.innerHTML = '<span class="button-icon" aria-hidden="true">⌕</span> Check this link <span class="arrow" aria-hidden="true">→</span>';
    if (chrome.runtime.lastError || !response?.ok) {
      showError(response?.error || chrome.runtime.lastError?.message || 'Could not contact the scanner. Reload the extension and try again.');
      return;
    }

    const report = response.report || {};
    resultBox.className = `risk-${String(report.level || 'unknown').replace(/[^a-z-]/gi, '')}`;
    resultBox.replaceChildren();
    const title = document.createElement('p');
    title.className = 'result-title';
    const dot = document.createElement('span');
    dot.className = 'result-dot';
    const titleText = document.createElement('span');
    titleText.textContent = report.title || 'Scan complete';
    title.append(dot, titleText);
    const summary = document.createElement('p');
    summary.className = 'result-summary';
    summary.textContent = report.summary || 'No summary was returned by the scanner.';
    resultBox.append(title, summary);
    if (report.aiAssessment?.message && report.aiAssessment.status !== 'complete') {
      const note = document.createElement('small');
      note.className = 'result-meta';
      note.textContent = `AI review unavailable: ${report.aiAssessment.message}`;
      resultBox.append(note);
    } else if (report.aiAssessment?.status === 'complete') {
      const note = document.createElement('small');
      note.className = 'result-meta';
      note.textContent = `AI review: ${report.aiAssessment.verdict} · ${report.aiAssessment.confidence}% confidence`;
      resultBox.append(note);
    }
  });
});
