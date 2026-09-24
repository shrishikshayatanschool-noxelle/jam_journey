(() => {
  'use strict';

  const $ = (selector) => document.querySelector(selector);
  const form = $('#scan-form');
  const input = $('#url-input');
  const submit = $('#scan-button');
  const loading = $('#loading-card');
  const result = $('#result');
  const error = $('#form-error');
  const scanAnother = $('#scan-another');
  let elapsedTimer = null;
  let stepTimer = null;
  let controller = null;

  function showError(message) {
    error.textContent = message;
    error.hidden = false;
    input.setAttribute('aria-invalid', 'true');
  }

  function stopTimers() {
    window.clearInterval(elapsedTimer);
    window.clearInterval(stepTimer);
    elapsedTimer = stepTimer = null;
  }

  function setScanning(isScanning) {
    submit.disabled = isScanning;
    input.disabled = isScanning;
    loading.hidden = !isScanning;
    if (isScanning) {
      $('#loading-title').textContent = 'Checking the website…';
      $('#loading-step').textContent = 'Looking up the public address and checking the connection.';
      $('#loading-elapsed').textContent = '0s';
      let seconds = 0;
      elapsedTimer = window.setInterval(() => { seconds += 1; $('#loading-elapsed').textContent = `${seconds}s`; }, 1000);
      const messages = [
        'Following public redirects and checking the TLS connection.',
        'Inspecting page controls, billing language, and hidden instructions.',
        'Summarizing the signals found for this page.',
      ];
      let step = 0;
      stepTimer = window.setInterval(() => { step = (step + 1) % messages.length; $('#loading-step').textContent = messages[step]; }, 1900);
    } else stopTimers();
  }

  function text(id, value) { $(id).textContent = value || ''; }

  function renderFinding(finding) {
    const article = document.createElement('article');
    article.className = `finding finding-${finding.severity}`;
    const icon = document.createElement('span');
    icon.className = 'finding-icon';
    icon.textContent = finding.severity === 'critical' ? '!' : finding.severity === 'high' ? '!' : finding.severity === 'medium' ? '△' : 'i';
    const copy = document.createElement('div');
    copy.className = 'finding-copy';
    const title = document.createElement('b');
    title.textContent = finding.title;
    const detail = document.createElement('p');
    detail.textContent = finding.detail;
    const severity = document.createElement('span');
    severity.className = 'finding-severity';
    severity.textContent = finding.severity.toUpperCase();
    copy.append(title, detail);
    article.append(icon, copy, severity);
    if (finding.evidence) {
      const evidence = document.createElement('details');
      evidence.className = 'finding-evidence';
      const summary = document.createElement('summary');
      summary.textContent = 'View evidence';
      const pre = document.createElement('pre');
      pre.textContent = String(finding.evidence).slice(0, 500);
      evidence.append(summary, pre);
      article.append(evidence);
    }
    return article;
  }

  function renderChecks(checks) {
    const grid = $('#check-grid');
    grid.replaceChildren();
    for (const check of checks || []) {
      const card = document.createElement('div');
      card.className = `check-card ${check.status || 'info'}`;
      const mark = document.createElement('span');
      mark.className = 'check-mark';
      mark.textContent = check.status === 'good' ? '✓' : check.status === 'warning' ? '!' : '·';
      const copy = document.createElement('span');
      const title = document.createElement('b');
      title.textContent = check.title;
      const detail = document.createElement('small');
      detail.textContent = check.detail;
      copy.append(title, detail);
      card.append(mark, copy);
      grid.append(card);
    }
  }

  function renderReport(report) {
    const level = report.level || 'unknown';
    const banner = $('#result-banner');
    banner.className = `result-banner banner-${level}`;
    $('#result-symbol').textContent = level === 'dangerous' ? '!' : level === 'suspicious' || level === 'caution' ? '△' : level === 'no-major-issues' ? '✓' : '?';
    text('#result-kicker', level === 'dangerous' ? 'HIGH RISK · DO NOT CONTINUE' : level === 'suspicious' ? 'SUSPICIOUS · USE CAUTION' : level === 'caution' ? 'CAUTION · REVIEW THE DETAILS' : level === 'no-major-issues' ? 'NO LISTED THREATS OR MAJOR PAGE RISKS FOUND' : 'INCOMPLETE · NOT VERIFIED SAFE');
    text('#result-title', report.title);
    text('#result-summary', report.summary);
    text('#result-host', report.host);
    text('#checked-url', report.finalUrl || report.url);
    text('#scan-time', `Checked ${new Date(report.checkedAt).toLocaleString()}`);

    const findings = $('#findings');
    findings.replaceChildren();
    for (const finding of report.findings || []) findings.append(renderFinding(finding));
    const hasFindings = (report.findings || []).length > 0;
    $('#no-findings').hidden = hasFindings;
    text('#no-findings-title', level === 'incomplete' ? 'This link is unverified' : 'No high-risk patterns were found by the configured checks');
    text('#no-findings-detail', level === 'incomplete' ? 'A reputation source or full page inspection was unavailable. Do not treat this as a safe result.' : 'No scan can guarantee that an unfamiliar website is safe.');
    text('#finding-count', hasFindings ? `${report.findings.length} SIGNAL${report.findings.length === 1 ? '' : 'S'}` : '0 SIGNALS');
    renderChecks(report.checks);
    result.hidden = false;
    result.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  async function scan(rawUrl) {
    if (controller) controller.abort();
    controller = new AbortController();
    setScanning(true);
    result.hidden = true;
    error.hidden = true;
    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({ url: rawUrl }),
        signal: controller.signal,
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || `Scan request failed (${response.status}).`);
      renderReport(data);
    } catch (cause) {
      if (cause.name === 'AbortError') return;
      showError(cause.message === 'Failed to fetch'
        ? 'Could not reach the scanner service. Start it with “node server.mjs” and open http://localhost:4173.'
        : cause.message || 'The scan could not be completed.');
    } finally {
      setScanning(false);
    }
  }

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    const value = input.value.trim();
    if (!value) { showError('Paste a website address to scan.'); input.focus(); return; }
    scan(value);
  });
  input.addEventListener('input', () => { error.hidden = true; input.removeAttribute('aria-invalid'); });
  scanAnother.addEventListener('click', () => {
    result.hidden = true;
    input.value = '';
    input.disabled = false;
    input.focus();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });
  document.querySelectorAll('[data-sample]').forEach((button) => {
    button.addEventListener('click', () => {
      input.value = button.dataset.sample || '';
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.focus();
      input.scrollIntoView({ behavior: 'smooth', block: 'center' });
    });
  });
})();

