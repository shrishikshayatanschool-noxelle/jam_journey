# Bodyguard — live website safety checker

Bodyguard lets a user paste a public website address and get a risk report before opening it. The backend checks its public HTTP response, redirect chain, and HTML, then asks Gemini to assess a bounded snapshot of page text and navigation controls for scam and phishing patterns. The Gemini API key stays on the server.

You can enter a bare domain such as `www.google.com`; the form adds `https://` before checking. A result marked unverified means a reputation provider or page check was unavailable, not that the address was confirmed malicious.

Use the theme control in the header to switch between light and dark mode. Bodyguard remembers the choice in the current browser.

## Start it

Requirements: Node.js 18 or later, outbound DNS and HTTP/HTTPS access to inspect public sites, and a Gemini API key for AI URL analysis.

1. Download or clone the project.
2. Open a terminal in the project folder.
3. Copy `.env.example` to `.env` and set `GEMINI_API_KEY` (Gemini analysis is omitted if no key is set).
4. Run `node server.mjs`.
5. Open <http://localhost:4173> and paste a public website address.

The service binds to `127.0.0.1` by default, so it is only available on your computer. It fetches public pages through its own backend; opening `index.html` directly with `file://` will not run a scan.

## What it checks

- HTTP versus HTTPS and whether the HTTPS certificate validates.
- Redirect count, destination, and HTTP downgrade.
- Checked consent boxes located near recurring billing or trial language.
- Inline invisible fixed/absolute elements that could cover page controls.
- Download, cancel, close, and dismiss labels paired with suspicious script or redirect destinations.
- Page text that resembles prompt injection or requests for private agent data.
- Punycode or IP-based addresses, password inputs sent over HTTP, security headers, scripts, and frames.

Results say **dangerous**, **suspicious**, **caution**, or **no major page risks detected**, and show the evidence behind each signal. A clean scan is not a certificate of safety.

## Important coverage limits

This version fetches public HTML but does not execute the target site's JavaScript or render its layout. It cannot see traps created only after scripts run, external stylesheets, canvas or image-only content, or behavior requiring a browser session. Gemini receives the URL, up to 12,000 characters of extracted visible text, a bounded list of link/button labels and destinations, form actions and field metadata (not entered values), redirects, and existing scan signals. It does not browse the destination, and its assessment is heuristic, not proof of safety. Bodyguard does not query Google Safe Browsing, VirusTotal, or another reputation database. Do not treat results as a substitute for browser protections.

Scanning sends the address to the Bodyguard server, which fetches the public page and sends the bounded extracted snapshot to Gemini when configured. Raw HTML and form-entered values are not sent. The URL and destinations can include private tokens or other secrets, so do not scan links containing confidential data. The server refuses private/reserved IP ranges, nonstandard ports, userinfo URLs, and redirects into private networks. It caps response size, request time, scan concurrency, and scan frequency. The extension observes page URLs locally and contacts the backend only after the user clicks its check button.

## Browser extension (Chrome / Chromium)

1. In Chrome, open `chrome://extensions` and turn on **Developer mode**.
2. Click **Load unpacked** and select this project's **`extension` subfolder** (the folder containing `manifest.json`, not the project root).
3. If you already loaded an earlier copy, remove that old copy or click its **Reload** icon after replacing these files.
4. Open a regular `http://` or `https://` webpage, click the Bodyguard puzzle-piece icon, and choose **Check this link**. Pin the extension from the puzzle-piece menu if you want its icon always visible.

The extension uses `https://bodyguard-ai.onrender.com` by default. If you want it to use your local server instead, change `DEFAULT_BACKEND` in `extension/service-worker.js` to `http://localhost:4173` and keep the matching localhost permission in `extension/manifest.json`; then reload the extension. The content script observes tab addresses locally, and the extension sends a URL to the backend only after you click the check button. Chrome's internal pages such as `chrome://extensions` cannot be scanned.

## Publish / host it

The interface and scanner must be hosted together by a server that runs Node.js or Docker. The included `Dockerfile` and `render.yaml` are set up for Render. To publish this edited copy, first push this project folder to a GitHub repository you control, then create a Render Blueprint from that repository and select `render.yaml`. Render will prompt for `GEMINI_API_KEY` on initial Blueprint creation; enter it as a secret in Render, never in the repository. The deployment then builds the Dockerfile and provides an HTTPS `onrender.com` URL. GitHub Pages alone cannot run `server.mjs`, so it cannot host the working scanner backend.

## Files

- `index.html`, `styles.css`, `app.js` — accessible responsive scanner interface.
- `server.mjs` — static web server, guarded public-site fetcher, and page-risk analyzer.
- `.env.example` — server-side Gemini and listener configuration.
- `extension/` — Chrome Manifest V3 content script, service worker, and popup.
- `engine/` — optional standalone C++ policy example; the live scanner currently runs in Node.js and does not use this CLI.
- `Dockerfile`, `.dockerignore` — container deployment configuration.

