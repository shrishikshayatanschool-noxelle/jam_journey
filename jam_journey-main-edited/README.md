# Bodyguard — live website safety checker

Bodyguard lets a user paste a public website address and get a risk report before opening it. The backend checks its public HTTP response and HTML, then asks Gemini to assess the URL string for scam and phishing patterns. The Gemini API key stays on the server.

Use the theme control in the header to switch between light and dark mode. Bodyguard remembers the choice in the current browser.

## Start it

Requirements: Node.js 18 or later, outbound DNS and HTTP/HTTPS access to inspect public sites, and a Gemini API key for AI URL analysis.

1. Download or clone the project.
2. Open a terminal in the project folder.
3. Copy `.env.example` to `.env` and set `GEMINI_API_KEY` (Gemini analysis is omitted if no key is set).
4. Run `node server.mjs`.
5. Open <https://bodyguard-ai.onrender.com/> and paste a public website address.

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

This version fetches public HTML but does not execute the target site's JavaScript or render its layout. It cannot see traps created only after scripts run, external stylesheets, canvas or image-only content, or behavior requiring a browser session. Gemini evaluates only the URL text; it does not browse the destination and its assessment is heuristic, not proof of safety. Bodyguard does not query Google Safe Browsing, VirusTotal, or another reputation database. Do not treat results as a substitute for browser protections.

Scanning sends the address to the Bodyguard server, which fetches the public page and sends the URL string to Gemini when configured. The page HTML is not sent to Gemini. Since the URL string can include its path and query parameters, do not scan links containing private tokens or other secrets. The server refuses private/reserved IP ranges, nonstandard ports, userinfo URLs, and redirects into private networks. It caps response size, request time, scan concurrency, and scan frequency. The extension observes page URLs locally and contacts the backend only after the user clicks its check button.

## Browser extension (Chrome / Chromium)

1. Start the backend as above.
2. Open `chrome://extensions`, enable **Developer mode**, choose **Load unpacked**, and select the `extension` folder.
3. Open a regular webpage, click the Bodyguard toolbar icon, and choose **Check link**.

The content script reports the current tab URL to the extension service worker. The worker stores it locally; it submits a scan only after an explicit popup click. For a hosted backend, update `DEFAULT_BACKEND` in `extension/service-worker.js` and the matching `host_permissions` in `extension/manifest.json` to the deployed origin. The API enables CORS for this extension call; deploy behind HTTPS and retain the API's rate limiting.

## Publish / host it

The interface and scanner must be hosted together by a server that runs Node.js or Docker. The included `Dockerfile` is ready to build a container. On a container host, configure the service to use its supplied `PORT` and set `TRUST_PROXY=1` only when the host sits behind its own trusted reverse proxy. Allow outbound DNS and HTTPS so scans can reach public sites. Use the host's HTTPS URL for the public website.

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https%3A%2F%2Fgithub.com%2Fshrishikshayatanschool-noxelle%2Fjam_journey)

To make your own public scanner URL, click **Deploy to Render**, sign in or create a Render account, review the `bodyguard-ai` web service, then click **Apply**. Render builds the Dockerfile and gives the service an `onrender.com` HTTPS address that anyone can open. The free service may sleep when unused and take a short time to wake on the next visit. The service is created in your Render account; the repository only stores the code and deployment settings.

GitHub stores the source code; GitHub Pages alone cannot run `server.mjs`, so a Pages URL would show the interface without a working scanner backend. The Render button above deploys both the interface and scanner server together.

## Files

- `index.html`, `styles.css`, `app.js` — accessible responsive scanner interface.
- `server.mjs` — static web server, guarded public-site fetcher, and page-risk analyzer.
- `.env.example` — server-side Gemini and listener configuration.
- `extension/` — Chrome Manifest V3 content script, service worker, and popup.
- `engine/` — optional standalone C++ policy example; the live scanner currently runs in Node.js and does not use this CLI.
- `Dockerfile`, `.dockerignore` — container deployment configuration.

