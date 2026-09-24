# Bodyguard — live website safety checker

Bodyguard lets a user paste a public website address and get a live, evidence-based risk report before opening that site. Unlike the earlier controlled demonstration, scans now fetch the address the user enters and inspect its public HTTP response and HTML.

## Start it

Requirements: Node.js 18 or later. The scanner has no third-party package dependencies and needs outbound DNS and HTTP/HTTPS access to scan public sites.

1. Download or clone the project.
2. Open a terminal in the project folder.
3. Run `node server.mjs`.
4. Open <http://localhost:4173> and paste a public website address.

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

This version fetches the initial public HTML and does not execute the target site's JavaScript or render its layout. As a result, it cannot see traps that are created only after scripts run, external stylesheets, canvas or image-only content, or behavior that requires a browser session. It is a live static page inspector, not yet a Chrome interstitial or extension that guards navigation. It also does not query Google Safe Browsing, VirusTotal, or another malware/phishing reputation database. Do not treat the result as a substitute for browser protections.

Scanning sends the address to the Bodyguard server so that server can fetch the page. The tool does not save scan history or forward the page to an external reputation service. The server refuses private/reserved IP ranges, nonstandard ports, userinfo URLs, and redirects into private networks. It caps response size, request time, scan concurrency, and scan frequency.

## Publish / host it

The interface and scanner must be hosted together by a server that runs Node.js or Docker. The included `Dockerfile` is ready to build a container. On a container host, configure the service to use its supplied `PORT` and set `TRUST_PROXY=1` only when the host sits behind its own trusted reverse proxy. Allow outbound DNS and HTTPS so scans can reach public sites. Use the host's HTTPS URL for the public website.

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https%3A%2F%2Fgithub.com%2Fshrishikshayatanschool-noxelle%2Fjam_journey)

To make your own public scanner URL, click **Deploy to Render**, sign in or create a Render account, review the `bodyguard-ai` web service, then click **Apply**. Render builds the Dockerfile and gives the service an `onrender.com` HTTPS address that anyone can open. The free service may sleep when unused and take a short time to wake on the next visit. The service is created in your Render account; the repository only stores the code and deployment settings.

GitHub stores the source code; GitHub Pages alone cannot run `server.mjs`, so a Pages URL would show the interface without a working scanner backend. The Render button above deploys both the interface and scanner server together.

## Files

- `index.html`, `styles.css`, `app.js` — accessible responsive scanner interface.
- `server.mjs` — static web server, guarded public-site fetcher, and page-risk analyzer.
- `engine/` — optional standalone C++ policy example; the live scanner currently runs in Node.js and does not use this CLI.
- `Dockerfile`, `.dockerignore` — container deployment configuration.

