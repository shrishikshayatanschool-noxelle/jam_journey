# Bodyguard — live website safety checker

Bodyguard lets a user paste a public website address and get a risk report before opening that site. It follows public redirects, checks Google Safe Browsing when configured, and inspects static HTML and supported public content through Gemini when configured. It accepts a bare domain (`example.com`) or a full URL.

## The idea, simply

Think of Bodyguard as a checkpoint before you open a link. It follows the route, checks Google's known-threat lists, looks for suspicious page signals, and shows what it found. It never promises that a site is completely safe. If an important check cannot run, the verdict is **incomplete / unverified**.

The homepage presents that process as a four-stop adventure: **Follow the trail → Check the threat map → Inspect the scene → Choose your exit**. The sample buttons fill in an address; they do not open it or scan it until the user presses **Check link**.

## Try it with sample addresses

- **Malayalam news page:** <https://www.manoramaonline.com/>. This is an ordinary public Malayalam-language site to try the scan flow; a clean result is not a safety guarantee.
- **Safe Browsing simulation:** <https://testsafebrowsing.appspot.com/s/malware.html>. This is a Google test page intended to trigger a malware warning in supported Safe Browsing checks. It is a simulation, not an actual malware download. Paste it into Bodyguard; do not click any download on that page.
- **More Google test pages:** <https://testsafebrowsing.appspot.com/>. Google labels the pages there as test links for phishing, malware, and other browser warnings.

Never use an actual malware or phishing website as a test. Use the Google test pages above.

## Start it

Requirements: Node.js 18 or later. The scanner has no third-party package dependencies and needs outbound DNS and HTTP/HTTPS access to scan public sites.

1. Download or clone the project.
2. Open a terminal in the project folder.
3. Run `node server.mjs`.
4. Open <http://localhost:4173> and paste a public website address.

The service binds to `127.0.0.1` by default, so it is only available on your computer. It fetches public pages through its own backend; opening `index.html` directly with `file://` will not run a scan.

## Connect real reputation and AI checks

Without `SAFE_BROWSING_API_KEY`, Bodyguard cannot check Google's known phishing and malware URL lists. In that state it reports results as **incomplete / unverified**, rather than claiming the link is safe. For a public Render service, add keys under **Render Dashboard → bodyguard-ai → Environment** (keep them server-side; never place them in `app.js`, `index.html`, GitHub, or a public message):

- `SAFE_BROWSING_API_KEY` — Google Safe Browsing API key. The scanner uses v4 `threatLists` plus `threatMatches:find` for direct URL lookups and falls back to the v5 URL search endpoint if v4 is unavailable. Enable the Safe Browsing API for a Google Cloud project and create a key. The API is for non-commercial use and should be used according to Google's terms.
- `GEMINI_API_KEY` — optional Gemini API key from Google AI Studio. Gemini uses URL Context to review supported public HTML, text, JSON, CSS, JavaScript, images, and PDF URLs. This is a supplementary AI review, not a malware reputation database, and it can make mistakes.
- `GEMINI_MODEL` — optional; defaults to `gemini-3.8-flash`.

After saving Render environment variables, Render restarts the service. Use the deployed site and look at the **Google Safe Browsing** and **Gemini page review** rows to see which checks actually completed. A blocked or unavailable check is not a clean result. Google may receive submitted URLs when Safe Browsing is enabled; Gemini may retrieve public URLs when its key is enabled. Avoid scanning private, signed, or access-token links.

## What it checks

- HTTP versus HTTPS and whether the HTTPS certificate validates.
- Redirect count, destination, and HTTP downgrade.
- Checked consent boxes located near recurring billing or trial language.
- Inline invisible fixed/absolute elements that could cover page controls.
- Download, cancel, close, and dismiss labels paired with suspicious script or redirect destinations.
- Page text that resembles prompt injection or requests for private agent data.
- Punycode or IP-based addresses, password inputs sent over HTTP, security headers, scripts, and frames.

Results say **dangerous**, **suspicious**, **caution**, **incomplete / unverified**, or **no listed threats or major page risks found**, and show the evidence behind each signal. A clean scan means only that configured checks found no known URL-list match and no major signals in the content they inspected; it is not a certificate of safety.

## Important coverage limits

The v4 `threatListUpdates:fetch` endpoint is for clients that maintain a local, persistent hash database and apply encoded list deltas (with additional full-hash checks). This web service uses the direct Lookup API instead; calling the update endpoint alone would not check a URL. The scanner does not execute the target site's JavaScript or render its layout. Dynamic overlays and behaviors that require a browser session can therefore be missed. Gemini URL Context can review supported public content types when enabled, but it does not turn this app into a browser extension and cannot guarantee a site is safe. Safe Browsing checks known listed threats; newly created or unlisted threats may not appear. Do not treat the result as a substitute for browser protections.

Scanning sends the address to the Bodyguard server so that server can fetch the page. The app does not save scan history. When configured, the submitted address is sent to Google Safe Browsing and/or Gemini as described above. The server refuses private/reserved IP ranges, nonstandard ports, userinfo URLs, and redirects into private networks. It caps response size, request time, scan concurrency, and scan frequency.

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

