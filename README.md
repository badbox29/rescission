# Rescission

Restore the original destination of protected URLs.

A browser-based pipeline tool that decodes, cleans, resolves, and inspects security-wrapped URLs — without sending anything to a server. Paste a Proofpoint, Safe Links, Barracuda, Mimecast, or any other wrapped link and get the real destination back, along with a full breakdown of what was done to get there.

Designed for security analysts, mail administrators, and technically capable users who need to know where a link actually goes before clicking it.

#### Screenshot
![Screenshot](screenshot.png)

#### Live Demo
[https://badbox29.github.io/rescission/](https://badbox29.github.io/rescission/)

---

## Features

### Processing Pipeline

Rescission processes URLs through up to four sequential stages. Each stage can be individually enabled or disabled via pill toggles directly under the input field. Stages run in order and pass their output to the next — so a decoded URL gets cleaned, the clean URL gets resolved, and the final URL gets inspected.

#### Stage 1 — Decode
Unwraps security-rewritten URLs from known email security services, recovering the original destination embedded in the link. Handles nested wrappers (e.g. a Safe Links URL wrapping a Proofpoint URL) by iterating until no further decoding is possible, up to 10 layers deep.

Each decode attempt is reported as a step with one of three outcomes:
- **Decoded** — the original URL was successfully recovered
- **Opaque token** — the service was detected but the URL is a server-side-only redirect that cannot be recovered locally
- **No wrappers detected** — the URL does not match any known service

**Supported services:**

| Service | Decode type | Verified |
|---|---|---|
| Proofpoint URL Defense v3 | Full decode | ✓ |
| Proofpoint URL Defense v2 | Full decode | ✓ |
| Microsoft Safe Links | Full decode | ✓ |
| Barracuda Email Security | Full decode | ✓ |
| Mimecast URL Protect | Full decode (modern format) / opaque (legacy) | ✓ |
| Cisco Umbrella | Detect only (opaque token) | ✓ |
| Google Redirect | Full decode | ✓ |
| Symantec / Broadcom Email Security | Full decode | — |
| Trend Micro IMSVA | Full decode | — |
| Check Point Email Security | Detect only | — |
| Generic redirect params | Full decode (`url=`, `target=`, `dest=`, `redirect=`, and others) | — |

Verified services have been tested against real-world links and confirmed to produce correct output. Unverified services are implemented based on documented formats but have not been validated against live samples.

The Proofpoint v3 decoder correctly handles the run-length `**X` token format and applies the full replacement character map in the correct forward order. The v2 decoder uses scoped hex replacement (`-XX` → `%XX`) with a fail-closed validator to avoid emitting corrupted output on partial matches.

#### Stage 2 — Clean
Removes noise from the URL that serves tracking or monetization purposes rather than identifying the actual content. Reports each action taken with a `removed`, `changed`, `kept`, or `none` badge.

**Tracking parameter removal** — strips ~50 known tracking query parameters including:
- UTM family (`utm_source`, `utm_medium`, `utm_campaign`, `utm_term`, `utm_content`, and extended variants)
- Google Ads / Analytics (`gclid`, `gbraid`, `wbraid`, `dclid`, `gad_source`, `_ga`, `_gl`)
- Meta / Facebook (`fbclid`, `fb_action_ids`, `fb_source`)
- Microsoft / Bing (`msclkid`)
- LinkedIn (`li_fat_id`)
- Twitter / X (`twclid`)
- TikTok (`ttclid`)
- HubSpot (`_hsmi`, `_hsenc`, `hsCtaTracking`)
- Marketo (`mkt_tok`)
- Mailchimp (`mc_cid`, `mc_eid`)
- Sailthru, Adobe, and others

**Affiliate tag removal** *(optional sub-toggle)* — removes monetization and referral parameters such as `tag`, `aff`, `affiliate`, `aff_id`, Amazon associate tags, and similar partner tracking values.

**Normalization:**
- Removes default ports (`:80` for HTTP, `:443` for HTTPS, `:21` for FTP)
- Collapses duplicate slashes in the URL path
- Lowercases the hostname

#### Stage 3 — Resolve
Follows redirects to find the final destination, with honest reporting about what can and cannot be determined locally.

- **Short URL detection** — identifies links from known URL shorteners (bit.ly, t.co, tinyurl.com, youtu.be, amzn.to, and ~30 others) and flags them for expansion
- **Redirect chain** — displays each hop from source to destination with labels and status
- **Network resolution** — follows redirects via the allorigins.win CORS proxy; the card renders immediately and updates in place when the network result returns
- Reports errors clearly (timeout, proxy failure) and explains that this stage requires an outbound network request, unlike the other stages which run entirely locally

#### Stage 4 — Inspect
Breaks the URL down into its structural components and evaluates it for security signals.

**URL breakdown:**
- Scheme, host, subdomain, TLD / registrable domain
- Port (with default vs. explicit distinction)
- Path, query string, fragment

**Query parameters table** — lists every parameter and its decoded value.

**Security indicators** — flags conditions worth noting:
- HTTPS vs. plain HTTP
- IDN / Punycode hostname (potential homograph attack)
- IP address used as hostname
- Excessive subdomain depth
- Suspicious TLD (`.tk`, `.ml`, `.xyz`, `.click`, and others commonly associated with phishing)
- Credentials embedded in the URL (`user:pass@host`)
- Non-standard port
- Unusually long URL (>400 characters, common in obfuscated links)
- High query parameter count (>8)

Each indicator is color-coded: green (safe), amber (worth noting), red (potential issue), blue (informational).

---

### Input & Controls

- **Source URL field** — paste any URL; multi-line for long wrapped links
- **Stage toggles** — pill buttons under the input field enable/disable individual pipeline stages
- **Affiliate sub-toggle** — appears under the Clean toggle when Clean is active; off by default
- **Process URL button** — runs the pipeline (also triggered by Ctrl/Cmd + Enter)
- **Reset button** — clears input and results

---

### Results Display

- Each stage produces a collapsible result card with a summary visible in the header — no need to expand to see the key finding
- Cards expand/collapse by clicking the header
- Every URL output in the results has **Copy** and **Open** actions
- A **pipeline status bar** updates live as stages complete, showing running / done / error / skipped state per stage
- The Resolve card updates in place when the async network result arrives, without re-rendering other cards

---

### Theme

- Dark mode by default; full light mode available via the toggle in the header
- Theme preference persisted to `localStorage`

---

### Privacy

All processing — decoding, cleaning, URL parsing, and security analysis — happens entirely in your browser. Nothing is transmitted anywhere. The only outbound request Rescission makes is the redirect-following step in the Resolve stage, which uses the allorigins.win CORS proxy. That stage can be disabled via its toggle if you prefer fully local operation.

---

## Usage

This is a three-file static tool — no build tools, no dependencies, no server required.

1. Open `index.html` in any modern browser (or serve from any static host)
2. Paste a URL into the **Source URL** field
3. Enable or disable stages as needed using the toggles
4. Click **Process URL**

Results appear below the input, one card per stage, in processing order.

---

## File Structure

```
rescission/
  index.html        ← markup shell; no inline scripts or styles
  css/
    styles.css      ← full theme system and all component styles
  js/
    app.js          ← decode, clean, resolve, and inspect engines + UI controller
```

The JavaScript has no external dependencies and does not use any framework. It runs in any modern browser without a build step.

---

## Hosting

Serve the three files from any static host maintaining the directory structure. GitHub Pages, Cloudflare Pages, Netlify, or a local web server all work.

**GitHub Pages example:**
1. Push the `rescission/` directory to a repository
2. Go to Settings → Pages → Source → select branch
3. Access at `https://yourusername.github.io/yourrepo/`

---

## Decoder Implementation Notes

### Proofpoint v2
Encoding scheme: a bare underscore (`_`) represents a forward slash; a hyphen followed by two hex digits (`-XX`) is a percent-encoded byte (including a literal hyphen encoded as `-2D`). The replacement is scoped to the `-XX` pattern to avoid corrupting legitimate hyphens in domain names and paths. The decoded result is validated before being returned; if it does not parse as a plausible URL, the decoder reports failure rather than emitting garbled output.

### Proofpoint v3
The encoded URL is base64url-encoded with special characters replaced by `*` markers (single replacement) or `**X` run-length tokens (where `X` maps to a repeat count via a defined character map: A=2…Z=27, a=28…z=53, 0=54…9=63, `-`=64, `_`=65). Replacements are applied in forward order against the sequence of special characters (`!*'();:@&=+$,/?#[]%`). The decoder implements the full run-length logic; an earlier implementation that omitted `**X` handling would produce corrupted output on any URL with consecutive special characters in the query string.

### Mimecast
Modern Mimecast links embed the destination URL in a `u=` query parameter (URL-encoded). Older links use an opaque path-based token that is a server-side-only redirect — the original URL is not present in the link and cannot be recovered locally. When an opaque token is detected, the tool reports this honestly rather than returning a wrong result.

### Nested wrappers
The decode stage iterates up to 10 times, passing each successfully decoded URL back through the full service registry. This handles real-world cases like a Safe Links link wrapping a Proofpoint link, which in turn wraps the actual destination.

---

## Security Indicator Reference

| Indicator | Severity | Meaning |
|---|---|---|
| HTTPS | ✓ Safe | Connection is encrypted in transit |
| Not HTTPS | ✗ Bad | Plain HTTP — contents and destination unencrypted |
| IDN / Punycode domain | ⚠ Warn | Domain uses internationalized characters; possible homograph phishing attack |
| IP address host | ⚠ Warn | Hostname is a raw IP address rather than a domain name |
| Subdomain depth > 4 | ⚠ Warn | Unusual number of subdomain levels; sometimes used to make fake domains look legitimate |
| Suspicious TLD | ⚠ Warn | TLD commonly associated with free/low-cost registrations and phishing infrastructure |
| Credentials in URL | ✗ Bad | Username and/or password embedded in the URL (`user:pass@host`) |
| Non-standard port | ⚠ Warn | Port differs from the protocol default |
| Long URL | ℹ Info | URL exceeds 400 characters; long URLs are sometimes used to obscure the actual destination |
| Many query parameters | ℹ Info | More than 8 query parameters; worth reviewing individually |

---

## Notes on the Resolve Stage

Redirect following requires an HTTP request, which browsers block cross-origin without CORS headers. Rescission uses allorigins.win as a CORS proxy to work around this. Implications:

- The proxy sees the URL being resolved (though not the context or user identity)
- The proxy may be rate-limited or unavailable
- Resolution times out after 8 seconds

If fully local operation is required, disable the Resolve stage. The Decode stage alone recovers the destination from all supported services that embed the URL in the link itself. For services that use opaque server-side tokens (Cisco Umbrella, some Mimecast configurations, Check Point), following the link is the only way to find the final destination.

---

## Version

v2.0

---

## License

See LICENSE file.
