/**
 * Rescission — Cloudflare Worker
 * Redirect resolution proxy for the Rescission URL analysis tool.
 *
 * Deploy on Cloudflare Workers (free tier is sufficient).
 * Set the ALLOWED_ORIGINS environment variable to your site's origin,
 * e.g. https://badbox29.github.io — requests from any other origin
 * will be rejected with 403.
 *
 * Routes:
 *   GET  /health          → 200 { ok: true, version: "1.0" }
 *   GET  /resolve?url=…   → 200 { hops: [...], finalUrl, duration_ms }
 *
 * Each hop in the chain:
 *   { url, status, statusText, location?, contentType?, server? }
 *
 * Configuration (Cloudflare dashboard → Worker → Settings → Variables):
 *   ALLOWED_ORIGINS  Required. One or more origins, comma-separated.
 *                    e.g. https://badbox29.github.io, http://localhost:5500
 *                    Each request Origin is checked against this list; the
 *                    matching value is reflected in Access-Control-Allow-Origin
 *                    (the header only ever contains a single origin value).
 *   MAX_HOPS         Optional. Max redirects to follow (default: 10)
 *   TIMEOUT_MS       Optional. Per-hop fetch timeout in ms (default: 5000)
 */

const DEFAULT_MAX_HOPS  = 10;
const DEFAULT_TIMEOUT   = 5000;

export default {
  async fetch(request, env) {
    // Parse ALLOWED_ORIGINS as a comma-separated list, trim each entry.
    const allowedOrigins = (env.ALLOWED_ORIGINS || '')
      .split(',')
      .map(o => o.trim().replace(/\/$/, ''))
      .filter(Boolean);

    const maxHops   = parseInt(env.MAX_HOPS   || DEFAULT_MAX_HOPS, 10);
    const timeoutMs = parseInt(env.TIMEOUT_MS || DEFAULT_TIMEOUT,  10);

    /* ── CORS pre-flight ── */
    const origin = request.headers.get('Origin') || '';
    const corsHeaders = buildCorsHeaders(origin, allowedOrigins);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    /* ── Origin guard ── */
    // If ALLOWED_ORIGINS is configured, the request origin must be in the list.
    // Requests with no Origin header (direct curl / health checks) bypass the
    // CORS check but still reach the route handlers — fine for server-to-server.
    if (allowedOrigins.length && origin && !allowedOrigins.includes(origin)) {
      return json({ error: 'Origin not allowed.' }, 403, corsHeaders);
    }

    const url = new URL(request.url);

    /* ── /health ── */
    if (url.pathname === '/health') {
      return json({ ok: true, version: '1.0', origins: allowedOrigins.length ? allowedOrigins : ['(any)'] }, 200, corsHeaders);
    }

    /* ── /resolve ── */
    if (url.pathname === '/resolve') {
      const target = url.searchParams.get('url');
      if (!target) {
        return json({ error: 'Missing required parameter: url' }, 400, corsHeaders);
      }

      // Basic sanity check — must be http/https
      let parsed;
      try {
        parsed = new URL(target);
        if (!['http:', 'https:'].includes(parsed.protocol)) {
          return json({ error: 'Only http and https URLs are supported.' }, 400, corsHeaders);
        }
      } catch {
        return json({ error: 'Invalid URL.' }, 400, corsHeaders);
      }

      const start = Date.now();
      const result = await followRedirects(target, maxHops, timeoutMs);
      result.duration_ms = Date.now() - start;

      return json(result, result.error ? 502 : 200, corsHeaders);
    }

    return json({ error: 'Not found.' }, 404, corsHeaders);
  },
};

/* ── Redirect follower ───────────────────────────────────────────────── */

async function followRedirects(startUrl, maxHops, timeoutMs) {
  const hops = [];
  let currentUrl = startUrl;
  const visited   = new Set();

  for (let i = 0; i < maxHops; i++) {
    if (visited.has(currentUrl)) {
      // Loop detected
      hops.push({ url: currentUrl, status: null, statusText: 'Loop detected', error: true });
      break;
    }
    visited.add(currentUrl);

    let resp;
    try {
      resp = await fetchWithTimeout(currentUrl, timeoutMs);
    } catch (e) {
      hops.push({ url: currentUrl, status: null, statusText: String(e.message || e), error: true });
      break;
    }

    const hop = {
      url:         currentUrl,
      status:      resp.status,
      statusText:  resp.statusText || statusLabel(resp.status),
      contentType: (resp.headers.get('content-type') || '').split(';')[0].trim() || null,
      server:      resp.headers.get('server') || null,
    };

    // Consume body to free the connection, but don't store it
    try { await resp.arrayBuffer(); } catch { /* ignore */ }

    if (resp.redirected) {
      // Cloudflare Workers' fetch() follows redirects by default and sets resp.url
      // to the final URL. To capture the chain we must use redirect: 'manual'.
      // But we already used the default — resp.url is the actual final URL.
      // We need redirect: 'manual' to see each hop individually.
      // Re-implement below.
    }

    hops.push(hop);

    // 2xx — done
    if (resp.status >= 200 && resp.status < 300) break;

    // 3xx — follow Location
    if (resp.status >= 300 && resp.status < 400) {
      const location = resp.headers.get('location');
      if (!location) {
        hop.error = true;
        hop.statusText = `${resp.status} redirect with no Location header`;
        break;
      }
      // Resolve relative redirects
      try {
        currentUrl = new URL(location, currentUrl).href;
        hop.location = currentUrl;
      } catch {
        hop.error = true;
        hop.statusText = `Invalid Location header: ${location}`;
        break;
      }
      continue;
    }

    // 4xx / 5xx — stop, report error hop
    hop.final = true;
    break;
  }

  const lastHop    = hops[hops.length - 1];
  const finalUrl   = lastHop?.url || startUrl;
  const hasError   = hops.some(h => h.error);

  return { hops, finalUrl, error: hasError ? lastHop?.statusText : null };
}

async function fetchWithTimeout(url, timeoutMs) {
  // Use redirect: 'manual' so we see each 3xx individually
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(url, {
      redirect: 'manual',
      signal:   controller.signal,
      headers: {
        // Impersonate a browser enough to get through simple bot blocks
        'User-Agent': 'Mozilla/5.0 (compatible; Rescission/1.0; redirect-checker)',
        'Accept':     'text/html,application/xhtml+xml,*/*;q=0.9',
      },
    });
    return resp;
  } catch (e) {
    if (e.name === 'AbortError') throw new Error('Request timed out');
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

/* ── Utilities ───────────────────────────────────────────────────────── */

function buildCorsHeaders(requestOrigin, allowedOrigins) {
  // Reflect the requesting origin if it's in the allowed list; otherwise '*'
  // (only reached when the list is empty / no ALLOWED_ORIGINS is configured).
  const acao = allowedOrigins.includes(requestOrigin) ? requestOrigin
             : allowedOrigins.length === 0            ? (requestOrigin || '*')
             : allowedOrigins[0];   // fallback: first entry (blocked upstream anyway)
  return {
    'Access-Control-Allow-Origin':  acao,
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age':       '86400',
    'Vary':                         'Origin',
  };
}

function json(data, status, corsHeaders) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders },
  });
}

function statusLabel(code) {
  const labels = {
    200: 'OK', 201: 'Created', 204: 'No Content',
    301: 'Moved Permanently', 302: 'Found', 303: 'See Other',
    307: 'Temporary Redirect', 308: 'Permanent Redirect',
    400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden',
    404: 'Not Found', 410: 'Gone', 429: 'Too Many Requests',
    500: 'Internal Server Error', 502: 'Bad Gateway', 503: 'Service Unavailable',
  };
  return labels[code] || `HTTP ${code}`;
}
