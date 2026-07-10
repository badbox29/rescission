/* =====================================================================
   Rescission — app.js
   Restore the original destination of protected URLs.
   ===================================================================== */
'use strict';

/* ══════════════════════════════════════════════════════════════════════
   DECODE ENGINE
   ══════════════════════════════════════════════════════════════════════ */

/** UTF-8-safe base64 decode. Tolerates base64url and missing padding. */
function b64decode(input) {
  let s = String(input).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  try {
    return new TextDecoder('utf-8').decode(Uint8Array.from(bin, c => c.charCodeAt(0)));
  } catch (e) { return bin; }
}

/** decodeURIComponent that never throws. */
function safeDecode(str) {
  try { return decodeURIComponent(str); } catch (e) { return str; }
}

/** Extract a named query parameter (case-insensitive) from a URL string. */
function getParam(url, name) {
  const m = url.match(new RegExp('[?&]' + name + '=([^&#]+)', 'i'));
  return m ? m[1] : null;
}

/** Loose URL plausibility check — must start with http/https or look like a domain. */
function isValidUrl(s) {
  if (!s) return false;
  s = s.trim();
  if (!s || /\s/.test(s)) return false;
  return /^https?:\/\/[^\s]+\.[^\s]/i.test(s)
    || /^\/\/[^\s]+\.[^\s]/.test(s)
    || /^[a-z0-9.-]+\.[a-z]{2,}([/?#].*)?\s*$/i.test(s);
}

/** Ensure a URL has a scheme. */
function ensureScheme(url) {
  if (!url) return url;
  if (/^https?:\/\//i.test(url)) return url;
  if (url.startsWith('//')) return 'https:' + url;
  return 'https://' + url;
}

/* ── Proofpoint v2 ──────────────────────────────────────────────────── */
// Encoding: bare '_' → '/', '-XX' → percent-encoded byte (incl. '-' as -2D)
function decodeProofpointV2(url) {
  const raw = getParam(url, 'u');
  if (!raw) return null;
  const decoded = safeDecode(raw.replace(/-([0-9A-Fa-f]{2})/g, '%$1').replace(/_/g, '/'));
  return isValidUrl(decoded) ? decoded : null;
}

/* ── Proofpoint v3 ──────────────────────────────────────────────────── */
// v3 has two formats:
//
// A) Passthrough / plain: the URL is embedded directly between __ delimiters
//    e.g. https://urldefense.com/v3/__https://example.com/path__;!!abc==
//    The URL sits between the first __ and the trailing __;
//
// B) Encoded: the 'u' query param holds a base64url-encoded string where
//    special chars are replaced by '*' markers (single) or '**X' run-length
//    tokens. runmap: A=2…Z=27, a=28…z=53, 0=54…9=63, '-'=64, '_'=65
function decodeProofpointV3(url) {
  /* ── Format A: passthrough __url__; ── */
  // Proofpoint v3 passthrough embeds the URL between __ delimiters:
  //   /v3/__https*//example.com/path__;!!token!
  // The scheme colon ':' is encoded as '*'. Path slashes are encoded as '_'.
  // Restore: '*' after scheme -> ':', then remaining '_' -> '/'
  const passthrough = url.match(/\/v3\/__([^_].*?)__;/);
  if (passthrough) {
    let candidate = passthrough[1];
    // Restore scheme colon: 'https*' or 'http*' -> 'https:' / 'http:'
    candidate = candidate.replace(/^(https?)\*/, '$1:');
    // Restore path slashes: '_' -> '/'
    candidate = candidate.replace(/_/g, '/');
    if (isValidUrl(candidate)) return candidate;
    // Fallback: colon omitted entirely in some older passthrough variants
    const withColon = candidate.replace(/^(https?)(\/\/)/, '$1:$2');
    if (isValidUrl(withColon)) return withColon;
  }

  /* ── Format B: encoded u= param ── */
  const raw = getParam(url, 'u');
  if (!raw) return null;
  try {
    const encoded = b64decode(raw);
    const SPECIALS = '!*\'();:@&=+$,/?#[]%';
    let specIndex = 0;
    const runmap = {};
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('').forEach((c, i) => { runmap[c] = i + 2; });
    'abcdefghijklmnopqrstuvwxyz'.split('').forEach((c, i) => { runmap[c] = i + 28; });
    '0123456789'.split('').forEach((c, i) => { runmap[c] = i + 54; });
    runmap['-'] = 64; runmap['_'] = 65;

    let result = '';
    let i = 0;
    while (i < encoded.length) {
      if (encoded[i] === '*') {
        if (encoded[i + 1] === '*') {
          const runChar = encoded[i + 2];
          const count = runmap[runChar] || 1;
          for (let r = 0; r < count; r++) {
            result += SPECIALS[specIndex % SPECIALS.length];
            specIndex++;
          }
          i += 3;
        } else {
          result += SPECIALS[specIndex % SPECIALS.length];
          specIndex++;
          i++;
        }
      } else {
        result += encoded[i];
        i++;
      }
    }
    return isValidUrl(result) ? result : null;
  } catch (e) { return null; }
}

/* ── Microsoft Safe Links ───────────────────────────────────────────── */
// safelinks.protection.outlook.com → url param, base64-encoded
function decodeSafeLinks(url) {
  const raw = getParam(url, 'url');
  if (!raw) return null;
  try {
    const decoded = safeDecode(raw);
    if (isValidUrl(decoded)) return decoded;
    // Try base64
    const b64 = b64decode(decoded);
    return isValidUrl(b64) ? b64 : null;
  } catch (e) { return null; }
}

/* ── Barracuda ──────────────────────────────────────────────────────── */
// linkprotect.cudasvc.com → 'a' param holds the URL, URL-encoded
function decodeBarracuda(url) {
  const raw = getParam(url, 'a');
  if (!raw) return null;
  const decoded = safeDecode(raw);
  return isValidUrl(decoded) ? decoded : null;
}

/* ── Mimecast ───────────────────────────────────────────────────────── */
// mimecastprotect.com or eu/de/au.mimecastprotect.com
// Modern format uses the 'u' param (URL-encoded). Some older tokens are opaque.
function decodeMimecast(url) {
  const u = getParam(url, 'u');
  if (u) {
    const decoded = safeDecode(u);
    if (isValidUrl(decoded)) return decoded;
  }
  // Older format may embed in path: /s/…/<base64>/…
  const pathMatch = url.match(/\/s\/[^/]+\/([A-Za-z0-9+/=_-]{20,})/);
  if (pathMatch) {
    try {
      const decoded = b64decode(pathMatch[1]);
      if (isValidUrl(decoded)) return decoded;
    } catch (e) {}
  }
  return { partial: true, note: 'Mimecast opaque token — original URL is server-side only. Visit the link to see the destination.' };
}

/* ── Cisco Umbrella / OpenDNS ───────────────────────────────────────── */
function decodeUmbrella(url) {
  // Umbrella rewrites: often proxied via cloud.cisco.com; url in 'url' param
  const raw = getParam(url, 'url') || getParam(url, 'u');
  if (raw) {
    const decoded = safeDecode(raw);
    if (isValidUrl(decoded)) return decoded;
  }
  return { partial: true, note: 'Umbrella link — token is opaque. Original URL cannot be recovered locally.' };
}

/* ── Symantec / Broadcom Email Security (MessageLabs) ──────────────── */
// mlsec.io rewrites: URL encoded in 'u' param
function decodeSymantec(url) {
  const raw = getParam(url, 'u');
  if (!raw) return null;
  const decoded = safeDecode(raw);
  return isValidUrl(decoded) ? decoded : null;
}

/* ── Google Safe Browsing Redirect ─────────────────────────────────── */
// google.com/url?q= or &url=
function decodeGoogleRedirect(url) {
  const raw = getParam(url, 'q') || getParam(url, 'url');
  if (!raw) return null;
  const decoded = safeDecode(raw);
  return isValidUrl(decoded) ? decoded : null;
}

/* ── Trend Micro ────────────────────────────────────────────────────── */
// imsva.com / trendmicro.com safe link: URL in 'u' param
function decodeTrendMicro(url) {
  const raw = getParam(url, 'u');
  if (!raw) return null;
  const decoded = safeDecode(raw);
  return isValidUrl(decoded) ? decoded : null;
}

/* ── Generic URL-encoded param fallback ────────────────────────────── */
// Catches FortiGate (url=), Sophos (url=), Avanan, and others
function decodeGenericUrlParam(url) {
  for (const p of ['url', 'target', 'dest', 'destination', 'redirect', 'redir', 'goto', 'link', 'out']) {
    const raw = getParam(url, p);
    if (raw) {
      const decoded = safeDecode(raw);
      if (isValidUrl(decoded)) return decoded;
    }
  }
  return null;
}

/* ── URL-encoded wrapper ────────────────────────────────────────────── */
// Sometimes the entire encoded URL is just URI-encoded at the top level
function decodeUrlEncoding(url) {
  if (!url.includes('%')) return null;
  const decoded = safeDecode(url);
  if (decoded !== url && isValidUrl(decoded)) return decoded;
  return null;
}

/* ── Decode Service Registry ────────────────────────────────────────── */
const DECODE_SERVICES = [
  {
    id:       'proofpoint-v3',
    name:     'Proofpoint URL Defense v3',
    verified: true,
    type:     'decode',
    match:    url => /urldefense\.(?:proofpoint\.)?com\/v3\//i.test(url)
                  || /urldefense\.com\/v3\//i.test(url),
    decode:   decodeProofpointV3,
  },
  {
    id:       'proofpoint-v2',
    name:     'Proofpoint URL Defense v2',
    verified: true,
    type:     'decode',
    match:    url => /urldefense\.(?:proofpoint\.)?com\/v2\//i.test(url)
                  || /urldefense\.com\/v2\//i.test(url),
    decode:   decodeProofpointV2,
  },
  {
    id:       'safelinks',
    name:     'Microsoft Safe Links',
    verified: true,
    type:     'decode',
    match:    url => /safelinks\.protection\.outlook\.com/i.test(url),
    decode:   decodeSafeLinks,
  },
  {
    id:       'barracuda',
    name:     'Barracuda Email Security',
    verified: true,
    type:     'decode',
    match:    url => /linkprotect\.cudasvc\.com/i.test(url),
    decode:   decodeBarracuda,
  },
  {
    id:       'mimecast',
    name:     'Mimecast URL Protect',
    verified: true,
    type:     'decode',
    match:    url => /mimecastprotect\.com/i.test(url),
    decode:   decodeMimecast,
  },
  {
    id:       'cisco-umbrella',
    name:     'Cisco Umbrella',
    verified: true,
    type:     'detect',
    match:    url => /umbrella\.cisco\.com|opendns\.com\/hitcount/i.test(url),
    decode:   decodeUmbrella,
  },
  {
    id:       'symantec',
    name:     'Symantec / Broadcom Email Security',
    verified: false,
    type:     'decode',
    match:    url => /mlsec\.io|messagelabs\.com|symanteccloud\.com/i.test(url),
    decode:   decodeSymantec,
  },
  {
    id:       'google-redirect',
    name:     'Google Redirect',
    verified: true,
    type:     'decode',
    match:    url => /(?:^|[/])(?:www\.)?google\.[a-z.]+\/url\?/i.test(url),
    decode:   decodeGoogleRedirect,
  },
  {
    id:       'trendmicro',
    name:     'Trend Micro IMSVA',
    verified: false,
    type:     'decode',
    match:    url => /imsva\.com|trendmicro\.com\/wis\//i.test(url),
    decode:   decodeTrendMicro,
  },
  {
    id:       'check-point',
    name:     'Check Point Email Security',
    verified: false,
    type:     'detect',
    match:    url => /te\.paloaltonetworks\.com|checkpoint\.com\/url-reputation/i.test(url),
    decode:   () => ({ partial: true, note: 'Check Point opaque token — not locally decodable.' }),
  },
  {
    id:       'generic',
    name:     'Generic URL redirect',
    verified: false,
    type:     'decode',
    match:    url => {
      // Only fire if there's an obvious redirect parameter
      for (const p of ['url', 'target', 'dest', 'destination', 'redirect', 'redir', 'goto', 'link', 'out']) {
        const raw = getParam(url, p);
        if (raw && isValidUrl(safeDecode(raw))) return true;
      }
      return false;
    },
    decode:   decodeGenericUrlParam,
  },
];

/* ── Main Decode Orchestrator ───────────────────────────────────────── */
/**
 * Attempts to decode a URL, handling nested wrappers.
 * Returns an array of decode steps (in order applied).
 */
function decodeUrl(inputUrl) {
  const steps   = [];
  let   current = inputUrl.trim();
  const seen    = new Set();
  let   iter    = 0;
  const MAX     = 10;

  // First try plain URL-encoding at the top level
  const topDecoded = decodeUrlEncoding(current);
  if (topDecoded) {
    steps.push({ service: 'URL Encoding', id: 'url-encoding', verified: true, type: 'decode', result: 'decoded', output: topDecoded, note: 'Percent-decoded outer URL encoding.' });
    current = topDecoded;
  }

  while (iter++ < MAX) {
    if (seen.has(current)) break;
    seen.add(current);

    let matched = false;
    for (const svc of DECODE_SERVICES) {
      if (!svc.match(current)) continue;
      matched = true;
      const result = svc.decode(current);

      if (result === null) {
        steps.push({ service: svc.name, id: svc.id, verified: svc.verified, type: svc.type, result: 'failed', output: null, note: 'Service detected but URL could not be decoded.' });
        break;
      }

      if (typeof result === 'object' && result.partial) {
        steps.push({ service: svc.name, id: svc.id, verified: svc.verified, type: svc.type, result: 'detect', output: null, note: result.note });
        break;
      }

      const decoded = ensureScheme(String(result).trim());
      steps.push({ service: svc.name, id: svc.id, verified: svc.verified, type: svc.type, result: 'decoded', output: decoded, note: null });
      current = decoded;

      // Check if there's another wrapper after decoding
      const innerDecoded = decodeUrlEncoding(current);
      if (innerDecoded && innerDecoded !== current) {
        steps.push({ service: 'URL Encoding', id: 'url-encoding', verified: true, type: 'decode', result: 'decoded', output: innerDecoded, note: 'Nested percent-encoding removed.' });
        current = innerDecoded;
      }
      break;
    }
    if (!matched) break;
  }

  // Final step is the "current" URL after all decoding
  const finalUrl = steps.length
    ? (steps[steps.length - 1].output || inputUrl.trim())
    : inputUrl.trim();

  return { steps, finalUrl, layers: steps.filter(s => s.result === 'decoded').length };
}


/* ══════════════════════════════════════════════════════════════════════
   CLEAN ENGINE
   ══════════════════════════════════════════════════════════════════════ */

/** Known tracking parameters — comprehensive list. */
const TRACKING_PARAMS = new Set([
  // UTM
  'utm_source','utm_medium','utm_campaign','utm_term','utm_content',
  'utm_id','utm_source_platform','utm_creative_format','utm_marketing_tactic',
  // Google Ads / Analytics
  'gclid','gclsrc','gbraid','wbraid','dclid','gad_source',
  '_ga','_gl','_gac','ga_source',
  // Facebook / Meta
  'fbclid','fb_action_ids','fb_action_types','fb_source','fb_ref',
  // Microsoft / Bing
  'msclkid',
  // LinkedIn
  'li_fat_id','li_source','li_medium',
  // Twitter / X
  'twclid',
  // TikTok
  'ttclid',
  // HubSpot
  '_hsmi','_hsenc','hsCtaTracking',
  // Marketo
  'mkt_tok',
  // Mailchimp
  'mc_cid','mc_eid',
  // Mailgun
  'h__',
  // Sailthru
  'sailthru_mid',
  // Adobe
  's_cid','s_kwcid',
  // Generic trackers
  'ref','referrer','source','medium','campaign',
  'clickid','click_id','trk','track','tracking',
  'igshid','nonce',
  // email click trackers
  'email_source','email_campaign','et_rid',
  // YouTube
  'si',
  // Pinterest
  'pt_ref',
  // Snapchat
  'sc_channel',
]);

/** Affiliate/monetization parameters. */
const AFFILIATE_PARAMS = new Set([
  'tag','aff','affiliate','partner','coupon','offer',
  'aff_id','aff_sub','aff_sub2','aff_sub3','aff_sub4','aff_sub5',
  'subid','sub_id','sub1','sub2','sub3',
  'clickref','cr_ref','refcode','refid','ref_id',
  'code','promo','discount','voucher',
  'ClickID','afftrack',
  // Amazon
  'linkCode','tag','ascsubtag','creative','creativeASIN',
]);

/** Default port numbers (protocol → port). */
const DEFAULT_PORTS = { 'http:': '80', 'https:': '443', 'ftp:': '21' };

/**
 * Clean a URL: remove tracking params, normalize, etc.
 * Returns { cleanUrl, changes: [{action, detail, badge}] }
 */
function cleanUrl(inputUrl, opts = {}) {
  const { removeAffiliates = false } = opts;
  const changes = [];

  let parsed;
  try {
    parsed = new URL(inputUrl);
  } catch (e) {
    return { cleanUrl: inputUrl, changes: [{ action: 'Parse error', detail: 'Could not parse URL for cleaning.', badge: 'none' }] };
  }

  /* 1. Remove tracking parameters */
  const removedTracking = [];
  for (const key of [...parsed.searchParams.keys()]) {
    if (TRACKING_PARAMS.has(key) || TRACKING_PARAMS.has(key.toLowerCase())) {
      removedTracking.push(key + '=' + parsed.searchParams.get(key));
      parsed.searchParams.delete(key);
    }
  }
  if (removedTracking.length) {
    changes.push({ action: 'Tracking params removed', detail: removedTracking.join(', '), badge: 'removed' });
  } else {
    changes.push({ action: 'Tracking params', detail: 'None found.', badge: 'none' });
  }

  /* 2. Remove affiliate tags (optional) */
  if (removeAffiliates) {
    const removedAff = [];
    for (const key of [...parsed.searchParams.keys()]) {
      if (AFFILIATE_PARAMS.has(key) || AFFILIATE_PARAMS.has(key.toLowerCase())) {
        removedAff.push(key + '=' + parsed.searchParams.get(key));
        parsed.searchParams.delete(key);
      }
    }
    if (removedAff.length) {
      changes.push({ action: 'Affiliate tags removed', detail: removedAff.join(', '), badge: 'removed' });
    } else {
      changes.push({ action: 'Affiliate tags', detail: 'None found.', badge: 'none' });
    }
  }

  /* 3. Remove default ports */
  if (parsed.port && DEFAULT_PORTS[parsed.protocol] === parsed.port) {
    const old = parsed.port;
    parsed.port = '';
    changes.push({ action: 'Default port removed', detail: `:${old} is implicit for ${parsed.protocol.replace(':', '')}`, badge: 'changed' });
  }

  /* 4. Collapse duplicate slashes in path (not in protocol) */
  const origPath = parsed.pathname;
  const cleanedPath = origPath.replace(/\/\/+/g, '/');
  if (cleanedPath !== origPath) {
    parsed.pathname = cleanedPath;
    changes.push({ action: 'Duplicate slashes removed', detail: `Path: ${origPath} → ${cleanedPath}`, badge: 'changed' });
  }

  /* 5. Lowercase hostname */
  const origHost = parsed.hostname;
  if (origHost !== origHost.toLowerCase()) {
    parsed.hostname = origHost.toLowerCase();
    changes.push({ action: 'Hostname lowercased', detail: origHost, badge: 'changed' });
  }

  /* 6. Remove trailing slash from bare domain (only if no path) */
  if (parsed.pathname === '/' && !parsed.search && !parsed.hash) {
    // keep the slash — stripping it can break some servers. Just note.
    changes.push({ action: 'Trailing slash', detail: 'Preserved (root path is canonical).', badge: 'kept' });
  }

  const cleanUrl = parsed.toString();
  return { cleanUrl, changes };
}


/* ══════════════════════════════════════════════════════════════════════
   SETTINGS — worker URL + preferences
   ══════════════════════════════════════════════════════════════════════ */

const SETTINGS_KEY = 'resc-settings';

function loadSettings() {
  try {
    return JSON.parse(localStorage.getItem(SETTINGS_KEY) || '{}');
  } catch { return {}; }
}

function saveSettings(s) {
  localStorage.setItem(SETTINGS_KEY, JSON.stringify(s));
}

function getWorkerUrl() {
  return (loadSettings().workerUrl || '').trim().replace(/\/$/, '');
}

function workerConfigured() {
  return !!getWorkerUrl();
}

/**
 * Test a worker URL — calls /health and expects { ok: true }.
 * Returns { ok: true } or { ok: false, error: string }
 */
async function testWorker(workerUrl) {
  const url = workerUrl.trim().replace(/\/$/, '');
  if (!url) return { ok: false, error: 'No URL provided.' };
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    const resp = await fetch(url + '/health', { signal: controller.signal, cache: 'no-store' });
    clearTimeout(timer);
    if (!resp.ok) return { ok: false, error: `Worker returned HTTP ${resp.status}.` };
    const data = await resp.json();
    if (!data.ok) return { ok: false, error: 'Worker responded but did not return { ok: true }.' };
    return { ok: true };
  } catch (e) {
    if (e.name === 'AbortError') return { ok: false, error: 'Connection timed out.' };
    return { ok: false, error: e.message || 'Connection failed.' };
  }
}


/* ══════════════════════════════════════════════════════════════════════
   RESOLVE ENGINE
   ══════════════════════════════════════════════════════════════════════ */

/** Known URL shortener domains. */
const SHORT_DOMAINS = new Set([
  'bit.ly','bitly.com','tinyurl.com','t.co','ow.ly','buff.ly','dlvr.it',
  'ift.tt','is.gd','v.gd','lnkd.in','goo.gl','youtu.be','amzn.to','amzn.com',
  'rb.gy','short.io','shorturl.at','cutt.ly','tiny.cc','tr.im','clk.im',
  'soo.gd','bl.ink','rebrand.ly','shorte.st','adf.ly','bc.vc','s.id',
]);

function isShortUrl(url) {
  try {
    const { hostname } = new URL(url);
    const bare = hostname.replace(/^www\./, '');
    return SHORT_DOMAINS.has(bare) || bare.length <= 8;
  } catch (e) { return false; }
}

/**
 * Local-only resolve analysis — no network calls.
 * Returns metadata that can be shown immediately.
 */
function resolveLocal(url) {
  const short = isShortUrl(url);
  let hostname = '';
  try { hostname = new URL(url).hostname; } catch {}

  const signals = [];

  if (short) {
    signals.push({ type: 'warn', text: `Short URL (${hostname}) — destination is hidden until followed.` });
  }

  // Detect if this looks like a known tracker redirect domain
  const trackerPatterns = [
    /click\./i, /track\./i, /redirect\./i, /r\./i, /go\./i, /link\./i,
  ];
  if (!short && trackerPatterns.some(p => p.test(hostname.split('.')[0]))) {
    signals.push({ type: 'info', text: `Subdomain pattern (${hostname}) suggests a redirect or tracking endpoint.` });
  }

  return {
    url,
    isShort: short,
    hostname,
    signals,
    workerAvailable: workerConfigured(),
  };
}

/**
 * Worker-based redirect resolution — full chain via Cloudflare Worker.
 * Returns { hops, finalUrl, duration_ms, error? }
 */
async function resolveWithWorker(url) {
  const workerUrl = getWorkerUrl();
  if (!workerUrl) return { hops: [], finalUrl: url, error: 'No worker configured.' };

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    const resp = await fetch(`${workerUrl}/resolve?url=${encodeURIComponent(url)}`, {
      signal: controller.signal,
      cache: 'no-store',
    });
    clearTimeout(timer);
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      return { hops: [], finalUrl: url, error: body.error || `Worker returned HTTP ${resp.status}.` };
    }
    const data = await resp.json();
    return data;
  } catch (e) {
    if (e.name === 'AbortError') return { hops: [], finalUrl: url, error: 'Worker request timed out.' };
    return { hops: [], finalUrl: url, error: e.message || 'Worker request failed.' };
  }
}

/* ══════════════════════════════════════════════════════════════════════
   INSPECT ENGINE
   ══════════════════════════════════════════════════════════════════════ */

/** Security indicator definitions. */
function getSecurityIndicators(parsed) {
  const indicators = [];

  // HTTPS check
  if (parsed.protocol === 'https:') {
    indicators.push({ label: 'HTTPS', status: 'ok', icon: '🔒' });
  } else {
    indicators.push({ label: 'Not HTTPS', status: 'bad', icon: '⚠️' });
  }

  // Punycode / IDN homograph
  if (/xn--/i.test(parsed.hostname)) {
    indicators.push({ label: 'IDN / Punycode domain', status: 'warn', icon: '🌐' });
  }

  // IP address as hostname
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(parsed.hostname)) {
    indicators.push({ label: 'IP address host', status: 'warn', icon: '🔢' });
  }

  // Excessive subdomains
  const parts = parsed.hostname.split('.');
  if (parts.length > 4) {
    indicators.push({ label: `${parts.length} subdomain levels`, status: 'warn', icon: '📛' });
  }

  // Known TLDs that phishers overuse
  const tld = parts[parts.length - 1];
  if (['tk','ml','ga','cf','gq','xyz','top','click','work','online'].includes(tld)) {
    indicators.push({ label: `Suspicious TLD (.${tld})`, status: 'warn', icon: '🎯' });
  }

  // Fragment
  if (parsed.hash) {
    indicators.push({ label: 'Fragment present', status: 'info', icon: '#' });
  }

  // Credentials in URL
  if (parsed.username || parsed.password) {
    indicators.push({ label: 'Credentials in URL', status: 'bad', icon: '🔑' });
  }

  // Non-standard port
  if (parsed.port && DEFAULT_PORTS[parsed.protocol] !== parsed.port) {
    indicators.push({ label: `Non-standard port (${parsed.port})`, status: 'warn', icon: '🔌' });
  }

  // Long URL (often used for obfuscation)
  if (parsed.href.length > 400) {
    indicators.push({ label: `Long URL (${parsed.href.length} chars)`, status: 'info', icon: '📏' });
  }

  // Many query parameters
  const paramCount = [...parsed.searchParams.keys()].length;
  if (paramCount > 8) {
    indicators.push({ label: `${paramCount} query parameters`, status: 'info', icon: '🔗' });
  }

  return indicators;
}

/**
 * Break down a URL into its component parts.
 */
function inspectUrl(url) {
  let parsed;
  try { parsed = new URL(url); }
  catch (e) { return { error: 'Invalid URL — could not parse.' }; }

  const params = [];
  parsed.searchParams.forEach((val, key) => params.push({ key, val }));

  const hostParts = parsed.hostname.split('.');
  const tld      = hostParts.length > 1 ? hostParts.slice(-2).join('.') : parsed.hostname;
  const subdomain = hostParts.length > 2 ? hostParts.slice(0, -2).join('.') : '';

  return {
    full:       parsed.href,
    scheme:     parsed.protocol.replace(':', ''),
    host:       parsed.hostname,
    subdomain,
    tld,
    port:       parsed.port || DEFAULT_PORTS[parsed.protocol] || '',
    portExplicit: !!parsed.port,
    path:       parsed.pathname,
    query:      parsed.search,
    params,
    fragment:   parsed.hash.replace(/^#/, ''),
    origin:     parsed.origin,
    username:   parsed.username,
    password:   parsed.password,
    security:   getSecurityIndicators(parsed),
  };
}


/* ══════════════════════════════════════════════════════════════════════
   PIPELINE ORCHESTRATOR
   ══════════════════════════════════════════════════════════════════════ */

/**
 * Run the full processing pipeline.
 * @param {string} sourceUrl
 * @param {object} opts — { decode, clean, cleanAffiliates, resolve, inspect }
 * @returns {object} results per stage
 */
async function runPipeline(sourceUrl, opts) {
  const results = { source: sourceUrl.trim() };

  let workingUrl = results.source;

  /* ── Stage 1: Decode ── */
  if (opts.decode) {
    const dr = decodeUrl(workingUrl);
    results.decode = dr;
    // Only advance working URL if decode actually unwrapped something.
    // dr.layers === 0 means no wrappers were found or all failed — keep source.
    if (dr.layers > 0 && dr.finalUrl) workingUrl = dr.finalUrl;
  }

  /* ── Stage 2: Clean ── */
  if (opts.clean) {
    const cr = cleanUrl(workingUrl, { removeAffiliates: opts.cleanAffiliates });
    results.clean = cr;
    if (cr.cleanUrl) workingUrl = cr.cleanUrl;
  }

  /* ── Stage 3: Resolve ── */
  if (opts.resolve) {
    results.resolve = {
      local: resolveLocal(workingUrl),
      worker: null,       // filled in async by UI
      loading: workerConfigured(),
    };
  }

  /* ── Stage 4: Inspect ── */
  if (opts.inspect) {
    results.inspect = inspectUrl(workingUrl);
  }

  results.finalUrl = workingUrl;
  return results;
}


/* ══════════════════════════════════════════════════════════════════════
   UI CONTROLLER
   ══════════════════════════════════════════════════════════════════════ */

const App = (() => {
  /* State */
  const state = {
    stages: { decode: true, clean: true, resolve: true, inspect: true },
    cleanAffiliates: false,
    results: null,
    processing: false,
    theme: 'dark',
    workerStatus: 'unchecked', // 'unchecked' | 'ok' | 'error'
  };

  /* DOM refs — populated after DOMContentLoaded */
  let els = {};

  /* ── Helpers ── */
  const qs  = (sel, ctx) => (ctx || document).querySelector(sel);
  const qsa = (sel, ctx) => [...(ctx || document).querySelectorAll(sel)];

  function icon(name, size = 14) {
    const icons = {
      scissors:    `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><line x1="20" y1="4" x2="8.12" y2="15.88"/><line x1="14.47" y1="14.48" x2="20" y2="20"/><line x1="8.12" y1="8.12" x2="12" y2="12"/></svg>`,
      sun:         `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"/><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"/><line x1="16.24" y1="7.76" x2="19.07" y2="4.93"/></svg>`,
      moon:        `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`,
      copy:        `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>`,
      check:       `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`,
      external:    `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/></svg>`,
      chevron:     `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>`,
      reset:       `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-4.68"/></svg>`,
      spinner:     `<div class="spinner"></div>`,
      lock:        `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`,
      search:      `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>`,
      link:        `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>`,
      link2:       `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>`,
      gear:        `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>`,
      worker:      `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>`,
      xmark:       `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`,
      info:        `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`,
    };
    return icons[name] || '';
  }

  function svgBool(condition, trueIcon, falseIcon, size) {
    return condition ? icon(trueIcon, size) : icon(falseIcon, size);
  }

  async function copyText(text, btn) {
    try {
      await navigator.clipboard.writeText(text);
      const orig = btn.innerHTML;
      btn.innerHTML = icon('check', 13) + ' Copied';
      btn.classList.add('copied');
      setTimeout(() => { btn.innerHTML = orig; btn.classList.remove('copied'); }, 2000);
    } catch (e) { /* ignore */ }
  }

  function openUrl(url) {
    window.open(url, '_blank', 'noopener,noreferrer');
  }

  /* ── Theme ── */
  function applyTheme(t) {
    state.theme = t;
    document.body.classList.toggle('light', t === 'light');
    els.themeBtn.innerHTML = t === 'light' ? icon('moon', 15) : icon('sun', 15);
    localStorage.setItem('resc-theme', t);
  }

  function toggleTheme() {
    applyTheme(state.theme === 'dark' ? 'light' : 'dark');
  }

  /* ── Worker chip ── */
  function updateWorkerChip() {
    if (!els.workerChip) return;
    const configured = workerConfigured();
    const ok = state.workerStatus === 'ok';
    if (configured && ok) {
      els.workerChip.className = 'badge-worker ok';
      els.workerChip.innerHTML = icon('worker', 11) + ' Worker enabled';
    } else if (configured) {
      els.workerChip.className = 'badge-worker warn';
      els.workerChip.innerHTML = icon('worker', 11) + ' Worker error';
    } else {
      els.workerChip.className = 'badge-local';
      els.workerChip.innerHTML = '🔒 Local only';
    }
  }

  /* ── Settings Modal ── */
  function openSettings() {
    const s = loadSettings();
    const workerUrl = s.workerUrl || '';

    const modal = document.createElement('div');
    modal.id = 'settings-modal';
    modal.className = 'modal-overlay';
    modal.innerHTML = `
      <div class="modal-box" role="dialog" aria-modal="true" aria-label="Settings">
        <div class="modal-header">
          <div class="modal-title">${icon('gear', 16)} Settings</div>
          <button class="modal-close" id="modal-close" aria-label="Close">${icon('xmark', 16)}</button>
        </div>
        <div class="modal-body">

          <div class="setting-section">
            <div class="setting-label">Cloudflare Worker URL</div>
            <div class="setting-desc">
              Deploy <code>worker.js</code> to Cloudflare Workers and paste the URL here.
              When configured, the Resolve stage follows full redirect chains server-side.
              Leave blank for local-only analysis.
            </div>
            <div class="setting-row">
              <input
                type="url"
                id="worker-url-input"
                class="setting-input"
                placeholder="https://your-worker.your-subdomain.workers.dev"
                value="${escHtml(workerUrl)}"
                spellcheck="false"
                autocomplete="off"
              >
              <button class="btn-test" id="test-worker-btn">Test</button>
            </div>
            <div id="test-result" class="test-result" style="display:none"></div>
          </div>

          <div class="setting-section" style="margin-top:1.25rem">
            <div class="setting-label">Worker Setup Guide</div>
            <div class="setting-desc">
              1. Copy <code>worker.js</code> from the Rescission repo<br>
              2. In Cloudflare dashboard → Workers & Pages → Create<br>
              3. Paste the script, click Deploy<br>
              4. Go to Settings → Variables → add <code>ALLOWED_ORIGINS</code>
                 set to <code>${escHtml(window.location.origin)}</code><br>
              5. Copy your worker URL and paste above
            </div>
          </div>

        </div>
        <div class="modal-footer">
          <button class="btn-secondary" id="modal-cancel">Cancel</button>
          <button class="btn-primary" id="modal-save" style="min-width:90px">Save</button>
        </div>
      </div>
    `;

    document.body.appendChild(modal);

    const inputEl   = modal.querySelector('#worker-url-input');
    const testBtn   = modal.querySelector('#test-worker-btn');
    const testRes   = modal.querySelector('#test-result');
    const closeBtn  = modal.querySelector('#modal-close');
    const cancelBtn = modal.querySelector('#modal-cancel');
    const saveBtn   = modal.querySelector('#modal-save');

    function closeModal() { modal.remove(); }

    closeBtn.addEventListener('click',  closeModal);
    cancelBtn.addEventListener('click', closeModal);
    modal.addEventListener('click', e => { if (e.target === modal) closeModal(); });
    document.addEventListener('keydown', function esc(e) {
      if (e.key === 'Escape') { closeModal(); document.removeEventListener('keydown', esc); }
    });

    testBtn.addEventListener('click', async () => {
      const url = inputEl.value.trim();
      if (!url) {
        showTestResult('error', 'Enter a worker URL first.');
        return;
      }
      testBtn.disabled = true;
      testBtn.textContent = 'Testing…';
      testRes.style.display = 'none';
      const result = await testWorker(url);
      testBtn.disabled = false;
      testBtn.textContent = 'Test';
      if (result.ok) {
        showTestResult('ok', '✓ Connection successful. Worker is reachable.');
        state.workerStatus = 'ok';
      } else {
        showTestResult('error', '✗ ' + result.error);
        state.workerStatus = 'error';
      }
    });

    saveBtn.addEventListener('click', () => {
      const url = inputEl.value.trim().replace(/\/$/, '');
      const s = loadSettings();
      s.workerUrl = url;
      saveSettings(s);
      if (!url) state.workerStatus = 'unchecked';
      updateWorkerChip();
      closeModal();
    });

    function showTestResult(type, msg) {
      testRes.style.display = 'block';
      testRes.className = 'test-result ' + type;
      testRes.textContent = msg;
    }

    // Focus input on open
    setTimeout(() => inputEl.focus(), 50);
  }

  /* ── Stage Toggle UI ── */
  function renderStageToggles() {
    const defs = [
      { id: 'decode',  label: 'Decode' },
      { id: 'clean',   label: 'Clean' },
      { id: 'resolve', label: 'Resolve' },
      { id: 'inspect', label: 'Inspect' },
    ];

    els.stageToggles.innerHTML = defs.map(d => `
      <button class="stage-toggle ${state.stages[d.id] ? 'active' : ''}" data-stage="${d.id}">
        <span class="stage-dot"></span>${d.label}
      </button>
    `).join('');

    // Sub-opts row
    els.subOpts.innerHTML = state.stages.clean ? `
      <button class="sub-opt ${state.cleanAffiliates ? 'active' : ''}" data-opt="cleanAffiliates">
        <span class="sub-dot"></span>Remove affiliate tags
      </button>
    ` : '';

    // Wire stage toggle clicks
    qsa('.stage-toggle', els.stageToggles).forEach(btn => {
      btn.addEventListener('click', () => {
        const id = btn.dataset.stage;
        state.stages[id] = !state.stages[id];
        btn.classList.toggle('active', state.stages[id]);
        btn.querySelector('.stage-dot').style.background = '';
        // re-render sub-opts
        renderStageToggles();
      });
    });

    // Wire sub-opt clicks
    qsa('.sub-opt', els.subOpts).forEach(btn => {
      btn.addEventListener('click', () => {
        const opt = btn.dataset.opt;
        if (opt === 'cleanAffiliates') {
          state.cleanAffiliates = !state.cleanAffiliates;
          btn.classList.toggle('active', state.cleanAffiliates);
        }
      });
    });
  }

  /* ── Pipeline Bar ── */
  function renderPipelineBar(status = {}) {
    if (!els.pipelineBar) return;
    const stages = [
      { id: 'decode',  label: 'Decode',  icon: '🔓' },
      { id: 'clean',   label: 'Clean',   icon: '🧹' },
      { id: 'resolve', label: 'Resolve', icon: '🔗' },
      { id: 'inspect', label: 'Inspect', icon: '🔍' },
    ];

    els.pipelineBar.innerHTML = stages.map((s, i) => {
      const skipped = !state.stages[s.id];
      const st = status[s.id] || (skipped ? 'skipped' : 'idle');
      const sep = i < stages.length - 1 ? `<span class="pipe-sep">›</span>` : '';
      return `
        <div class="pipe-stage ${st}">
          <span class="pipe-stage-icon">${s.icon}</span>${s.label}
        </div>${sep}
      `;
    }).join('');
  }

  /* ── URL Block ── */
  function urlBlock(url) {
    return `
      <div class="url-block">${escHtml(url)}</div>
      <div class="url-block-actions">
        <button class="btn-icon resc-copy" data-url="${escHtml(url)}">${icon('copy', 12)} Copy</button>
        <button class="btn-icon resc-open" data-url="${escHtml(url)}">${icon('external', 12)} Open</button>
      </div>
    `;
  }

  function escHtml(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  /* ── Result Cards ── */
  function resultCard(stage, label, summaryText, bodyHtml) {
    return `
      <div class="result-card" data-stage="${stage}">
        <div class="result-card-header" onclick="this.parentElement.classList.toggle('collapsed')">
          <span class="stage-badge ${stage}">${label}</span>
          <span class="result-summary">${escHtml(summaryText)}</span>
          <span class="collapse-icon">${icon('chevron', 14)}</span>
        </div>
        <div class="result-card-body">${bodyHtml}</div>
      </div>
    `;
  }

  /* ── Render Decode Results ── */
  function renderDecode(dr) {
    if (!dr) return '';
    const { steps, finalUrl, layers } = dr;

    let stepsHtml = '';

    if (steps.length === 0) {
      stepsHtml = `
        <div class="decode-step step-none">
          <span class="step-icon info">${icon('check', 14)}</span>
          <div><div class="step-label">No wrappers detected</div>
          <div class="step-note">URL does not match any known email security service. No decoding needed.</div></div>
        </div>`;
    } else {
      stepsHtml = steps.map(s => {
        if (s.result === 'decoded') {
          return `
            <div class="decode-step step-pass">
              <span class="step-icon ok">${icon('check', 14)}</span>
              <div>
                <div class="step-label">${escHtml(s.service)} ${s.verified ? '✓' : ''}</div>
                ${s.note ? `<div class="step-note">${escHtml(s.note)}</div>` : ''}
                ${s.output ? `<div class="step-note text-mono" style="margin-top:4px">${escHtml(s.output)}</div>` : ''}
              </div>
            </div>`;
        } else if (s.result === 'detect') {
          return `
            <div class="decode-step step-detect">
              <span class="step-icon warn">⚠</span>
              <div>
                <div class="step-label">${escHtml(s.service)} — opaque token</div>
                <div class="step-note">${escHtml(s.note || 'Server-side redirect. Original URL cannot be recovered locally.')}</div>
              </div>
            </div>`;
        } else {
          return `
            <div class="decode-step step-skip">
              <span class="step-icon skip">—</span>
              <div>
                <div class="step-label">${escHtml(s.service)}</div>
                <div class="step-note">${escHtml(s.note || 'Detected but could not decode.')}</div>
              </div>
            </div>`;
        }
      }).join('');
    }

    const summaryLabel = layers === 0 ? 'No wrappers' : `${layers} wrapper${layers === 1 ? '' : 's'} unwrapped`;

    const body = `
      <div class="decode-steps">${stepsHtml}</div>
      ${layers > 0 ? `<div class="divider"></div><div class="text-xs text-muted" style="margin-bottom:0.4rem">Final decoded URL</div>${urlBlock(finalUrl)}` : ''}
    `;

    return resultCard('decode', 'Decode', summaryLabel, body);
  }

  /* ── Render Clean Results ── */
  function renderClean(cr) {
    if (!cr) return '';
    const { cleanUrl, changes } = cr;

    const rows = changes.map(c => `
      <div class="clean-row">
        <span class="clean-action">${escHtml(c.action)}</span>
        <span class="clean-badge ${c.badge}">${c.badge}</span>
        <span class="clean-detail">${escHtml(c.detail)}</span>
      </div>`).join('');

    const changed = changes.filter(c => c.badge !== 'none' && c.badge !== 'kept').length;
    const summary = changed ? `${changed} change${changed === 1 ? '' : 's'}` : 'No changes';

    const body = `
      <div class="clean-rows">${rows}</div>
      <div class="divider"></div>
      <div class="text-xs text-muted" style="margin-bottom:0.4rem">Clean URL</div>
      ${urlBlock(cleanUrl)}
    `;

    return resultCard('clean', 'Clean', summary, body);
  }

  /* ── Render Resolve Results ── */
  function renderResolve(rr) {
    if (!rr) return '';
    const { local, worker, loading } = rr;
    if (!local) return '';

    const isShort   = local.isShort;
    const hasWorker = local.workerAvailable;

    /* ── Local signals ── */
    const localSignals = local.signals.map(s => `
      <div class="resolve-note ${s.type === 'warn' ? 'warn' : ''}">
        ${s.type === 'warn' ? '⚠' : icon('info', 13)} ${escHtml(s.text)}
      </div>`).join('');

    /* ── Worker result or loading/nudge ── */
    let workerSection = '';

    if (!hasWorker) {
      // No worker — show local only note + nudge
      workerSection = `
        <div class="resolve-note resolve-nudge">
          ${icon('worker', 13)}
          <span>Configure a <button class="link-btn resc-action" data-action="openSettings">Cloudflare Worker</button> to follow redirect chains and expand short URLs.</span>
        </div>`;
    } else if (loading) {
      workerSection = `
        <div class="resolve-note" id="resolve-loading">
          ${icon('spinner')} Following redirects via worker…
        </div>`;
    } else if (worker) {
      if (worker.error && !worker.hops?.length) {
        workerSection = `
          <div class="resolve-note error">
            ⚠ Worker error: ${escHtml(worker.error)}
          </div>`;
      } else {
        const hops = worker.hops || [];
        const chainHtml = hops.map((hop, i) => {
          const isFirst = i === 0;
          const isLast  = i === hops.length - 1;
          const numClass = isFirst ? 'source' : isLast ? 'final' : '';
          const statusClass = hop.error ? 'hop-error' : (hop.status >= 300 && hop.status < 400) ? 'hop-redirect' : '';
          return `
            <div class="redirect-hop ${statusClass}">
              <div class="hop-num ${numClass}">${i + 1}</div>
              <div class="hop-detail">
                <div class="hop-url">${escHtml(hop.url)}</div>
                <div class="hop-meta">
                  ${hop.status ? `<span class="hop-status">${hop.status} ${escHtml(hop.statusText || '')}</span>` : ''}
                  ${hop.server ? `<span class="hop-server">${escHtml(hop.server)}</span>` : ''}
                  ${hop.location ? `<span class="hop-location">→ ${escHtml(hop.location)}</span>` : ''}
                </div>
              </div>
            </div>`;
        }).join('');

        const finalUrl   = worker.finalUrl;
        const inputUrl   = local.url;
        const durationMs = worker.duration_ms;
        const hopCount   = hops.length - 1;

        workerSection = `
          <div class="redirect-chain">${chainHtml}</div>
          ${worker.error ? `<div class="resolve-note warn" style="margin-top:0.5rem">⚠ Chain ended with an error: ${escHtml(worker.error)}</div>` : ''}
          ${durationMs != null ? `<div class="hop-meta" style="margin-top:0.4rem;padding-left:0.25rem">${hopCount} redirect${hopCount === 1 ? '' : 's'} · ${durationMs}ms</div>` : ''}
          ${(finalUrl && finalUrl !== inputUrl)
            ? '<div class="divider"></div><div class="text-xs text-muted" style="margin-bottom:0.4rem">Final destination</div>' + urlBlock(finalUrl)
            : '<div class="resolve-note ok" style="margin-top:0.5rem">✓ No redirects — URL goes directly to destination.</div>'}
        `;
      }
    }

    const body = `
      ${localSignals}
      ${workerSection}
      <div class="divider"></div>
      <div class="url-block-actions">
        <button class="btn-icon resc-open" data-url="${escHtml(local.url)}">${icon('external', 12)} Open URL directly</button>
        <button class="btn-icon resc-copy" data-url="${escHtml(local.url)}">${icon('copy', 12)} Copy</button>
      </div>
    `;

    const hops = worker?.hops?.length ? worker.hops.length - 1 : null;
    const summary = loading ? 'Resolving…'
      : !hasWorker    ? 'Local analysis'
      : worker?.error && !worker?.hops?.length ? 'Worker error'
      : hops != null  ? `${hops} redirect${hops === 1 ? '' : 's'}`
      : 'No redirects';

    return resultCard('resolve', 'Resolve', summary, body);
  }
  /* ── Render Inspect Results ── */
  function renderInspect(ir) {
    if (!ir) return '';
    if (ir.error) return resultCard('inspect', 'Inspect', 'Parse error', `<p class="text-sm text-muted">${escHtml(ir.error)}</p>`);

    const field = (key, val, full = false) => `
      <div class="inspect-field ${full ? 'full' : ''}">
        <div class="inspect-key">${escHtml(key)}</div>
        <div class="inspect-val ${!val ? 'empty' : ''}">${val ? escHtml(val) : 'none'}</div>
      </div>`;

    const paramsHtml = ir.params.length ? `
      <table class="params-table">
        <thead><tr><th>Parameter</th><th>Value</th></tr></thead>
        <tbody>
          ${ir.params.map(p => `
            <tr>
              <td class="param-key">${escHtml(p.key)}</td>
              <td class="param-val">${escHtml(p.val)}</td>
            </tr>`).join('')}
        </tbody>
      </table>` : `<div class="inspect-val empty">none</div>`;

    const secHtml = ir.security.map(s => `
      <div class="sec-chip ${s.status}">
        <span>${s.icon}</span>${escHtml(s.label)}
      </div>`).join('');

    const body = `
      <div class="inspect-grid">
        ${field('Scheme', ir.scheme)}
        ${field('Host', ir.host)}
        ${ir.subdomain ? field('Subdomain', ir.subdomain) : ''}
        ${field('TLD / Domain', ir.tld)}
        ${field('Port', ir.portExplicit ? ir.port : `${ir.port} (default)`)}
        ${field('Path', ir.path)}
        ${field('Fragment', ir.fragment || '')}
        ${ir.username ? field('Username', ir.username) : ''}
      </div>
      <div class="divider"></div>
      <div class="inspect-key" style="margin-bottom:0.4rem">Query Parameters</div>
      ${paramsHtml}
      <div class="divider"></div>
      <div class="inspect-key" style="margin-bottom:0.5rem">Security Indicators</div>
      <div class="sec-indicators">${secHtml}</div>
    `;

    const paramCount = ir.params.length;
    const summary = `${paramCount} param${paramCount === 1 ? '' : 's'} · ${ir.security.filter(s => s.status !== 'ok').length} flag${ir.security.filter(s => s.status !== 'ok').length === 1 ? '' : 's'}`;

    return resultCard('inspect', 'Inspect', summary, body);
  }

  /* ── Patch resolve card in place after async worker result ── */
  function renderResults() {
    const results = state.results;
    if (!results) { els.resultsArea.innerHTML = emptyState(); return; }
    let html = '';
    if (results.decode)  html += renderDecode(results.decode);
    if (results.clean)   html += renderClean(results.clean);
    if (results.resolve) html += renderResolve(results.resolve);
    if (results.inspect) html += renderInspect(results.inspect);
    els.resultsArea.innerHTML = html;
  }

  /* ── Process ── */
  async function process() {
    const url = els.urlInput.value.trim();
    if (!url) { els.urlInput.focus(); return; }

    state.processing = true;
    els.processBtn.disabled = true;
    els.processBtn.innerHTML = icon('spinner') + ' Processing…';

    renderPipelineBar({ decode: 'running' });
    els.resultsArea.innerHTML = '';

    try {
      const results = await runPipeline(url, {
        decode:          state.stages.decode,
        clean:           state.stages.clean,
        cleanAffiliates: state.cleanAffiliates,
        resolve:         state.stages.resolve,
        inspect:         state.stages.inspect,
      });

      state.results = results;

      // Initial render (resolve card shows loading if a worker is configured)
      renderResults();
      renderPipelineBar({
        decode: 'done', clean: 'done',
        resolve: results.resolve ? (workerConfigured() ? 'running' : 'done') : 'skipped',
        inspect: 'done',
      });

      // Async worker resolve — updates state, then re-renders the whole area
      if (state.stages.resolve && results.resolve && workerConfigured()) {
        const resolveInput = results.clean?.cleanUrl || results.decode?.finalUrl || url;

        resolveWithWorker(resolveInput)
          .then(workerResult => {
            results.resolve = {
              local:   { ...results.resolve.local, workerAvailable: true },
              worker:  workerResult,
              loading: false,
            };
            const hasErr = !!(workerResult.error && !workerResult.hops?.length);
            renderResults();
            renderPipelineBar({ decode: 'done', clean: 'done', resolve: hasErr ? 'error' : 'done', inspect: 'done' });
          })
          .catch(err => {
            results.resolve = {
              local:   { ...results.resolve.local, workerAvailable: true },
              worker:  { hops: [], finalUrl: resolveInput, error: (err && err.message) || 'Worker request failed.' },
              loading: false,
            };
            renderResults();
            renderPipelineBar({ decode: 'done', clean: 'done', resolve: 'error', inspect: 'done' });
          });
      } else if (state.stages.resolve && results.resolve) {
        renderPipelineBar({ decode: 'done', clean: 'done', resolve: 'done', inspect: 'done' });
      }

    } catch (e) {
      els.resultsArea.innerHTML = `<p class="text-sm text-muted" style="padding:1rem">Error: ${escHtml(e.message)}</p>`;
    } finally {
      state.processing = false;
      els.processBtn.disabled = false;
      els.processBtn.innerHTML = icon('scissors', 14) + ' Process URL';
    }
  }

  function reset() {
    els.urlInput.value = '';
    els.resultsArea.innerHTML = emptyState();
    els.pipelineBar.innerHTML = '';
    state.results = null;
    els.urlInput.focus();
  }

  function emptyState() {
    return `
      <div class="state-empty">
        ${icon('scissors', 32)}
        <p>Paste a URL above and click <strong>Process URL</strong> to begin.</p>
        <p style="margin-top:0.4rem;font-size:0.75rem">Decoded, cleaned, resolved, and inspected — entirely in your browser. Nothing leaves this page.</p>
      </div>`;
  }

  /* ── Public API (for inline event handlers) ── */
  return {
    copy: copyText,
    openUrl,
    openSettings,

    init() {
      els = {
        urlInput:     qs('#url-input'),
        processBtn:   qs('#process-btn'),
        resetBtn:     qs('#reset-btn'),
        themeBtn:     qs('#theme-btn'),
        settingsBtn:  qs('#settings-btn'),
        workerChip:   qs('#worker-chip'),
        stageToggles: qs('#stage-toggles'),
        subOpts:      qs('#sub-opts'),
        pipelineBar:  qs('#pipeline-bar'),
        resultsArea:  qs('#results-area'),
      };

      // Theme
      const saved = localStorage.getItem('resc-theme') || 'dark';
      applyTheme(saved);
      els.themeBtn.addEventListener('click', toggleTheme);

      // Settings
      els.settingsBtn.addEventListener('click', openSettings);

      // Worker chip — check saved worker on load
      if (workerConfigured()) {
        testWorker(getWorkerUrl()).then(result => {
          state.workerStatus = result.ok ? 'ok' : 'error';
          updateWorkerChip();
        });
      }
      updateWorkerChip();

      // Stage toggles
      renderStageToggles();

      // Process / Reset
      els.processBtn.addEventListener('click', process);
      els.resetBtn.addEventListener('click', reset);

      // Enter key in textarea (Ctrl/Cmd + Enter)
      els.urlInput.addEventListener('keydown', e => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') process();
      });

      // Paste auto-process option
      els.urlInput.addEventListener('paste', () => {
        setTimeout(() => {
          const v = els.urlInput.value.trim();
          if (v && (v.startsWith('http') || v.startsWith('//'))) {
            // Small visual hint — don't auto-process, let user confirm
          }
        }, 50);
      });

      // Event delegation for dynamically rendered buttons in results
      document.body.addEventListener('click', e => {
        // Copy button
        const copyBtn = e.target.closest('.resc-copy');
        if (copyBtn) {
          const url = copyBtn.dataset.url;
          if (url) copyText(url, copyBtn);
          return;
        }
        // Open button
        const openBtn = e.target.closest('.resc-open');
        if (openBtn) {
          const url = openBtn.dataset.url;
          if (url) openUrl(url);
          return;
        }
        // Action buttons (e.g. openSettings)
        const actionBtn = e.target.closest('.resc-action');
        if (actionBtn) {
          const action = actionBtn.dataset.action;
          if (action === 'openSettings') openSettings();
          return;
        }
      });

      // Empty state
      els.resultsArea.innerHTML = emptyState();
    }
  };
})();

window.App = App;
document.addEventListener('DOMContentLoaded', () => App.init());
