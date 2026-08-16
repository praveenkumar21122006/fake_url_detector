'use strict';

/**
 * URLGuard heuristic analysis engine.
 * Pure functions — no I/O — so they're easy to unit test and reuse.
 */

const SUSPICIOUS_TLDS = [
  'ru', 'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'click', 'link', 'win',
  'bid', 'loan', 'work', 'gdn', 'date', 'racing', 'science', 'review',
  'trade', 'cricket', 'faith', 'party', 'download', 'stream', 'accountant',
  'men', 'rocks', 'xin', 'vip'
];

const PHISHING_KEYWORDS = [
  'secure', 'verify', 'login', 'signin', 'account', 'update', 'confirm',
  'password', 'banking', 'wallet', 'suspension', 'suspended', 'unusual',
  'limited', 'access', 'restore', 'validate', 'authenticate'
];

const BRAND_TARGETS = [
  'paypal', 'amazon', 'google', 'apple', 'microsoft', 'netflix', 'facebook',
  'instagram', 'twitter', 'chase', 'wellsfargo', 'bankofamerica', 'ebay',
  'linkedin', 'whatsapp', 'telegram', 'coinbase', 'binance', 'blockchain'
];

const HOMOGLYPHS = { '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '@': 'a', 'vv': 'w', 'rn': 'm' };

const HIGH_RISK_PATHS = [
  'login', 'signin', 'account', 'verify', 'secure', 'update', 'confirm',
  'wallet', 'password', 'credentials'
];

function getRegisteredDomain(hostname) {
  const parts = hostname.split('.');
  return parts.slice(-2).join('.');
}

/**
 * Normalizes a raw user-supplied string into a parseable URL string.
 * Throws if it still can't be parsed.
 */
function normalizeUrl(raw) {
  let url = String(raw || '').trim();
  if (!url) throw new Error('Empty URL');
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
  return url;
}

/**
 * Runs all heuristic checks against a URL and returns flags + a 0-100 score.
 * @param {string} raw - the original, unmodified user input
 * @returns {{flags: Array, score: number, level: string}}
 */
function analyzeURL(raw) {
  const normalized = normalizeUrl(raw);
  const parsed = new URL(normalized);
  const hostname = parsed.hostname.toLowerCase();
  const path = (parsed.pathname + parsed.search).toLowerCase();
  const flags = [];

  // 1. IP address as hostname
  const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
  flags.push({
    id: 'ip', name: 'IP Address Host', triggered: isIP, weight: 30,
    desc: isIP ? 'Legitimate services rarely use bare IP addresses.' : 'Domain name used — expected.'
  });

  // 2. Suspicious TLD
  const tld = hostname.split('.').pop();
  const badTLD = SUSPICIOUS_TLDS.includes(tld);
  flags.push({
    id: 'tld', name: 'High-Abuse TLD', triggered: badTLD, weight: 20,
    desc: badTLD ? `".${tld}" is frequently used in phishing.` : `".${tld}" is a common trusted TLD.`
  });

  // 3. Homoglyph / number substitution in domain
  const domainBody = hostname.replace(/\.(com|net|org|io|co)$/, '');
  let homoFound = false, homoDetail = '';
  for (const [fake, real] of Object.entries(HOMOGLYPHS)) {
    if (domainBody.includes(fake)) { homoFound = true; homoDetail = `"${fake}" used instead of "${real}"`; break; }
  }
  flags.push({
    id: 'homoglyph', name: 'Homoglyph Substitution', triggered: homoFound, weight: 35,
    desc: homoFound ? `Digit/letter swap detected: ${homoDetail}` : 'No character substitutions detected.'
  });

  // 4. Brand name in suspicious domain (checked both literally and with
  //    homoglyph substitutions undone, so "paypa1.com" still matches "paypal").
  //    A domain is only exempt when its registrable root is EXACTLY the
  //    brand (e.g. "amazon.com") — "amazon-order-security.info" still
  //    contains "amazon" as a prefix but is not an exact-root match, so
  //    it correctly gets flagged instead of waved through.
  let brandSpoofed = false, spoofedBrand = '';
  const registeredDomain = getRegisteredDomain(hostname);
  const registeredRoot = registeredDomain.split('.')[0];
  let deHomoglyphed = hostname;
  for (const [fake, real] of Object.entries(HOMOGLYPHS)) {
    deHomoglyphed = deHomoglyphed.split(fake).join(real);
  }
  for (const brand of BRAND_TARGETS) {
    const isExactBrandRoot = registeredRoot === brand;
    const literalMatch = hostname.includes(brand) && !isExactBrandRoot;
    const disguisedMatch = !hostname.includes(brand) && deHomoglyphed.includes(brand) && !isExactBrandRoot;
    if (literalMatch || disguisedMatch) {
      brandSpoofed = true; spoofedBrand = brand; break;
    }
  }
  flags.push({
    id: 'brand', name: 'Brand Spoofing', triggered: brandSpoofed, weight: 40,
    desc: brandSpoofed ? `"${spoofedBrand}" appears in domain but isn't the real owner.` : 'No known brand names misused in domain.'
  });

  // 5. Excessive subdomains
  const subdomainCount = hostname.split('.').length - 2;
  const tooManySubs = subdomainCount >= 3;
  flags.push({
    id: 'subdomain', name: 'Excessive Subdomains', triggered: tooManySubs, weight: 15,
    desc: tooManySubs ? `${subdomainCount} subdomain levels detected — often used to hide real domain.` : 'Normal subdomain depth.'
  });

  // 6. Phishing keywords in path/query
  const kwFound = PHISHING_KEYWORDS.filter(kw => path.includes(kw));
  const hasKW = kwFound.length >= 2;
  flags.push({
    id: 'keywords', name: 'Phishing Keywords', triggered: hasKW, weight: 20,
    desc: hasKW ? `Suspicious terms in URL: ${kwFound.slice(0, 3).join(', ')}` : 'No suspicious keyword stacking.'
  });

  // 7. Long URL (obfuscation indicator)
  const longURL = raw.length > 100;
  flags.push({
    id: 'length', name: 'Abnormal URL Length', triggered: longURL, weight: 10,
    desc: longURL ? `URL is ${raw.length} chars — unusually long.` : `URL length (${raw.length} chars) looks normal.`
  });

  // 8. HTTP (no HTTPS)
  const noHTTPS = parsed.protocol === 'http:';
  flags.push({
    id: 'https', name: 'No HTTPS', triggered: noHTTPS, weight: 15,
    desc: noHTTPS ? 'Connection is unencrypted — data can be intercepted.' : 'HTTPS enabled.'
  });

  // 9. URL-encoded characters (obfuscation)
  const encodedMatches = raw.match(/%[0-9a-f]{2}/gi) || [];
  const hasEncoded = encodedMatches.length > 3;
  flags.push({
    id: 'encoded', name: 'Encoded Characters', triggered: hasEncoded, weight: 15,
    desc: hasEncoded ? 'Heavy URL encoding can hide malicious content.' : 'No suspicious encoding detected.'
  });

  // 10. High-risk path keywords
  const riskyPath = HIGH_RISK_PATHS.some(kw => path.split('/').includes(kw));
  flags.push({
    id: 'path', name: 'Sensitive Path Keywords', triggered: riskyPath, weight: 10,
    desc: riskyPath ? 'Path contains authentication/credential keywords.' : 'Path looks benign.'
  });

  // 11. @ symbol in URL (credential-stuffing / redirect trick)
  const hasAtSymbol = normalized.includes('@') && normalized.indexOf('@') > normalized.indexOf('://') + 3;
  flags.push({
    id: 'atsymbol', name: '"@" in URL', triggered: hasAtSymbol, weight: 25,
    desc: hasAtSymbol ? 'The "@" symbol can hide the real destination host from the visible one.' : 'No "@" trick detected.'
  });

  const totalWeight = flags.reduce((sum, f) => sum + (f.triggered ? f.weight : 0), 0);
  const maxPossible = flags.reduce((sum, f) => sum + f.weight, 0);
  const score = Math.min(100, Math.round((totalWeight / maxPossible) * 100 * 1.4));
  const level = score >= 60 ? 'danger' : score >= 25 ? 'warn' : 'safe';

  return {
    input: raw,
    normalizedUrl: normalized,
    hostname,
    registeredDomain,
    score,
    level,
    flags,
    analyzedAt: new Date().toISOString()
  };
}

module.exports = { analyzeURL, normalizeUrl, getRegisteredDomain };
