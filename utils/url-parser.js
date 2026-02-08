/**
 * PhishGuard - URL Parsing Utility Module
 *
 * Provides comprehensive URL parsing, domain extraction, TLD validation,
 * and punycode decoding for phishing detection analysis.
 */

// ---------------------------------------------------------------------------
// Known TLD lists
// ---------------------------------------------------------------------------

/** Common single-part TLDs */
const SINGLE_TLDS = new Set([
  'com', 'net', 'org', 'edu', 'gov', 'mil', 'int',
  'kr', 'jp', 'cn', 'tw', 'hk', 'sg', 'th', 'vn', 'my', 'id', 'ph', 'in',
  'uk', 'de', 'fr', 'it', 'es', 'nl', 'be', 'at', 'ch', 'se', 'no', 'fi',
  'dk', 'pl', 'pt', 'ie', 'ru', 'ua', 'cz', 'ro', 'hu', 'gr', 'bg',
  'us', 'ca', 'mx', 'br', 'ar', 'cl', 'co',
  'au', 'nz',
  'za', 'ng', 'eg', 'ke',
  'io', 'ai', 'app', 'dev', 'me', 'tv', 'cc', 'info', 'biz', 'xyz',
  'online', 'site', 'store', 'tech', 'cloud', 'space', 'pro', 'mobi',
  'name', 'museum', 'aero', 'coop', 'travel', 'jobs', 'cat', 'asia',
]);

/** Common multi-part TLDs (second-level + top-level) */
const MULTI_PART_TLDS = new Set([
  // Korea
  'co.kr', 'or.kr', 'ne.kr', 'go.kr', 'ac.kr', 'pe.kr', 're.kr', 'ms.kr',
  // Japan
  'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp', 'ad.jp',
  // United Kingdom
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk', 'sch.uk',
  // Australia
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'id.au',
  // New Zealand
  'co.nz', 'net.nz', 'org.nz', 'ac.nz', 'govt.nz',
  // China
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn',
  // Taiwan
  'com.tw', 'net.tw', 'org.tw', 'edu.tw', 'gov.tw',
  // Hong Kong
  'com.hk', 'net.hk', 'org.hk', 'edu.hk', 'gov.hk',
  // Singapore
  'com.sg', 'net.sg', 'org.sg', 'edu.sg', 'gov.sg',
  // India
  'co.in', 'net.in', 'org.in', 'ac.in', 'gov.in',
  // Brazil
  'com.br', 'net.br', 'org.br', 'edu.br', 'gov.br',
  // South Africa
  'co.za', 'net.za', 'org.za', 'ac.za', 'gov.za',
  // Thailand
  'co.th', 'or.th', 'ac.th', 'go.th', 'in.th',
  // Vietnam
  'com.vn', 'net.vn', 'org.vn', 'edu.vn', 'gov.vn',
  // Malaysia
  'com.my', 'net.my', 'org.my', 'edu.my', 'gov.my',
  // Indonesia
  'co.id', 'or.id', 'ac.id', 'go.id', 'web.id',
  // Philippines
  'com.ph', 'net.ph', 'org.ph', 'edu.ph', 'gov.ph',
  // Nigeria
  'com.ng', 'net.ng', 'org.ng', 'edu.ng', 'gov.ng',
  // Mexico
  'com.mx', 'net.mx', 'org.mx', 'edu.mx', 'gob.mx',
  // Argentina
  'com.ar', 'net.ar', 'org.ar', 'edu.ar', 'gov.ar',
  // Turkey
  'com.tr', 'net.tr', 'org.tr', 'edu.tr', 'gov.tr',
  // Russia
  'com.ru',
  // European extras
  'co.at', 'co.il', 'co.ke',
]);

/** Combined set of all known TLDs for quick lookup */
const ALL_KNOWN_TLDS = new Set([...SINGLE_TLDS, ...MULTI_PART_TLDS]);

// ---------------------------------------------------------------------------
// Punycode helpers (basic implementation)
// ---------------------------------------------------------------------------

const PUNYCODE_BASE = 36;
const PUNYCODE_TMIN = 1;
const PUNYCODE_TMAX = 26;
const PUNYCODE_SKEW = 38;
const PUNYCODE_DAMP = 700;
const PUNYCODE_INITIAL_BIAS = 72;
const PUNYCODE_INITIAL_N = 128;
const PUNYCODE_DELIMITER = '-';

/**
 * Decode a single punycode digit character to its numeric value.
 * a-z => 0-25, 0-9 => 26-35
 *
 * @param {number} codePoint - Character code point
 * @returns {number} Numeric value or Infinity if invalid
 */
function punycodeDigitToValue(codePoint) {
  if (codePoint >= 0x30 && codePoint <= 0x39) {
    // '0'..'9' => 26..35
    return codePoint - 0x30 + 26;
  }
  if (codePoint >= 0x41 && codePoint <= 0x5A) {
    // 'A'..'Z' => 0..25
    return codePoint - 0x41;
  }
  if (codePoint >= 0x61 && codePoint <= 0x7A) {
    // 'a'..'z' => 0..25
    return codePoint - 0x61;
  }
  return Infinity;
}

/**
 * Adapt the bias according to the punycode algorithm (RFC 3492 section 6.1).
 *
 * @param {number} delta
 * @param {number} numPoints
 * @param {boolean} firstTime
 * @returns {number} New bias
 */
function adaptBias(delta, numPoints, firstTime) {
  let d = firstTime ? Math.floor(delta / PUNYCODE_DAMP) : Math.floor(delta / 2);
  d += Math.floor(d / numPoints);

  let k = 0;
  while (d > Math.floor(((PUNYCODE_BASE - PUNYCODE_TMIN) * PUNYCODE_TMAX) / 2)) {
    d = Math.floor(d / (PUNYCODE_BASE - PUNYCODE_TMIN));
    k += PUNYCODE_BASE;
  }

  return k + Math.floor(((PUNYCODE_BASE - PUNYCODE_TMIN + 1) * d) / (d + PUNYCODE_SKEW));
}

/**
 * Decode a single punycode-encoded string (the part after "xn--") into Unicode.
 * Implements the Bootstring / Punycode decode algorithm from RFC 3492.
 *
 * @param {string} encoded - The punycode-encoded payload (without the "xn--" prefix)
 * @returns {string} Decoded Unicode string
 */
function punycodeDecodePayload(encoded) {
  const output = [];
  const inputLength = encoded.length;

  // Find the last delimiter; everything before it is literal ASCII
  let basicEnd = encoded.lastIndexOf(PUNYCODE_DELIMITER);
  if (basicEnd < 0) {
    basicEnd = 0;
  }

  for (let j = 0; j < basicEnd; j++) {
    output.push(encoded.charCodeAt(j));
  }

  let n = PUNYCODE_INITIAL_N;
  let bias = PUNYCODE_INITIAL_BIAS;
  let i = 0;
  let inputIndex = basicEnd > 0 ? basicEnd + 1 : 0;

  while (inputIndex < inputLength) {
    const oldi = i;
    let w = 1;

    for (let k = PUNYCODE_BASE; ; k += PUNYCODE_BASE) {
      if (inputIndex >= inputLength) {
        throw new RangeError('Invalid punycode input');
      }

      const digit = punycodeDigitToValue(encoded.charCodeAt(inputIndex++));
      if (digit >= PUNYCODE_BASE) {
        throw new RangeError('Invalid punycode input');
      }

      i += digit * w;

      const t =
        k <= bias + PUNYCODE_TMIN
          ? PUNYCODE_TMIN
          : k >= bias + PUNYCODE_TMAX
            ? PUNYCODE_TMAX
            : k - bias;

      if (digit < t) {
        break;
      }

      w *= PUNYCODE_BASE - t;
    }

    const outputLength = output.length + 1;
    bias = adaptBias(i - oldi, outputLength, oldi === 0);
    n += Math.floor(i / outputLength);
    i %= outputLength;

    output.splice(i, 0, n);
    i++;
  }

  return String.fromCodePoint(...output);
}

// ---------------------------------------------------------------------------
// Exported functions
// ---------------------------------------------------------------------------

/**
 * Decode a punycode-encoded hostname to its Unicode representation.
 * Each label that starts with "xn--" is decoded individually.
 *
 * @param {string} hostname - The hostname to decode (e.g. "xn--d1acufc.xn--p1ai")
 * @returns {string} The decoded hostname with Unicode characters
 *
 * @example
 *   decodePunycode('xn--3e0b707e.xn--3e0b707e') // Korean TLD example
 *   decodePunycode('www.xn--n3h.com')            // emoji domain
 */
export function decodePunycode(hostname) {
  if (!hostname || typeof hostname !== 'string') {
    return hostname ?? '';
  }

  try {
    const labels = hostname.split('.');

    const decoded = labels.map((label) => {
      if (label.toLowerCase().startsWith('xn--')) {
        return punycodeDecodePayload(label.slice(4));
      }
      return label;
    });

    return decoded.join('.');
  } catch {
    // If decoding fails, return the original hostname unchanged
    return hostname;
  }
}

/**
 * Check whether a given TLD (single-part or multi-part) is a known/common TLD.
 *
 * @param {string} tld - The TLD to check, e.g. "com", "co.kr"
 * @returns {boolean} true if the TLD is in the known list
 *
 * @example
 *   isKnownTLD('com')   // true
 *   isKnownTLD('co.kr') // true
 *   isKnownTLD('zzz')   // false
 */
export function isKnownTLD(tld) {
  if (!tld || typeof tld !== 'string') {
    return false;
  }
  return ALL_KNOWN_TLDS.has(tld.toLowerCase());
}

/**
 * Extract the registrable domain (eTLD+1) from a hostname.
 * Handles multi-part TLDs such as co.kr, co.uk, com.au, etc.
 *
 * @param {string} hostname - Full hostname (e.g. "sub.naver.com" or "blog.example.co.kr")
 * @returns {string} The registrable domain (e.g. "naver.com", "example.co.kr"),
 *                   or the hostname itself if it cannot be decomposed further.
 *
 * @example
 *   extractRegistrableDomain('www.naver.com')        // 'naver.com'
 *   extractRegistrableDomain('sub.example.co.kr')    // 'example.co.kr'
 *   extractRegistrableDomain('deep.sub.bbc.co.uk')   // 'bbc.co.uk'
 *   extractRegistrableDomain('localhost')             // 'localhost'
 */
export function extractRegistrableDomain(hostname) {
  if (!hostname || typeof hostname !== 'string') {
    return hostname ?? '';
  }

  const parts = hostname.toLowerCase().split('.');

  // Single label (e.g. "localhost") — nothing to extract
  if (parts.length <= 1) {
    return hostname;
  }

  // Check for multi-part TLD first (look at the last 2 parts, then last 3, etc.)
  // We only support up to 2-part TLDs in our list, but the approach is extensible.
  if (parts.length >= 3) {
    const candidateTLD = parts.slice(-2).join('.');
    if (MULTI_PART_TLDS.has(candidateTLD)) {
      // The registrable domain is the label just before the multi-part TLD
      if (parts.length >= 3) {
        return parts.slice(-3).join('.');
      }
    }
  }

  // Fallback: treat the last part as the TLD
  // Registrable domain = second-to-last label + TLD
  if (parts.length >= 2) {
    return parts.slice(-2).join('.');
  }

  return hostname;
}

/**
 * Parse a URL string into its structural components, including phishing-relevant
 * metadata such as registrable domain, subdomain, TLD, and IP/localhost detection.
 *
 * @param {string} urlString - The URL to parse (e.g. "https://www.naver.com:443/path?a=1#hash")
 * @returns {{
 *   protocol: string,
 *   hostname: string,
 *   port: string,
 *   pathname: string,
 *   queryParams: Record<string, string>,
 *   hash: string,
 *   domain: string,
 *   subdomain: string,
 *   tld: string,
 *   isIP: boolean,
 *   isLocalhost: boolean
 * }} Parsed URL components
 *
 * @example
 *   parseUrl('https://www.naver.com/search?q=test#top')
 *   // {
 *   //   protocol: 'https:',
 *   //   hostname: 'www.naver.com',
 *   //   port: '',
 *   //   pathname: '/search',
 *   //   queryParams: { q: 'test' },
 *   //   hash: '#top',
 *   //   domain: 'naver.com',
 *   //   subdomain: 'www',
 *   //   tld: 'com',
 *   //   isIP: false,
 *   //   isLocalhost: false,
 *   // }
 */
export function parseUrl(urlString) {
  // Defaults for an unparseable URL
  const empty = {
    protocol: '',
    hostname: '',
    port: '',
    pathname: '',
    queryParams: {},
    hash: '',
    domain: '',
    subdomain: '',
    tld: '',
    isIP: false,
    isLocalhost: false,
  };

  if (!urlString || typeof urlString !== 'string') {
    return empty;
  }

  let url;
  try {
    url = new URL(urlString);
  } catch {
    // If the string is not a valid URL, try prepending https://
    try {
      url = new URL(`https://${urlString}`);
    } catch {
      return empty;
    }
  }

  const protocol = url.protocol; // e.g. "https:"
  const hostname = url.hostname; // e.g. "www.naver.com"
  const port = url.port; // e.g. "443" or ""
  const pathname = url.pathname; // e.g. "/path"
  const hash = url.hash; // e.g. "#section"

  // --- Query parameters ---
  const queryParams = {};
  for (const [key, value] of url.searchParams.entries()) {
    queryParams[key] = value;
  }

  // --- IP address detection ---
  // IPv4: digits and dots, e.g. 192.168.1.1
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  // IPv6: enclosed in brackets in URL hostname representation, or raw colons
  const isIPv4 = ipv4Regex.test(hostname);
  const isIPv6 = hostname.startsWith('[') || /^[0-9a-fA-F:]+$/.test(hostname);
  const isIP = isIPv4 || isIPv6;

  // --- Localhost detection ---
  const isLocalhost =
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname === '[::1]' ||
    hostname === '::1' ||
    hostname === '0.0.0.0';

  // --- Domain decomposition ---
  let domain = '';
  let subdomain = '';
  let tld = '';

  if (!isIP) {
    const lowerHost = hostname.toLowerCase();
    const parts = lowerHost.split('.');

    if (parts.length === 1) {
      // Single-label host (e.g. "localhost")
      domain = lowerHost;
    } else {
      // Determine TLD (check multi-part first)
      let tldParts = 1;
      if (parts.length >= 3) {
        const candidateMulti = parts.slice(-2).join('.');
        if (MULTI_PART_TLDS.has(candidateMulti)) {
          tldParts = 2;
        }
      }

      tld = parts.slice(-tldParts).join('.');
      domain = extractRegistrableDomain(lowerHost);

      // Subdomain: everything before the registrable domain
      if (domain && lowerHost.length > domain.length) {
        // Strip the trailing dot separator from the subdomain portion
        const subPart = lowerHost.slice(0, lowerHost.length - domain.length);
        subdomain = subPart.endsWith('.') ? subPart.slice(0, -1) : subPart;
      }
    }
  }

  return {
    protocol,
    hostname,
    port,
    pathname,
    queryParams,
    hash,
    domain,
    subdomain,
    tld,
    isIP,
    isLocalhost,
  };
}

// ---------------------------------------------------------------------------
// Default export: UrlParser namespace object
// ---------------------------------------------------------------------------

const UrlParser = {
  parseUrl,
  extractRegistrableDomain,
  isKnownTLD,
  decodePunycode,
};

export default UrlParser;
