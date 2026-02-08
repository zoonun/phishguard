/**
 * PhishGuard - Test Suite
 *
 * A standalone test file that exercises the core modules of the PhishGuard
 * Chrome extension without any external test framework.
 *
 * Run with:
 *   node --experimental-vm-modules tests/test.mjs
 */

// ---------------------------------------------------------------------------
// 0. Environment setup -- mock browser globals before any module loads
// ---------------------------------------------------------------------------

// Mock chrome APIs (chrome.runtime.getURL, chrome.storage, etc.)
globalThis.chrome = {
  runtime: {
    getURL: (path) => `chrome-extension://fake-id/${path}`,
    sendMessage: () => {},
    onMessage: { addListener: () => {} },
  },
  storage: {
    local: {
      get: (_keys, cb) => { if (cb) cb({}); return Promise.resolve({}); },
      set: (_items, cb) => { if (cb) cb(); return Promise.resolve(); },
    },
    sync: {
      get: (_keys, cb) => { if (cb) cb({}); return Promise.resolve({}); },
      set: (_items, cb) => { if (cb) cb(); return Promise.resolve(); },
    },
  },
  tabs: {
    query: () => Promise.resolve([]),
    sendMessage: () => Promise.resolve(),
  },
};

// Mock fetch -- returns a minimal known-domains.json payload when requested.
// Individual tests that need TyposquatDetector use _setKnownDomains() directly,
// so this mock mainly prevents runtime errors from _loadKnownDomains().
const MOCK_KNOWN_DOMAINS = {
  domains: [
    {
      name: 'Naver',
      primary: 'naver.com',
      aliases: ['m.naver.com', 'search.naver.com'],
    },
    {
      name: 'Kakao',
      primary: 'kakao.com',
      aliases: ['accounts.kakao.com'],
    },
    {
      name: 'Google',
      primary: 'google.com',
      aliases: ['accounts.google.com', 'mail.google.com'],
    },
  ],
};

globalThis.fetch = async (url) => {
  // Return mock known-domains data for any request that looks like it
  return {
    ok: true,
    status: 200,
    json: async () => MOCK_KNOWN_DOMAINS,
    text: async () => JSON.stringify(MOCK_KNOWN_DOMAINS),
  };
};

// ---------------------------------------------------------------------------
// 1. Inline test runner
// ---------------------------------------------------------------------------

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;
const failures = [];

function assert(condition, message) {
  totalTests++;
  if (condition) {
    passedTests++;
    console.log(`  \x1b[32m\u2705 PASS\x1b[0m  ${message}`);
  } else {
    failedTests++;
    failures.push(message);
    console.log(`  \x1b[31m\u274C FAIL\x1b[0m  ${message}`);
  }
}

function assertEqual(actual, expected, message) {
  const ok = actual === expected;
  assert(ok, ok ? message : `${message} (expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)})`);
}

function assertGreater(actual, threshold, message) {
  const ok = actual > threshold;
  assert(ok, ok ? message : `${message} (expected > ${threshold}, got ${actual})`);
}

function assertGreaterOrEqual(actual, threshold, message) {
  const ok = actual >= threshold;
  assert(ok, ok ? message : `${message} (expected >= ${threshold}, got ${actual})`);
}

function section(title) {
  console.log(`\n\x1b[1m\x1b[36m[${ title }]\x1b[0m`);
}

// ---------------------------------------------------------------------------
// 2. Dynamic imports (ES modules)
// ---------------------------------------------------------------------------

const { default: StringSimilarity, levenshteinDistance, jaroWinklerSimilarity, normalizedSimilarity, homoglyphNormalize, detectTechnique } =
  await import('../utils/string-similarity.js');

const { default: UrlParser, parseUrl, extractRegistrableDomain, isKnownTLD } =
  await import('../utils/url-parser.js');

const { default: TyposquatDetector } =
  await import('../detectors/domain-typosquat.js');

const { default: ProtocolDetector } =
  await import('../detectors/protocol-check.js');

// DetectorManager imports other detectors (domain-age, content-analysis,
// llm-analysis) which may depend on browser APIs. We import it in a
// try/catch so the rest of the suite still runs if those modules fail.
let DetectorManager = null;
try {
  const mod = await import('../detectors/index.js');
  DetectorManager = mod.default;
} catch (err) {
  console.warn(`\x1b[33m[WARN] Could not import DetectorManager: ${err.message}\x1b[0m`);
  console.warn('       Integration tests will be skipped.');
}

// ---------------------------------------------------------------------------
// 3. Test suites
// ---------------------------------------------------------------------------

// ============================
//  String Similarity Tests
// ============================
section('String Similarity');

// Levenshtein distance
assertEqual(
  levenshteinDistance('naver', 'naverr'), 1,
  'levenshteinDistance("naver", "naverr") === 1'
);

assertEqual(
  levenshteinDistance('abc', 'abc'), 0,
  'levenshteinDistance identical strings === 0'
);

assertEqual(
  levenshteinDistance('', 'abc'), 3,
  'levenshteinDistance empty vs "abc" === 3'
);

// Jaro-Winkler similarity
assertGreater(
  jaroWinklerSimilarity('naver', 'naverr'), 0.9,
  'jaroWinklerSimilarity("naver", "naverr") > 0.9'
);

assertEqual(
  jaroWinklerSimilarity('naver', 'naver'), 1,
  'jaroWinklerSimilarity identical strings === 1'
);

assertEqual(
  jaroWinklerSimilarity('', 'naver'), 0,
  'jaroWinklerSimilarity empty vs non-empty === 0'
);

// normalizedSimilarity
assertGreater(
  normalizedSimilarity('naver', 'naverr'), 0.85,
  'normalizedSimilarity("naver", "naverr") > 0.85'
);

assertEqual(
  normalizedSimilarity('naver', 'naver'), 1,
  'normalizedSimilarity identical strings === 1'
);

// homoglyphNormalize
{
  // Cyrillic 'а' (\u0430) -> 'a', Cyrillic 'е' (\u0435) -> 'e'
  const input = 'n\u0430v\u0435r'; // Cyrillic а and е embedded
  const result = homoglyphNormalize(input);
  assertEqual(result, 'naver', `homoglyphNormalize converts Cyrillic lookalikes to ASCII: "${input}" -> "${result}"`);
}

{
  // Cyrillic 'о' (\u043E) -> 'o'
  const input = 'g\u043E\u043Egle';
  const result = homoglyphNormalize(input);
  assertEqual(result, 'google', `homoglyphNormalize("g\\u043E\\u043Egle") -> "google"`);
}

{
  // Pure ASCII should remain unchanged
  const result = homoglyphNormalize('hello');
  assertEqual(result, 'hello', 'homoglyphNormalize leaves pure ASCII unchanged');
}

// detectTechnique
assertEqual(
  detectTechnique('naver', 'naverr'), 'character_repetition',
  'detectTechnique("naver", "naverr") === "character_repetition"'
);

// '0' is in HOMOGLYPH_MAP → 'o', so g00gle normalizes to google → homoglyph
assertEqual(
  detectTechnique('google', 'g00gle'), 'homoglyph',
  'detectTechnique("google", "g00gle") === "homoglyph"'
);

assertEqual(
  detectTechnique('naver.com', 'naver.net'), 'tld_change',
  'detectTechnique("naver.com", "naver.net") === "tld_change"'
);

assertEqual(
  detectTechnique('google.com', 'goo-gle.com'), 'hyphen_insertion',
  'detectTechnique("google.com", "goo-gle.com") === "hyphen_insertion"'
);

assertEqual(
  detectTechnique('naver', 'navre'), 'character_substitution',
  'detectTechnique("naver", "navre") same length transposition === "character_substitution"'
);

assertEqual(
  detectTechnique('google', 'gogle'), 'character_deletion',
  'detectTechnique("google", "gogle") === "character_deletion"'
);

// ============================
//  URL Parser Tests
// ============================
section('URL Parser');

// parseUrl full URL
{
  const result = parseUrl('https://www.naver.com/path?q=test');
  assertEqual(result.protocol, 'https:', 'parseUrl protocol === "https:"');
  assertEqual(result.hostname, 'www.naver.com', 'parseUrl hostname === "www.naver.com"');
  assertEqual(result.pathname, '/path', 'parseUrl pathname === "/path"');
  assertEqual(result.queryParams.q, 'test', 'parseUrl queryParams.q === "test"');
  assertEqual(result.domain, 'naver.com', 'parseUrl domain === "naver.com"');
  assertEqual(result.subdomain, 'www', 'parseUrl subdomain === "www"');
  assertEqual(result.tld, 'com', 'parseUrl tld === "com"');
  assertEqual(result.isIP, false, 'parseUrl isIP === false');
  assertEqual(result.isLocalhost, false, 'parseUrl isLocalhost === false');
}

// extractRegistrableDomain - simple
assertEqual(
  extractRegistrableDomain('sub.naver.com'), 'naver.com',
  'extractRegistrableDomain("sub.naver.com") === "naver.com"'
);

// extractRegistrableDomain - multi-part TLD
assertEqual(
  extractRegistrableDomain('sub.example.co.kr'), 'example.co.kr',
  'extractRegistrableDomain("sub.example.co.kr") === "example.co.kr"'
);

// extractRegistrableDomain - deep subdomain
assertEqual(
  extractRegistrableDomain('deep.sub.bbc.co.uk'), 'bbc.co.uk',
  'extractRegistrableDomain("deep.sub.bbc.co.uk") === "bbc.co.uk"'
);

// extractRegistrableDomain - already registrable
assertEqual(
  extractRegistrableDomain('naver.com'), 'naver.com',
  'extractRegistrableDomain("naver.com") === "naver.com" (already registrable)'
);

// extractRegistrableDomain - single label
assertEqual(
  extractRegistrableDomain('localhost'), 'localhost',
  'extractRegistrableDomain("localhost") === "localhost"'
);

// isKnownTLD
assertEqual(isKnownTLD('com'), true, 'isKnownTLD("com") === true');
assertEqual(isKnownTLD('co.kr'), true, 'isKnownTLD("co.kr") === true');
assertEqual(isKnownTLD('org'), true, 'isKnownTLD("org") === true');
assertEqual(isKnownTLD('xyz123'), false, 'isKnownTLD("xyz123") === false');
assertEqual(isKnownTLD(''), false, 'isKnownTLD("") === false');
assertEqual(isKnownTLD(null), false, 'isKnownTLD(null) === false');

// parseUrl edge cases
{
  const ipResult = parseUrl('http://192.168.1.1:8080/admin');
  assertEqual(ipResult.isIP, true, 'parseUrl detects IPv4 address');
  assertEqual(ipResult.port, '8080', 'parseUrl extracts port "8080"');
}

{
  const localResult = parseUrl('http://localhost:3000/');
  assertEqual(localResult.isLocalhost, true, 'parseUrl detects localhost');
}

// ============================
//  Typosquat Detector Tests
// ============================
section('Typosquat Detector');

// Inject mock known-domains data directly
TyposquatDetector._setKnownDomains(MOCK_KNOWN_DOMAINS);

// "naverr.com" -- character repetition, should flag as similar to naver.com
{
  const result = await TyposquatDetector.analyze({ hostname: 'naverr.com' });
  assertGreaterOrEqual(result.risk, 85, `"naverr.com" risk >= 85 (got ${result.risk})`);
  assertEqual(
    result.details.matchedDomain, 'naver.com',
    '"naverr.com" matched domain === "naver.com"'
  );
}

// "kkakao.com" -- character repetition/insertion, should flag as similar to kakao.com
{
  const result = await TyposquatDetector.analyze({ hostname: 'kkakao.com' });
  assertGreater(result.risk, 0, `"kkakao.com" risk > 0 (got ${result.risk})`);
  assertEqual(
    result.details.matchedDomain, 'kakao.com',
    '"kkakao.com" matched domain === "kakao.com"'
  );
}

// "g00gle.com" -- digit substitution (homoglyph map: '0' -> 'o')
{
  const result = await TyposquatDetector.analyze({ hostname: 'g00gle.com' });
  assertGreater(result.risk, 0, `"g00gle.com" risk > 0 (got ${result.risk})`);
  assertEqual(
    result.details.matchedDomain, 'google.com',
    '"g00gle.com" matched domain === "google.com"'
  );
  // The technique should be homoglyph (since homoglyphNormalize('g00gle') === 'google')
  // or character_substitution depending on the code path
  assert(
    result.details.technique === 'homoglyph' || result.details.technique === 'character_substitution',
    `"g00gle.com" technique is homoglyph or character_substitution (got "${result.details.technique}")`
  );
}

// "naver.com" -- exact match, should be safe
{
  const result = await TyposquatDetector.analyze({ hostname: 'naver.com' });
  assertEqual(result.risk, 0, '"naver.com" exact match risk === 0');
  assertEqual(
    result.details.matchType, 'exact',
    '"naver.com" matchType === "exact"'
  );
}

// "m.naver.com" -- alias, should also be safe
{
  const result = await TyposquatDetector.analyze({ hostname: 'm.naver.com' });
  assertEqual(result.risk, 0, '"m.naver.com" alias match risk === 0');
}

// "naver.com.evil.com" -- subdomain impersonation
{
  const result = await TyposquatDetector.analyze({ hostname: 'naver.com.evil.com' });
  assertGreaterOrEqual(result.risk, 90, `"naver.com.evil.com" risk >= 90 (got ${result.risk})`);
  assertEqual(
    result.details.technique, 'subdomain_impersonation',
    '"naver.com.evil.com" technique === "subdomain_impersonation"'
  );
}

// ============================
//  Protocol Detector Tests
// ============================
section('Protocol Detector');

// HTTP without sensitive forms -> risk 40
{
  const result = await ProtocolDetector.analyze({
    protocol: 'http:',
    domContent: null,
  });
  assertEqual(result.risk, 40, 'HTTP without forms: risk === 40');
  assertEqual(result.details.issue, 'no_encryption', 'HTTP issue === "no_encryption"');
}

// HTTP with password form -> risk 80
{
  const result = await ProtocolDetector.analyze({
    protocol: 'http:',
    domContent: {
      forms: [
        {
          inputs: [
            { type: 'text', name: 'username', placeholder: '' },
            { type: 'password', name: 'password', placeholder: '' },
          ],
        },
      ],
    },
  });
  assertEqual(result.risk, 80, 'HTTP with password form: risk === 80');
  assertEqual(result.details.issue, 'sensitive_form_on_http', 'HTTP+password issue === "sensitive_form_on_http"');
  assert(
    result.details.formTypes.includes('password'),
    'HTTP+password formTypes includes "password"'
  );
}

// HTTPS -> risk 0
{
  const result = await ProtocolDetector.analyze({
    protocol: 'https:',
    domContent: null,
  });
  assertEqual(result.risk, 0, 'HTTPS: risk === 0');
  assertEqual(result.details.issue, 'none', 'HTTPS issue === "none"');
}

// HTTPS with mixed content
{
  const result = await ProtocolDetector.analyze({
    protocol: 'https:',
    domContent: {
      externalResources: [
        'http://insecure.cdn.com/script.js',
        'https://safe.cdn.com/style.css',
      ],
    },
  });
  assertEqual(result.risk, 30, 'HTTPS with mixed content: risk === 30');
  assertEqual(result.details.issue, 'mixed_content', 'HTTPS mixed content issue === "mixed_content"');
}

// Unusual protocol (file:)
{
  const result = await ProtocolDetector.analyze({
    protocol: 'file:',
    domContent: null,
  });
  assertEqual(result.risk, 20, 'file: protocol risk === 20');
  assertEqual(result.details.issue, 'unusual_protocol', 'file: issue === "unusual_protocol"');
}

// ============================
//  Integration Tests (DetectorManager)
// ============================
section('Integration (DetectorManager)');

if (DetectorManager) {
  // Pre-inject known domains for the TyposquatDetector used inside DetectorManager
  TyposquatDetector._setKnownDomains(MOCK_KNOWN_DOMAINS);

  // "http://naverr.com" -- typosquat + HTTP => very high risk
  {
    const result = await DetectorManager.analyze(
      {
        url: 'http://naverr.com',
        hostname: 'naverr.com',
        protocol: 'http:',
        pathname: '/',
        domContent: null,
      },
      {
        enableLLM: false,
        enabledDetectors: {
          typosquat: true,
          protocol: true,
          domainAge: false,
          contentAnalysis: false,
          llmAnalysis: false,
        },
      }
    );

    assertGreaterOrEqual(
      result.totalRisk, 70,
      `"http://naverr.com" integration totalRisk >= 70 (got ${result.totalRisk})`
    );
    assertEqual(
      result.riskLevel, 'danger',
      `"http://naverr.com" riskLevel === "danger" (got "${result.riskLevel}")`
    );
  }

  // "https://naver.com" -- exact match + HTTPS => all safe
  {
    const result = await DetectorManager.analyze(
      {
        url: 'https://naver.com',
        hostname: 'naver.com',
        protocol: 'https:',
        pathname: '/',
        domContent: null,
      },
      {
        enableLLM: false,
        enabledDetectors: {
          typosquat: true,
          protocol: true,
          domainAge: false,
          contentAnalysis: false,
          llmAnalysis: false,
        },
      }
    );

    assertEqual(result.totalRisk, 0, '"https://naver.com" integration totalRisk === 0');
    assertEqual(
      result.riskLevel, 'safe',
      `"https://naver.com" riskLevel === "safe" (got "${result.riskLevel}")`
    );
  }
} else {
  console.log('  \x1b[33m[SKIPPED]\x1b[0m DetectorManager could not be imported; integration tests skipped.');
}

// ---------------------------------------------------------------------------
// 4. Summary
// ---------------------------------------------------------------------------

console.log('\n' + '='.repeat(60));
console.log(`\x1b[1mTest Summary\x1b[0m`);
console.log('='.repeat(60));
console.log(`  Total:   ${totalTests}`);
console.log(`  \x1b[32mPassed:  ${passedTests}\x1b[0m`);
console.log(`  \x1b[31mFailed:  ${failedTests}\x1b[0m`);

if (failures.length > 0) {
  console.log(`\n\x1b[31mFailed tests:\x1b[0m`);
  for (const f of failures) {
    console.log(`  - ${f}`);
  }
}

console.log('='.repeat(60));

// Exit with non-zero code if any test failed
if (failedTests > 0) {
  process.exit(1);
}
