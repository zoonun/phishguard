/**
 * PhishGuard - String Similarity Utility Module
 *
 * Provides algorithms and heuristics for detecting typosquatting and
 * domain impersonation techniques used in phishing attacks.
 */

// ---------------------------------------------------------------------------
// Homoglyph Mapping Table
// ---------------------------------------------------------------------------
// Maps visually similar Unicode characters to their ASCII equivalents.
// Covers Cyrillic confusables, Greek confusables, and common digit/letter
// lookalikes.

const HOMOGLYPH_MAP = new Map([
  // Cyrillic -> Latin
  ['\u0430', 'a'], // а -> a
  ['\u0435', 'e'], // е -> e
  ['\u043E', 'o'], // о -> o
  ['\u0440', 'p'], // р -> p
  ['\u0441', 'c'], // с -> c
  ['\u0443', 'y'], // у -> y
  ['\u0445', 'x'], // х -> x
  ['\u0456', 'i'], // і -> i  (Ukrainian i)
  ['\u0458', 'j'], // ј -> j  (Serbian je)
  ['\u04BB', 'h'], // һ -> h  (Bashkir/Chuvash)
  ['\u0455', 's'], // ѕ -> s  (Macedonian dze)
  ['\u0454', 'e'], // є -> e  (Ukrainian ie)
  ['\u0457', 'i'], // ї -> i  (Ukrainian yi)
  ['\u0491', 'g'], // ґ -> g  (Ukrainian ghe)
  ['\u044C', 'b'], // ь -> b  (soft sign, visual)
  ['\u043A', 'k'], // к -> k
  ['\u043C', 'm'], // м -> m  (visual similarity in some fonts)
  ['\u0442', 't'], // т -> t  (visual similarity in some fonts)
  ['\u043D', 'h'], // н -> h  (visual similarity)
  ['\u0412', 'B'], // В -> B
  ['\u041D', 'H'], // Н -> H
  ['\u0410', 'A'], // А -> A
  ['\u0415', 'E'], // Е -> E
  ['\u041E', 'O'], // О -> O
  ['\u0420', 'P'], // Р -> P
  ['\u0421', 'C'], // С -> C
  ['\u0422', 'T'], // Т -> T
  ['\u0425', 'X'], // Х -> X
  ['\u041C', 'M'], // М -> M
  ['\u041A', 'K'], // К -> K

  // Greek -> Latin
  ['\u03BF', 'o'], // ο -> o
  ['\u03B1', 'a'], // α -> a  (visual similarity)
  ['\u03B5', 'e'], // ε -> e  (visual similarity in some fonts)
  ['\u03B9', 'i'], // ι -> i
  ['\u03BA', 'k'], // κ -> k
  ['\u03BD', 'v'], // ν -> v
  ['\u03C1', 'p'], // ρ -> p
  ['\u03C4', 't'], // τ -> t
  ['\u03C5', 'u'], // υ -> u
  ['\u03C9', 'w'], // ω -> w
  ['\u0391', 'A'], // Α -> A
  ['\u0392', 'B'], // Β -> B
  ['\u0395', 'E'], // Ε -> E
  ['\u0396', 'Z'], // Ζ -> Z
  ['\u0397', 'H'], // Η -> H
  ['\u0399', 'I'], // Ι -> I
  ['\u039A', 'K'], // Κ -> K
  ['\u039C', 'M'], // Μ -> M
  ['\u039D', 'N'], // Ν -> N
  ['\u039F', 'O'], // Ο -> O
  ['\u03A1', 'P'], // Ρ -> P
  ['\u03A4', 'T'], // Τ -> T
  ['\u03A5', 'Y'], // Υ -> Y
  ['\u03A7', 'X'], // Χ -> X

  // Digit / letter lookalikes
  ['0', 'o'],
  ['1', 'l'],
  ['!', 'l'],
  ['|', 'l'],

  // Latin extended / special
  ['\u0131', 'i'], // ı (dotless i)
  ['\u1E9A', 'a'], // ẚ -> a
  ['\u00E0', 'a'], // à -> a
  ['\u00E1', 'a'], // á -> a
  ['\u00E2', 'a'], // â -> a
  ['\u00E3', 'a'], // ã -> a
  ['\u00E4', 'a'], // ä -> a
  ['\u00E5', 'a'], // å -> a
  ['\u00E8', 'e'], // è -> e
  ['\u00E9', 'e'], // é -> e
  ['\u00EA', 'e'], // ê -> e
  ['\u00EB', 'e'], // ë -> e
  ['\u00EC', 'i'], // ì -> i
  ['\u00ED', 'i'], // í -> i
  ['\u00EE', 'i'], // î -> i
  ['\u00EF', 'i'], // ï -> i
  ['\u00F2', 'o'], // ò -> o
  ['\u00F3', 'o'], // ó -> o
  ['\u00F4', 'o'], // ô -> o
  ['\u00F5', 'o'], // õ -> o
  ['\u00F6', 'o'], // ö -> o
  ['\u00F9', 'u'], // ù -> u
  ['\u00FA', 'u'], // ú -> u
  ['\u00FB', 'u'], // û -> u
  ['\u00FC', 'u'], // ü -> u

  // Fullwidth Latin
  ['\uFF41', 'a'], // ａ -> a
  ['\uFF42', 'b'], // ｂ -> b
  ['\uFF43', 'c'], // ｃ -> c
  ['\uFF44', 'd'], // ｄ -> d
  ['\uFF45', 'e'], // ｅ -> e
  ['\uFF46', 'f'], // ｆ -> f
  ['\uFF47', 'g'], // ｇ -> g
  ['\uFF48', 'h'], // ｈ -> h
  ['\uFF49', 'i'], // ｉ -> i
  ['\uFF4A', 'j'], // ｊ -> j
  ['\uFF4B', 'k'], // ｋ -> k
  ['\uFF4C', 'l'], // ｌ -> l
  ['\uFF4D', 'm'], // ｍ -> m
  ['\uFF4E', 'n'], // ｎ -> n
  ['\uFF4F', 'o'], // ｏ -> o
  ['\uFF50', 'p'], // ｐ -> p
  ['\uFF51', 'q'], // ｑ -> q
  ['\uFF52', 'r'], // ｒ -> r
  ['\uFF53', 's'], // ｓ -> s
  ['\uFF54', 't'], // ｔ -> t
  ['\uFF55', 'u'], // ｕ -> u
  ['\uFF56', 'v'], // ｖ -> v
  ['\uFF57', 'w'], // ｗ -> w
  ['\uFF58', 'x'], // ｘ -> x
  ['\uFF59', 'y'], // ｙ -> y
  ['\uFF5A', 'z'], // ｚ -> z
]);

// ---------------------------------------------------------------------------
// Levenshtein Distance
// ---------------------------------------------------------------------------
// Calculates the minimum number of single-character edits (insertions,
// deletions, or substitutions) required to change string `a` into string `b`.

/**
 * @param {string} a - First string.
 * @param {string} b - Second string.
 * @returns {number} The edit distance between `a` and `b`.
 */
export function levenshteinDistance(a, b) {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  // Use two-row optimisation to keep memory at O(min(m, n)).
  if (a.length > b.length) {
    [a, b] = [b, a];
  }

  const aLen = a.length;
  const bLen = b.length;

  let prevRow = new Array(aLen + 1);
  let currRow = new Array(aLen + 1);

  for (let i = 0; i <= aLen; i++) {
    prevRow[i] = i;
  }

  for (let j = 1; j <= bLen; j++) {
    currRow[0] = j;
    for (let i = 1; i <= aLen; i++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      currRow[i] = Math.min(
        currRow[i - 1] + 1,       // insertion
        prevRow[i] + 1,           // deletion
        prevRow[i - 1] + cost     // substitution
      );
    }
    [prevRow, currRow] = [currRow, prevRow];
  }

  return prevRow[aLen];
}

// ---------------------------------------------------------------------------
// Jaro-Winkler Similarity
// ---------------------------------------------------------------------------
// Returns a value between 0 (no similarity) and 1 (exact match).  The Jaro
// base score is boosted when the strings share a common prefix (up to 4
// characters), which is especially useful for domain name comparison.

/**
 * @param {string} a - First string.
 * @param {string} b - Second string.
 * @param {number} [prefixScale=0.1] - Scaling factor for prefix bonus (max 0.25).
 * @returns {number} Jaro-Winkler similarity in the range [0, 1].
 */
export function jaroWinklerSimilarity(a, b, prefixScale = 0.1) {
  if (a === b) return 1;
  if (a.length === 0 || b.length === 0) return 0;

  const aLen = a.length;
  const bLen = b.length;

  // Maximum distance for a character to be considered matching.
  const matchWindow = Math.max(0, Math.floor(Math.max(aLen, bLen) / 2) - 1);

  const aMatches = new Array(aLen).fill(false);
  const bMatches = new Array(bLen).fill(false);

  let matches = 0;
  let transpositions = 0;

  // --- Find matching characters ---
  for (let i = 0; i < aLen; i++) {
    const start = Math.max(0, i - matchWindow);
    const end = Math.min(bLen - 1, i + matchWindow);

    for (let j = start; j <= end; j++) {
      if (bMatches[j] || a[i] !== b[j]) continue;
      aMatches[i] = true;
      bMatches[j] = true;
      matches++;
      break;
    }
  }

  if (matches === 0) return 0;

  // --- Count transpositions ---
  let k = 0;
  for (let i = 0; i < aLen; i++) {
    if (!aMatches[i]) continue;
    while (!bMatches[k]) k++;
    if (a[i] !== b[k]) transpositions++;
    k++;
  }

  const jaro =
    (matches / aLen + matches / bLen + (matches - transpositions / 2) / matches) / 3;

  // --- Winkler prefix bonus ---
  let prefixLength = 0;
  const maxPrefix = Math.min(4, Math.min(aLen, bLen));
  for (let i = 0; i < maxPrefix; i++) {
    if (a[i] === b[i]) {
      prefixLength++;
    } else {
      break;
    }
  }

  // Clamp prefixScale to a maximum of 0.25 per the original paper.
  const pScale = Math.min(prefixScale, 0.25);

  return jaro + prefixLength * pScale * (1 - jaro);
}

// ---------------------------------------------------------------------------
// Normalized Similarity
// ---------------------------------------------------------------------------
// Combines Levenshtein-based similarity and Jaro-Winkler similarity into a
// single 0-1 score via a weighted average.  The Jaro-Winkler component is
// weighted more heavily because prefix-aware matching is particularly
// effective at catching typosquatting domains.

/**
 * @param {string} a - First string.
 * @param {string} b - Second string.
 * @param {number} [jwWeight=0.6] - Weight for the Jaro-Winkler score.
 * @returns {number} Combined similarity in the range [0, 1].
 */
export function normalizedSimilarity(a, b, jwWeight = 0.6) {
  if (a === b) return 1;
  if (a.length === 0 && b.length === 0) return 1;
  if (a.length === 0 || b.length === 0) return 0;

  const levWeight = 1 - jwWeight;

  // Levenshtein-based similarity: 1 - (distance / maxLength).
  const maxLen = Math.max(a.length, b.length);
  const levDistance = levenshteinDistance(a, b);
  const levSimilarity = 1 - levDistance / maxLen;

  const jwSimilarity = jaroWinklerSimilarity(a, b);

  return levWeight * levSimilarity + jwWeight * jwSimilarity;
}

// ---------------------------------------------------------------------------
// Homoglyph Normalisation
// ---------------------------------------------------------------------------
// Replaces visually similar Unicode characters with their ASCII equivalents
// so that strings like "gооgle.com" (with Cyrillic о) normalise to the same
// form as "google.com".

/**
 * @param {string} str - Input string potentially containing homoglyphs.
 * @returns {string} String with homoglyphs replaced by ASCII equivalents.
 */
export function homoglyphNormalize(str) {
  let result = '';
  for (const char of str) {
    const replacement = HOMOGLYPH_MAP.get(char);
    result += replacement !== undefined ? replacement : char;
  }
  return result;
}

// ---------------------------------------------------------------------------
// Typosquatting Technique Detection
// ---------------------------------------------------------------------------
// Analyses a suspect domain string against an original (legitimate) domain
// and returns the most likely typosquatting technique being employed.

/**
 * @param {string} original - The legitimate domain (e.g. "google.com").
 * @param {string} suspect  - The suspect domain  (e.g. "g00gle.com").
 * @returns {'character_repetition'|'character_substitution'|'character_insertion'|'character_deletion'|'homoglyph'|'tld_change'|'hyphen_insertion'|'subdomain_impersonation'}
 */
export function detectTechnique(original, suspect) {
  // --- Helper: split domain into (name, tld) ---
  const splitDomain = (domain) => {
    const parts = domain.split('.');
    if (parts.length < 2) return { name: domain, tld: '' };
    const tld = parts.slice(-1)[0];
    const name = parts.slice(0, -1).join('.');
    return { name, tld };
  };

  const origParts = splitDomain(original);
  const suspParts = splitDomain(suspect);

  // ---- 1. Subdomain impersonation ----
  // The suspect has more subdomains and one of them contains the original name.
  // e.g. "google.evil.com" when the original is "google.com"
  const suspSubdomains = suspect.split('.');
  const origSubdomains = original.split('.');
  if (suspSubdomains.length > origSubdomains.length) {
    const suspLabels = suspSubdomains.slice(0, -1); // everything except TLD
    const origBase = origParts.name.replace(/\./g, '');
    const hasImpersonation = suspLabels.some(
      (label) => label.includes(origBase) || origBase.includes(label)
    );
    if (hasImpersonation && suspSubdomains.length >= 3) {
      return 'subdomain_impersonation';
    }
  }

  // ---- 2. TLD change ----
  // Same name, different TLD. e.g. "google.net" vs "google.com"
  if (
    origParts.name === suspParts.name &&
    origParts.tld !== '' &&
    suspParts.tld !== '' &&
    origParts.tld !== suspParts.tld
  ) {
    return 'tld_change';
  }

  // For the remaining techniques we compare the domain name portions only
  // (ignoring TLD differences).
  const origName = origParts.name;
  const suspName = suspParts.name;

  // ---- 3. Homoglyph attack ----
  // After normalising homoglyphs, the names become identical but they
  // differ in their raw form.
  if (origName !== suspName) {
    const normOrig = homoglyphNormalize(origName).toLowerCase();
    const normSusp = homoglyphNormalize(suspName).toLowerCase();
    if (normOrig === normSusp) {
      return 'homoglyph';
    }
  }

  // ---- 4. Hyphen insertion ----
  // The suspect has hyphens that the original does not (or vice-versa).
  // e.g. "goo-gle.com" vs "google.com"
  const origHyphens = (origName.match(/-/g) || []).length;
  const suspHyphens = (suspName.match(/-/g) || []).length;
  if (suspHyphens > origHyphens && suspName.replace(/-/g, '') === origName.replace(/-/g, '')) {
    return 'hyphen_insertion';
  }

  // ---- 5. Character repetition ----
  // A character that exists in the original is doubled (or tripled, etc.)
  // in the suspect. e.g. "gooogle.com" vs "google.com"
  // Check by collapsing consecutive duplicate characters and comparing.
  const collapseRepeats = (s) => s.replace(/(.)\1+/g, '$1');
  if (
    origName !== suspName &&
    collapseRepeats(origName) === collapseRepeats(suspName) &&
    suspName.length > origName.length
  ) {
    return 'character_repetition';
  }

  // ---- 6. Character insertion / deletion / substitution ----
  // Use edit distance to discriminate between these.
  const distance = levenshteinDistance(origName, suspName);

  if (distance > 0) {
    const lenDiff = suspName.length - origName.length;

    if (lenDiff > 0) {
      // Suspect is longer -> likely insertion(s).
      // Verify by checking if removing characters from suspect can yield original.
      return 'character_insertion';
    }

    if (lenDiff < 0) {
      // Suspect is shorter -> likely deletion(s).
      return 'character_deletion';
    }

    // Same length but different characters -> substitution.
    return 'character_substitution';
  }

  // Fallback — domains may differ only in TLD while also having name differences
  // already handled above. Default to substitution as the most general category.
  return 'character_substitution';
}

// ---------------------------------------------------------------------------
// Default export — single object gathering all utilities
// ---------------------------------------------------------------------------

const StringSimilarity = {
  levenshteinDistance,
  jaroWinklerSimilarity,
  normalizedSimilarity,
  homoglyphNormalize,
  detectTechnique,
};

export default StringSimilarity;
