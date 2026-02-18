/**
 * PhishGuard - 타이포스쿼팅 감지 모듈
 * 유명 사이트 도메인과 유사한 피싱 도메인 감지
 */

import StringSimilarity from '../utils/string-similarity.js';
import Logger from '../utils/logger.js';

// known-domains.json은 서비스 워커에서 로드하여 전달하거나 fetch로 로드
let knownDomainsCache = null;

const TyposquatDetector = {
  name: 'TyposquatDetector',
  weight: 0.4,

  // 유사도 임계값
  SIMILARITY_THRESHOLD: 0.85,

  async analyze(context) {
    const { hostname } = context;

    Logger.debug(`[TyposquatDetector] Analyzing: ${hostname}`);

    try {
      // 정규 도메인 목록 로드
      const knownDomains = await this._loadKnownDomains();

      // 현재 도메인의 기본 도메인 추출 (서브도메인 제거)
      const currentDomain = this._extractBaseDomain(hostname);

      // 1. 정확히 일치하는 도메인 확인 (안전)
      const exactMatch = this._findExactMatch(hostname, knownDomains);
      if (exactMatch) {
        return {
          risk: 0,
          confidence: 1.0,
          reason: `${exactMatch.name}(${exactMatch.primary})의 정식 도메인 또는 공식 하위 도메인입니다.`,
          details: {
            matchedDomain: exactMatch.primary,
            matchType: 'exact',
            domainName: exactMatch.name
          }
        };
      }

      // 2. 서브도메인 위장 감지 (naver.com.evil.com 형태)
      const subdomainResult = this._checkSubdomainImpersonation(hostname, knownDomains);
      if (subdomainResult) {
        return subdomainResult;
      }

      // 3. 동형문자(homoglyph) 감지
      const normalizedHostname = StringSimilarity.homoglyphNormalize(currentDomain);
      if (normalizedHostname !== currentDomain) {
        const homoglyphMatch = this._findBestMatch(normalizedHostname, knownDomains);
        if (homoglyphMatch && homoglyphMatch.similarity >= this.SIMILARITY_THRESHOLD) {
          return {
            risk: 95,
            confidence: 0.95,
            reason: `이 도메인은 '${homoglyphMatch.domain}'과 시각적으로 유사한 동형문자(homoglyph)를 사용합니다. 피싱 사이트가 의심됩니다.`,
            details: {
              matchedDomain: homoglyphMatch.domain,
              similarity: homoglyphMatch.similarity,
              technique: 'homoglyph',
              originalDomain: currentDomain,
              normalizedDomain: normalizedHostname,
              domainName: homoglyphMatch.name
            }
          };
        }
      }

      // 4. 일반 유사도 검사 (Levenshtein + Jaro-Winkler)
      const bestMatch = this._findBestMatch(currentDomain, knownDomains);

      if (bestMatch && bestMatch.similarity >= this.SIMILARITY_THRESHOLD) {
        const technique = StringSimilarity.detectTechnique(
          bestMatch.domainBase,
          this._getDomainWithoutTLD(currentDomain)
        );

        // TLD 변경 감지 (naver.com vs naver.net)
        const tldChanged = this._checkTLDChange(currentDomain, bestMatch.domain);
        const finalTechnique = tldChanged ? 'tld_change' : technique;

        const risk = this._calculateRisk(bestMatch.similarity, finalTechnique);

        return {
          risk,
          confidence: Math.min(0.95, bestMatch.similarity),
          reason: `이 도메인은 '${bestMatch.domain}'과 매우 유사합니다 (${currentDomain}). 타이포스쿼팅 피싱이 의심됩니다.`,
          details: {
            matchedDomain: bestMatch.domain,
            similarity: Math.round(bestMatch.similarity * 100) / 100,
            technique: finalTechnique,
            domainName: bestMatch.name
          }
        };
      }

      // 5. 하이픈 삽입 감지 (naver-login.com)
      const hyphenResult = this._checkHyphenInsertion(currentDomain, knownDomains);
      if (hyphenResult) {
        return hyphenResult;
      }

      // 위험 없음
      return {
        risk: 0,
        confidence: 0.8,
        reason: '알려진 도메인과의 유사성이 감지되지 않았습니다.',
        details: {
          bestMatch: bestMatch ? {
            domain: bestMatch.domain,
            similarity: Math.round(bestMatch.similarity * 100) / 100
          } : null
        }
      };
    } catch (error) {
      Logger.error(`[TyposquatDetector] Error:`, error);
      return {
        risk: 0,
        confidence: 0,
        reason: '타이포스쿼팅 검사 중 오류가 발생했습니다.',
        details: { error: error.message }
      };
    }
  },

  /**
   * known-domains.json 로드
   */
  async _loadKnownDomains() {
    if (knownDomainsCache) return knownDomainsCache;

    try {
      // Chrome 익스텐션 환경
      if (typeof chrome !== 'undefined' && chrome.runtime?.getURL) {
        const url = chrome.runtime.getURL('rag/known-domains.json');
        const response = await fetch(url);
        knownDomainsCache = await response.json();
        return knownDomainsCache;
      }

      // 직접 import (테스트 환경)
      const response = await fetch('./rag/known-domains.json');
      knownDomainsCache = await response.json();
      return knownDomainsCache;
    } catch (error) {
      Logger.error(`[TyposquatDetector] Failed to load known domains:`, error);
      return { domains: [] };
    }
  },

  /**
   * 정확한 도메인 매칭 확인
   */
  _findExactMatch(hostname, data) {
    for (const entry of data.domains) {
      // primary 도메인 일치
      if (hostname === entry.primary || hostname.endsWith('.' + entry.primary)) {
        return entry;
      }
      // aliases 일치
      if (entry.aliases) {
        for (const alias of entry.aliases) {
          if (hostname === alias || hostname.endsWith('.' + alias)) {
            return entry;
          }
        }
      }
    }
    return null;
  },

  /**
   * 서브도메인 위장 감지 (naver.com.evil.com 형태)
   */
  _checkSubdomainImpersonation(hostname, data) {
    const parts = hostname.split('.');

    for (const entry of data.domains) {
      const brandDomain = entry.primary;
      // hostname이 brandDomain을 포함하지만, 실제로 해당 도메인이 아닌 경우
      // 예: naver.com.evil.com → "naver.com"을 포함하지만 evil.com 도메인
      if (hostname.includes(brandDomain) && !hostname.endsWith(brandDomain)) {
        return {
          risk: 95,
          confidence: 0.95,
          reason: `이 도메인(${hostname})은 '${brandDomain}'을 서브도메인으로 위장하고 있습니다. 피싱 사이트가 강하게 의심됩니다.`,
          details: {
            matchedDomain: brandDomain,
            similarity: 0.95,
            technique: 'subdomain_impersonation',
            domainName: entry.name
          }
        };
      }

      // 브랜드명이 서브도메인에 있는 경우 (naver.evil-domain.com)
      const brandName = brandDomain.split('.')[0];
      const genericSubdomains = [
        'www', 'm', 'mail', 'blog', 'shop', 'store', 'pay', 'login',
        'auth', 'api', 'app', 'web', 'map', 'maps', 'news', 'search',
        'tv', 'music', 'open', 'dev', 'story', 'cafe', 'card', 'order',
        'my', 'id', 'help', 'support', 'about', 'admin', 'portal',
        'cloud', 'drive', 'docs', 'meet', 'teams', 'chat'
      ];
      if (parts.length > 2 && parts[0] === brandName && !hostname.endsWith(brandDomain) && !genericSubdomains.includes(brandName)) {
        return {
          risk: 90,
          confidence: 0.9,
          reason: `이 도메인(${hostname})은 서브도메인에 '${brandName}'을 사용하여 ${entry.name}을(를) 위장하고 있습니다.`,
          details: {
            matchedDomain: brandDomain,
            similarity: 0.9,
            technique: 'subdomain_impersonation',
            domainName: entry.name
          }
        };
      }
    }
    return null;
  },

  /**
   * 하이픈 삽입 감지 (naver-login.com)
   */
  _checkHyphenInsertion(currentDomain, data) {
    if (!currentDomain.includes('-')) return null;

    const domainWithoutTLD = this._getDomainWithoutTLD(currentDomain);
    const withoutHyphens = domainWithoutTLD.replace(/-/g, '');

    for (const entry of data.domains) {
      const brandBase = entry.primary.split('.')[0];

      // 하이픈 제거 시 브랜드명을 포함하는 경우
      if (withoutHyphens.includes(brandBase) || brandBase.includes(withoutHyphens)) {
        const similarity = StringSimilarity.normalizedSimilarity(withoutHyphens, brandBase);
        if (similarity >= 0.7) {
          return {
            risk: 85,
            confidence: 0.85,
            reason: `이 도메인(${currentDomain})은 '${entry.primary}'에 하이픈을 삽입한 형태입니다. 피싱이 의심됩니다.`,
            details: {
              matchedDomain: entry.primary,
              similarity: Math.round(similarity * 100) / 100,
              technique: 'hyphen_insertion',
              domainName: entry.name
            }
          };
        }
      }
    }
    return null;
  },

  /**
   * 최적 매칭 도메인 검색
   */
  _findBestMatch(domain, data) {
    let best = null;
    const domainBase = this._getDomainWithoutTLD(domain);

    for (const entry of data.domains) {
      const primaryBase = entry.primary.split('.')[0];
      const similarity = StringSimilarity.normalizedSimilarity(domainBase, primaryBase);

      if (!best || similarity > best.similarity) {
        best = {
          domain: entry.primary,
          domainBase: primaryBase,
          name: entry.name,
          similarity
        };
      }
    }

    return best;
  },

  /**
   * TLD 변경 감지
   */
  _checkTLDChange(currentDomain, knownDomain) {
    const currentBase = this._getDomainWithoutTLD(currentDomain);
    const knownBase = knownDomain.split('.')[0];
    const currentTLD = this._getTLD(currentDomain);
    const knownTLD = this._getTLD(knownDomain);

    return currentBase === knownBase && currentTLD !== knownTLD;
  },

  /**
   * 기법별 위험도 산출
   */
  _calculateRisk(similarity, technique) {
    const baseRisk = Math.round(similarity * 100);

    const techniqueBonus = {
      'homoglyph': 5,
      'subdomain_impersonation': 5,
      'character_substitution': 3,
      'character_repetition': 2,
      'character_insertion': 2,
      'character_deletion': 3,
      'tld_change': 4,
      'hyphen_insertion': 2
    };

    return Math.min(100, baseRisk + (techniqueBonus[technique] || 0));
  },

  /**
   * 기본 도메인 추출 (서브도메인 제거)
   */
  _extractBaseDomain(hostname) {
    const multiPartTLDs = [
      'co.kr', 'co.jp', 'co.uk', 'com.au', 'com.br', 'co.in',
      'or.kr', 'go.kr', 'ac.kr', 'ne.kr', 'or.jp', 'ac.jp'
    ];

    for (const tld of multiPartTLDs) {
      if (hostname.endsWith('.' + tld)) {
        const withoutTLD = hostname.slice(0, -(tld.length + 1));
        const parts = withoutTLD.split('.');
        return parts[parts.length - 1] + '.' + tld;
      }
    }

    const parts = hostname.split('.');
    if (parts.length >= 2) {
      return parts.slice(-2).join('.');
    }
    return hostname;
  },

  /**
   * TLD 없이 도메인명만 추출
   */
  _getDomainWithoutTLD(domain) {
    return domain.split('.')[0];
  },

  /**
   * TLD 추출
   */
  _getTLD(domain) {
    const parts = domain.split('.');
    return parts.slice(1).join('.');
  },

  /**
   * 캐시 초기화 (테스트용)
   */
  _clearCache() {
    knownDomainsCache = null;
  },

  /**
   * 도메인 데이터 직접 설정 (테스트용)
   */
  _setKnownDomains(data) {
    knownDomainsCache = data;
  }
};

export default TyposquatDetector;
