/**
 * PhishGuard - RAG 엔진
 * 로컬 JSON DB를 검색하여 LLM 프롬프트에 포함할 관련 컨텍스트를 구성
 */

import { normalizedSimilarity } from '../utils/string-similarity.js';
import Logger from '../utils/logger.js';

let knownDomainsData = null;
let phishingPatternsData = null;

const RAGEngine = {
  /**
   * 데이터 로드
   */
  async _loadData() {
    if (knownDomainsData && phishingPatternsData) return;

    try {
      if (typeof chrome !== 'undefined' && chrome.runtime?.getURL) {
        const [domainsResp, patternsResp] = await Promise.all([
          fetch(chrome.runtime.getURL('rag/known-domains.json')),
          fetch(chrome.runtime.getURL('rag/phishing-patterns.json'))
        ]);
        knownDomainsData = await domainsResp.json();
        phishingPatternsData = await patternsResp.json();
      } else {
        const [domainsResp, patternsResp] = await Promise.all([
          fetch('./rag/known-domains.json'),
          fetch('./rag/phishing-patterns.json')
        ]);
        knownDomainsData = await domainsResp.json();
        phishingPatternsData = await patternsResp.json();
      }
    } catch (error) {
      Logger.error('[RAGEngine] Failed to load data:', error);
      knownDomainsData = { domains: [] };
      phishingPatternsData = { patterns: [], keywords: {} };
    }
  },

  /**
   * 유사 정규 도메인 검색
   * @param {string} hostname - 검사 대상 호스트명
   * @returns {Array} 유사 도메인 목록
   */
  async findSimilarDomains(hostname) {
    await this._loadData();

    const baseDomain = this._extractBase(hostname);
    const results = [];

    for (const entry of knownDomainsData.domains) {
      const primaryBase = entry.primary.split('.')[0];
      const similarity = normalizedSimilarity(baseDomain, primaryBase);

      if (similarity >= 0.6) {
        results.push({
          name: entry.name,
          domain: entry.primary,
          category: entry.category,
          similarity: Math.round(similarity * 100) / 100,
          isExactMatch: hostname === entry.primary ||
                        hostname.endsWith('.' + entry.primary) ||
                        (entry.aliases || []).some(a => hostname === a || hostname.endsWith('.' + a))
        });
      }
    }

    return results.sort((a, b) => b.similarity - a.similarity).slice(0, 5);
  },

  /**
   * 피싱 패턴 매칭
   * @param {string} url - 전체 URL
   * @param {string} content - 페이지 텍스트 콘텐츠
   * @returns {Array} 매칭된 패턴 목록
   */
  async matchPhishingPatterns(url, content) {
    await this._loadData();

    const matched = [];

    // URL 패턴 매칭
    for (const pattern of phishingPatternsData.patterns) {
      if (pattern.type === 'url_pattern' && pattern.pattern) {
        try {
          const regex = new RegExp(pattern.pattern, 'i');
          if (regex.test(url)) {
            matched.push({
              id: pattern.id,
              type: pattern.type,
              description: pattern.description,
              riskWeight: pattern.risk_weight,
              matchedIn: 'url'
            });
          }
        } catch {
          // 잘못된 정규식 무시
        }
      }
    }

    // 콘텐츠 키워드 매칭
    if (content) {
      const contentLower = content.toLowerCase();
      const keywordMatches = {};

      for (const [category, keywords] of Object.entries(phishingPatternsData.keywords)) {
        const found = keywords.filter(kw => contentLower.includes(kw.toLowerCase()));
        if (found.length > 0) {
          keywordMatches[category] = found;
        }
      }

      if (Object.keys(keywordMatches).length > 0) {
        matched.push({
          id: 'keyword_match',
          type: 'keyword_pattern',
          description: '피싱 관련 키워드가 페이지에서 발견됨',
          matchedKeywords: keywordMatches,
          matchedIn: 'content'
        });
      }
    }

    // 도메인 패턴 매칭
    for (const pattern of phishingPatternsData.patterns) {
      if (pattern.type === 'domain_pattern') {
        // 도메인 패턴은 설명 기반 (정규식 아님)
        matched.push({
          id: pattern.id,
          type: pattern.type,
          description: pattern.description,
          riskWeight: pattern.risk_weight,
          matchedIn: 'reference'
        });
      }
    }

    return matched;
  },

  /**
   * LLM에 전달할 RAG 컨텍스트 문자열 생성
   * @param {string} url - 분석 대상 URL
   * @param {string} content - 페이지 텍스트
   * @returns {string} 포맷팅된 컨텍스트 문자열
   */
  async buildContext(url, content) {
    const [similarDomains, matchedPatterns] = await Promise.all([
      this.findSimilarDomains(new URL(url).hostname),
      this.matchPhishingPatterns(url, content)
    ]);

    let context = '';

    // 유사 도메인 정보
    if (similarDomains.length > 0) {
      context += '### 유사한 정규 도메인\n';
      for (const d of similarDomains) {
        const status = d.isExactMatch ? '✅ 정확히 일치' : `⚠️ 유사도 ${d.similarity}`;
        context += `- ${d.name} (${d.domain}) [${d.category}] - ${status}\n`;
      }
      context += '\n';
    }

    // 매칭된 피싱 패턴
    const urlPatterns = matchedPatterns.filter(p => p.matchedIn === 'url');
    if (urlPatterns.length > 0) {
      context += '### 매칭된 URL 패턴\n';
      for (const p of urlPatterns) {
        context += `- [${p.id}] ${p.description} (위험 가중치: ${p.riskWeight})\n`;
      }
      context += '\n';
    }

    // 키워드 매칭
    const keywordMatch = matchedPatterns.find(p => p.type === 'keyword_pattern');
    if (keywordMatch) {
      context += '### 감지된 위험 키워드\n';
      for (const [category, keywords] of Object.entries(keywordMatch.matchedKeywords)) {
        const categoryLabel = {
          'urgent_ko': '긴급성 유도 (한국어)',
          'urgent_en': '긴급성 유도 (영어)',
          'reward_ko': '보상 유도 (한국어)',
          'reward_en': '보상 유도 (영어)',
          'credential_ko': '인증정보 요구 (한국어)',
          'credential_en': '인증정보 요구 (영어)'
        }[category] || category;
        context += `- ${categoryLabel}: ${keywords.join(', ')}\n`;
      }
      context += '\n';
    }

    // 참고 패턴 (도메인 패턴)
    const domainPatterns = matchedPatterns.filter(p => p.type === 'domain_pattern');
    if (domainPatterns.length > 0) {
      context += '### 참고: 알려진 피싱 도메인 패턴\n';
      for (const p of domainPatterns.slice(0, 5)) {
        context += `- ${p.description}\n`;
      }
      context += '\n';
    }

    return context || '관련 피싱 패턴이 발견되지 않았습니다.\n';
  },

  /**
   * 기본 도메인명 추출
   */
  _extractBase(hostname) {
    const parts = hostname.split('.');
    if (parts.length >= 2) {
      const multiPartTLDs = ['co.kr', 'co.jp', 'co.uk', 'or.kr', 'go.kr', 'ac.kr'];
      const last2 = parts.slice(-2).join('.');
      if (multiPartTLDs.includes(last2) && parts.length >= 3) {
        return parts[parts.length - 3];
      }
      return parts[parts.length - 2];
    }
    return hostname;
  },

  /**
   * 데이터 캐시 초기화 (테스트용)
   */
  _clearCache() {
    knownDomainsData = null;
    phishingPatternsData = null;
  }
};

export default RAGEngine;
