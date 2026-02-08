/**
 * PhishGuard - 도메인 연령 감지 모듈
 * 최근 등록된 도메인(신생 도메인) 감지
 */

import Logger from '../utils/logger.js';

const DomainAgeDetector = {
  name: 'DomainAgeDetector',
  weight: 0.15,

  // 캐시 저장소
  _cache: new Map(),

  async analyze(context) {
    const { hostname } = context;

    Logger.debug(`[DomainAgeDetector] Analyzing domain age: ${hostname}`);

    try {
      // 캐시 확인
      const cached = await this._getCachedResult(hostname);
      if (cached) {
        Logger.debug(`[DomainAgeDetector] Cache hit for ${hostname}`);
        return cached;
      }

      // 도메인 등록일 조회
      const domainInfo = await this._queryDomainAge(hostname);

      if (!domainInfo || !domainInfo.creationDate) {
        Logger.warn(`[DomainAgeDetector] Could not retrieve domain age for ${hostname}`);
        return {
          risk: 0,
          confidence: 0,
          reason: '도메인 등록일 정보를 조회할 수 없습니다.',
          details: { error: 'lookup_failed', hostname }
        };
      }

      const result = this._calculateRisk(hostname, domainInfo);

      // 결과 캐싱
      await this._cacheResult(hostname, result);

      return result;
    } catch (error) {
      Logger.error(`[DomainAgeDetector] Error:`, error);
      return {
        risk: 0,
        confidence: 0,
        reason: '도메인 연령 검사 중 오류가 발생했습니다.',
        details: { error: error.message, hostname }
      };
    }
  },

  /**
   * 도메인 등록일 기반 위험도 산정
   */
  _calculateRisk(hostname, domainInfo) {
    const now = Date.now();
    const creationDate = new Date(domainInfo.creationDate).getTime();
    const ageDays = Math.floor((now - creationDate) / (1000 * 60 * 60 * 24));

    let risk, reason;

    if (ageDays < 30) {
      risk = 70;
      reason = `이 도메인은 ${ageDays}일 전에 등록되었습니다. 최근 생성된 도메인은 피싱에 자주 사용됩니다.`;
    } else if (ageDays < 90) {
      risk = 50;
      reason = `이 도메인은 약 ${Math.floor(ageDays / 7)}주 전에 등록되었습니다. 비교적 최근 생성된 도메인입니다.`;
    } else if (ageDays < 365) {
      risk = 30;
      reason = `이 도메인은 약 ${Math.floor(ageDays / 30)}개월 전에 등록되었습니다.`;
    } else {
      risk = 5;
      const years = Math.floor(ageDays / 365);
      reason = `이 도메인은 약 ${years}년 전에 등록된 도메인입니다.`;
    }

    // 신뢰도는 등록일이 정확할수록 높음
    const confidence = domainInfo.source === 'whois' ? 0.8 : 0.6;

    return {
      risk,
      confidence,
      reason,
      details: {
        hostname,
        creationDate: domainInfo.creationDate,
        ageDays,
        registrar: domainInfo.registrar || 'unknown',
        source: domainInfo.source
      }
    };
  },

  /**
   * WHOIS API를 통한 도메인 등록일 조회
   * MVP에서는 ip2whois 무료 API 사용
   */
  async _queryDomainAge(hostname) {
    // 등록 가능한 도메인 추출 (서브도메인 제거)
    const domain = this._extractBaseDomain(hostname);

    try {
      // ip2whois 무료 API (API 키 필요 없는 기본 조회)
      const response = await fetch(
        `https://www.ip2whois.com/api/v1?domain=${encodeURIComponent(domain)}`
      );

      if (!response.ok) {
        throw new Error(`API response: ${response.status}`);
      }

      const data = await response.json();

      if (data.create_date) {
        return {
          creationDate: data.create_date,
          registrar: data.registrar || 'unknown',
          source: 'whois'
        };
      }

      return null;
    } catch (error) {
      Logger.warn(`[DomainAgeDetector] WHOIS API failed for ${domain}:`, error.message);

      // 대안: rdap.org 시도
      try {
        const rdapResponse = await fetch(
          `https://rdap.org/domain/${encodeURIComponent(domain)}`
        );

        if (rdapResponse.ok) {
          const rdapData = await rdapResponse.json();
          const registrationEvent = rdapData.events?.find(
            e => e.eventAction === 'registration'
          );

          if (registrationEvent) {
            return {
              creationDate: registrationEvent.eventDate,
              registrar: rdapData.entities?.[0]?.vcardArray?.[1]?.[1]?.[3] || 'unknown',
              source: 'rdap'
            };
          }
        }
      } catch (rdapError) {
        Logger.warn(`[DomainAgeDetector] RDAP fallback also failed:`, rdapError.message);
      }

      return null;
    }
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
   * 캐시에서 결과 조회
   */
  async _getCachedResult(hostname) {
    try {
      if (typeof chrome !== 'undefined' && chrome.storage) {
        return new Promise((resolve) => {
          chrome.storage.local.get(`domainAge_${hostname}`, (data) => {
            const cached = data[`domainAge_${hostname}`];
            if (cached && (Date.now() - cached.timestamp < 86400000)) { // 24시간 캐시
              resolve(cached.result);
            } else {
              resolve(null);
            }
          });
        });
      }
    } catch {
      // storage 사용 불가 시 메모리 캐시 사용
    }

    const cached = this._cache.get(hostname);
    if (cached && (Date.now() - cached.timestamp < 86400000)) {
      return cached.result;
    }
    return null;
  },

  /**
   * 결과 캐싱
   */
  async _cacheResult(hostname, result) {
    const cacheEntry = { result, timestamp: Date.now() };

    // 메모리 캐시
    this._cache.set(hostname, cacheEntry);

    // chrome.storage 캐시
    try {
      if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.set({ [`domainAge_${hostname}`]: cacheEntry });
      }
    } catch {
      // storage 사용 불가 시 무시
    }
  }
};

export default DomainAgeDetector;
