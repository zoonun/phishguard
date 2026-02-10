/**
 * PhishGuard - KISA 피싱 블랙리스트 감지 모듈
 * 한국인터넷진흥원(KISA)의 피싱사이트 DB를 활용한 블랙리스트 매칭
 */

import Logger from '../utils/logger.js';

// In-memory 캐시 (chrome.storage.local에서 로드 후 Set으로 변환)
let _hostnameSet = null;
let _loadPromise = null;

const KisaBlacklistDetector = {
  name: 'KisaBlacklistDetector',
  weight: 0.25,

  async analyze(context) {
    const { hostname, url } = context;

    Logger.debug(`[KisaBlacklist] Checking: ${hostname}`);

    // KISA API 키 확인
    const settings = await chrome.storage.sync.get(['kisaApiKey', 'kisaEnabled']);
    if (!settings.kisaApiKey || settings.kisaEnabled === false) {
      return {
        risk: 0,
        confidence: 0,
        reason: 'KISA 블랙리스트가 설정되지 않았습니다.',
        details: { skipped: true }
      };
    }

    // 블랙리스트 로드
    const hostnames = await this._loadBlacklist();

    if (!hostnames || hostnames.size === 0) {
      // 동기화 상태 확인
      const syncState = await chrome.storage.local.get('kisaSyncState');
      const state = syncState.kisaSyncState;
      if (state && state.status === 'syncing') {
        return {
          risk: 0,
          confidence: 0,
          reason: 'KISA 블랙리스트 동기화 중입니다.',
          details: { syncing: true }
        };
      }
      return {
        risk: 0,
        confidence: 0,
        reason: 'KISA 블랙리스트 데이터가 아직 없습니다.',
        details: { empty: true }
      };
    }

    // 매칭 검사: hostname
    if (hostnames.has(hostname)) {
      Logger.warn(`[KisaBlacklist] MATCH: ${hostname}`);
      return {
        risk: 100,
        confidence: 1.0,
        reason: 'KISA 피싱사이트 블랙리스트에 등록된 도메인입니다.',
        details: {
          source: 'KISA',
          matchType: 'hostname',
          matchedEntry: hostname,
          blacklistSize: hostnames.size
        }
      };
    }

    // 매칭 검사: www. 제거한 hostname
    const bareHostname = hostname.replace(/^www\./, '');
    if (bareHostname !== hostname && hostnames.has(bareHostname)) {
      Logger.warn(`[KisaBlacklist] MATCH (bare): ${bareHostname}`);
      return {
        risk: 100,
        confidence: 1.0,
        reason: 'KISA 피싱사이트 블랙리스트에 등록된 도메인입니다.',
        details: {
          source: 'KISA',
          matchType: 'hostname',
          matchedEntry: bareHostname,
          blacklistSize: hostnames.size
        }
      };
    }

    // 미매칭
    return {
      risk: 0,
      confidence: 0.9,
      reason: 'KISA 블랙리스트에 등록되지 않은 사이트입니다.',
      details: {
        blacklistSize: hostnames.size,
        lastSync: await this._getLastSyncTime()
      }
    };
  },

  /**
   * chrome.storage.local에서 블랙리스트를 로드하여 in-memory Set으로 캐싱
   */
  async _loadBlacklist() {
    if (_hostnameSet) return _hostnameSet;

    // 동시 로드 방지
    if (_loadPromise) return _loadPromise;

    _loadPromise = (async () => {
      try {
        const data = await chrome.storage.local.get('kisaBlacklist');
        const bl = data.kisaBlacklist;
        if (bl && bl.hostnames && bl.hostnames.length > 0) {
          _hostnameSet = new Set(bl.hostnames);
          Logger.info(`[KisaBlacklist] Loaded ${_hostnameSet.size} hostnames`);
        } else {
          _hostnameSet = new Set();
        }
        return _hostnameSet;
      } catch (error) {
        Logger.error('[KisaBlacklist] Load failed:', error);
        _hostnameSet = new Set();
        return _hostnameSet;
      } finally {
        _loadPromise = null;
      }
    })();

    return _loadPromise;
  },

  async _getLastSyncTime() {
    try {
      const data = await chrome.storage.local.get('kisaBlacklist');
      return data.kisaBlacklist?.lastSync || null;
    } catch {
      return null;
    }
  },

  /**
   * 블랙리스트 캐시 무효화 (동기화 완료 시 호출)
   */
  invalidateCache() {
    _hostnameSet = null;
    _loadPromise = null;
    Logger.debug('[KisaBlacklist] Cache invalidated');
  }
};

export default KisaBlacklistDetector;
