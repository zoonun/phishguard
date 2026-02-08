/**
 * PhishGuard - 백그라운드 서비스 워커
 * 탭 URL 변경 감지 → 분석 오케스트레이션 → 결과 전달
 */

import DetectorManager from '../detectors/index.js';
import { parseUrl, extractRegistrableDomain } from '../utils/url-parser.js';
import RiskBadge from '../ui/risk-badge.js';
import Logger from '../utils/logger.js';

// 분석 결과 캐시 (도메인 → 결과)
const analysisCache = new Map();
const CACHE_EXPIRY = 3600000; // 1시간

// 화이트리스트 도메인 (known-domains.json에서 로드)
let whitelistDomains = null;

/**
 * 화이트리스트 도메인 로드
 */
async function loadWhitelist() {
  if (whitelistDomains) return whitelistDomains;

  try {
    const url = chrome.runtime.getURL('rag/known-domains.json');
    const response = await fetch(url);
    const data = await response.json();

    whitelistDomains = new Set();
    for (const entry of data.domains) {
      whitelistDomains.add(entry.primary);
      if (entry.aliases) {
        entry.aliases.forEach(alias => whitelistDomains.add(alias));
      }
    }

    Logger.info(`[ServiceWorker] Whitelist loaded: ${whitelistDomains.size} domains`);
    return whitelistDomains;
  } catch (error) {
    Logger.error('[ServiceWorker] Failed to load whitelist:', error);
    return new Set();
  }
}

/**
 * 도메인이 화이트리스트에 있는지 확인
 */
function isWhitelisted(hostname, whitelist) {
  if (whitelist.has(hostname)) return true;

  // 서브도메인도 체크 (mail.naver.com → naver.com)
  const registrable = extractRegistrableDomain(hostname);
  if (whitelist.has(registrable)) return true;

  // aliases 매칭 (subdomain.domain.com 형태)
  for (const domain of whitelist) {
    if (hostname.endsWith('.' + domain)) return true;
  }

  return false;
}

/**
 * 캐시에서 분석 결과 조회
 */
function getCachedResult(hostname) {
  const cached = analysisCache.get(hostname);
  if (cached && (Date.now() - cached.timestamp < CACHE_EXPIRY)) {
    return cached.result;
  }
  analysisCache.delete(hostname);
  return null;
}

/**
 * 분석 결과 캐싱
 */
function cacheResult(hostname, result) {
  analysisCache.set(hostname, {
    result,
    timestamp: Date.now()
  });

  // 캐시 크기 제한 (최대 200개)
  if (analysisCache.size > 200) {
    const oldest = analysisCache.keys().next().value;
    analysisCache.delete(oldest);
  }
}

/**
 * URL 분석 실행
 */
async function analyzeUrl(tabId, url) {
  try {
    const parsed = parseUrl(url);

    // 분석 대상이 아닌 URL 무시
    if (!parsed || parsed.isLocalhost || parsed.isIP) {
      await RiskBadge.clear(tabId);
      return null;
    }

    if (!['http:', 'https:'].includes(parsed.protocol)) {
      await RiskBadge.clear(tabId);
      return null;
    }

    const { hostname } = parsed;

    // 화이트리스트 체크
    const whitelist = await loadWhitelist();
    if (isWhitelisted(hostname, whitelist)) {
      Logger.debug(`[ServiceWorker] Whitelisted: ${hostname}`);
      const safeResult = {
        totalRisk: 0,
        riskLevel: 'safe',
        results: [],
        hostname,
        whitelisted: true
      };
      await RiskBadge.clear(tabId);
      // 팝업에서 조회할 수 있도록 저장
      await storeResult(tabId, safeResult);
      return safeResult;
    }

    // 캐시 확인
    const cached = getCachedResult(hostname);
    if (cached) {
      Logger.debug(`[ServiceWorker] Cache hit: ${hostname}`);
      await RiskBadge.update(tabId, cached.totalRisk, cached.riskLevel);
      await storeResult(tabId, cached);
      return cached;
    }

    // 분석 중 표시
    await RiskBadge.showLoading(tabId);

    // Context 구성 (기본 정보만, DOM 정보는 content script에서 수신)
    const context = {
      url,
      hostname: parsed.hostname,
      protocol: parsed.protocol,
      pathname: parsed.pathname
    };

    // DetectorManager를 통해 분석 실행
    const result = await DetectorManager.analyze(context, {
      enableLLM: false // 기본적으로 LLM 비활성화 (설정에서 토글)
    });

    result.hostname = hostname;
    result.analyzedAt = Date.now();

    // 결과 캐싱
    cacheResult(hostname, result);

    // 뱃지 업데이트
    await RiskBadge.update(tabId, result.totalRisk, result.riskLevel);

    // 결과 저장 (팝업에서 조회용)
    await storeResult(tabId, result);

    // Content script에 결과 전달
    try {
      await chrome.tabs.sendMessage(tabId, {
        type: 'PHISHGUARD_RESULT',
        data: result
      });
    } catch {
      // content script가 아직 로드되지 않았을 수 있음
      Logger.debug(`[ServiceWorker] Could not send result to tab ${tabId}`);
    }

    Logger.info(`[ServiceWorker] Analysis complete for ${hostname}: risk=${result.totalRisk}, level=${result.riskLevel}`);

    return result;
  } catch (error) {
    Logger.error('[ServiceWorker] Analysis error:', error);
    await RiskBadge.clear(tabId);
    return null;
  }
}

/**
 * 분석 결과 저장 (chrome.storage.session)
 */
async function storeResult(tabId, result) {
  try {
    await chrome.storage.session.set({ [`tab_${tabId}`]: result });
  } catch {
    // session storage 실패 시 무시
  }
}

// ============================================================
// 이벤트 리스너
// ============================================================

/**
 * 탭 URL 변경 감지
 */
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  // URL이 변경되고 로딩이 완료된 경우
  if (changeInfo.status === 'complete' && tab.url) {
    analyzeUrl(tabId, tab.url);
  }
});

/**
 * 탭 활성화 시 (이미 분석된 결과가 있으면 뱃지 복원)
 */
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab.url) {
      const parsed = parseUrl(tab.url);
      if (parsed) {
        const cached = getCachedResult(parsed.hostname);
        if (cached) {
          await RiskBadge.update(activeInfo.tabId, cached.totalRisk, cached.riskLevel);
        }
      }
    }
  } catch {
    // 탭 정보 조회 실패 시 무시
  }
});

/**
 * 메시지 리스너 (popup/content script와 통신)
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'GET_RESULT') {
    // 팝업에서 현재 탭의 분석 결과 요청
    handleGetResult(message.tabId).then(sendResponse);
    return true; // 비동기 응답
  }

  if (message.type === 'DOM_CONTENT') {
    // Content script에서 DOM 정보 전달
    handleDomContent(sender.tab?.id, sender.tab?.url, message.data);
    sendResponse({ received: true });
    return false;
  }

  if (message.type === 'REANALYZE') {
    // 재분석 요청
    if (sender.tab) {
      analysisCache.delete(parseUrl(sender.tab.url)?.hostname);
      analyzeUrl(sender.tab.id, sender.tab.url).then(sendResponse);
      return true;
    }
  }

  return false;
});

/**
 * 분석 결과 조회 핸들러
 */
async function handleGetResult(tabId) {
  try {
    const data = await chrome.storage.session.get(`tab_${tabId}`);
    return data[`tab_${tabId}`] || null;
  } catch {
    return null;
  }
}

/**
 * DOM 콘텐츠 수신 후 추가 분석
 */
async function handleDomContent(tabId, url, domContent) {
  if (!tabId || !url) return;

  const parsed = parseUrl(url);
  if (!parsed) return;

  // DOM 정보를 포함한 context로 재분석
  const context = {
    url,
    hostname: parsed.hostname,
    protocol: parsed.protocol,
    pathname: parsed.pathname,
    domContent,
    pageTitle: domContent?.title
  };

  // 기존 캐시 삭제 후 재분석
  analysisCache.delete(parsed.hostname);

  const result = await DetectorManager.analyze(context, {
    enableLLM: false
  });

  result.hostname = parsed.hostname;
  result.analyzedAt = Date.now();

  cacheResult(parsed.hostname, result);
  await RiskBadge.update(tabId, result.totalRisk, result.riskLevel);
  await storeResult(tabId, result);

  // Content script에 업데이트된 결과 전달
  try {
    await chrome.tabs.sendMessage(tabId, {
      type: 'PHISHGUARD_RESULT',
      data: result
    });
  } catch {
    // 전달 실패 무시
  }
}

/**
 * 익스텐션 설치/업데이트 시 초기화
 */
chrome.runtime.onInstalled.addListener(() => {
  Logger.info('[PhishGuard] Extension installed/updated');
  loadWhitelist();
});
