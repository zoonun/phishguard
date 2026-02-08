/**
 * PhishGuard - 백그라운드 서비스 워커
 * 탭 URL 변경 감지 → 분석 오케스트레이션 → 결과 전달
 */

import DetectorManager from "../detectors/index.js";
import { parseUrl, extractRegistrableDomain } from "../utils/url-parser.js";
import RiskBadge from "../ui/risk-badge.js";
import Logger from "../utils/logger.js";
import LLMClient from "../llm/api-client.js";
import Prompts from "../llm/prompts.js";

// 분석 결과 캐시 (도메인 → 결과)
const analysisCache = new Map();
const CACHE_EXPIRY = 3600000; // 1시간

// 화이트리스트 도메인 (known-domains.json에서 로드)
let whitelistDomains = null;

// 익스텐션 활성화 상태
let extEnabled = true;

// 초기 설정 로드 완료 Promise
let _initReady;
const initReady = new Promise((resolve) => {
  _initReady = resolve;
});

/**
 * 익스텐션 활성화 상태 로드
 */
async function loadExtEnabled() {
  try {
    const data = await chrome.storage.sync.get("extEnabled");
    extEnabled = data.extEnabled !== false; // 기본값 true
  } catch {
    extEnabled = true;
  }
}

/**
 * LLM 설정 로드 (popup에서 저장한 llmProvider/apiKey 읽기)
 */
async function loadLlmSettings() {
  try {
    const data = await chrome.storage.sync.get(["llmProvider", "apiKey"]);
    if (data.apiKey) {
      LLMClient.setProvider(data.llmProvider || "gemini");
      LLMClient.setApiKey(data.apiKey);
      Logger.info(
        `[ServiceWorker] LLM enabled: ${data.llmProvider || "gemini"}`,
      );
    } else {
      LLMClient.setApiKey("");
      Logger.debug("[ServiceWorker] LLM disabled: no API key");
    }
  } catch {
    Logger.warn("[ServiceWorker] Failed to load LLM settings");
  }
}

/**
 * 화이트리스트 도메인 로드
 */
async function loadWhitelist() {
  if (whitelistDomains) return whitelistDomains;

  try {
    const url = chrome.runtime.getURL("rag/known-domains.json");
    const response = await fetch(url);
    const data = await response.json();

    whitelistDomains = new Set();
    for (const entry of data.domains) {
      whitelistDomains.add(entry.primary);
      if (entry.aliases) {
        entry.aliases.forEach((alias) => whitelistDomains.add(alias));
      }
    }

    Logger.info(
      `[ServiceWorker] Whitelist loaded: ${whitelistDomains.size} domains`,
    );
    return whitelistDomains;
  } catch (error) {
    Logger.error("[ServiceWorker] Failed to load whitelist:", error);
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
    if (hostname.endsWith("." + domain)) return true;
  }

  return false;
}

/**
 * 캐시에서 분석 결과 조회
 */
function getCachedResult(hostname) {
  const cached = analysisCache.get(hostname);
  if (cached && Date.now() - cached.timestamp < CACHE_EXPIRY) {
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
    timestamp: Date.now(),
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
  // 초기 설정 로드 완료 대기
  await initReady;

  // 익스텐션 비활성화 시 분석 건너뛰기
  if (!extEnabled) {
    await RiskBadge.clear(tabId);
    return null;
  }

  try {
    const parsed = parseUrl(url);

    // 분석 대상이 아닌 URL 무시
    if (!parsed || parsed.isLocalhost || parsed.isIP) {
      await RiskBadge.clear(tabId);
      return null;
    }

    if (!["http:", "https:"].includes(parsed.protocol)) {
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
        riskLevel: "safe",
        results: [],
        hostname,
        whitelisted: true,
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
    await storeResult(tabId, { status: "analyzing", hostname });

    // Context 구성 (기본 정보만, DOM 정보는 content script에서 수신)
    const context = {
      url,
      hostname: parsed.hostname,
      protocol: parsed.protocol,
      pathname: parsed.pathname,
    };

    // DetectorManager를 통해 분석 실행
    const llmEnabled = LLMClient.hasApiKey();
    const result = await DetectorManager.analyze(context, {
      enableLLM: llmEnabled,
      apiClient: llmEnabled ? LLMClient : null,
      prompts: Prompts,
    });

    result.hostname = hostname;
    result.analyzedAt = Date.now();
    result.status = "complete";

    // 결과 캐싱
    cacheResult(hostname, result);

    // 뱃지 업데이트
    await RiskBadge.update(tabId, result.totalRisk, result.riskLevel);

    // 결과 저장 (팝업에서 조회용)
    await storeResult(tabId, result);

    // Content script에 결과 전달
    try {
      await chrome.tabs.sendMessage(tabId, {
        type: "PHISHGUARD_RESULT",
        data: result,
      });
    } catch {
      // content script가 아직 로드되지 않았을 수 있음
      Logger.debug(`[ServiceWorker] Could not send result to tab ${tabId}`);
    }

    Logger.info(
      `[ServiceWorker] Analysis complete for ${hostname}: risk=${result.totalRisk}, level=${result.riskLevel}`,
    );

    return result;
  } catch (error) {
    Logger.error("[ServiceWorker] Analysis error:", error);
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
  if (changeInfo.status === "complete" && tab.url) {
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
          await RiskBadge.update(
            activeInfo.tabId,
            cached.totalRisk,
            cached.riskLevel,
          );
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
  if (message.type === "GET_RESULT") {
    // 팝업에서 현재 탭의 분석 결과 요청
    handleGetResult(message.tabId).then(sendResponse);
    return true; // 비동기 응답
  }

  if (message.type === "DOM_CONTENT") {
    // Content script에서 DOM 정보 전달
    handleDomContent(sender.tab?.id, sender.tab?.url, message.data);
    sendResponse({ received: true });
    return false;
  }

  if (message.type === "TRIGGER_ANALYZE") {
    // 팝업에서 미분석 탭에 대해 분석 요청
    analyzeUrl(message.tabId, message.url).then(sendResponse);
    return true;
  }

  if (message.type === "REANALYZE") {
    // 재분석 요청
    if (sender.tab) {
      analysisCache.delete(parseUrl(sender.tab.url)?.hostname);
      analyzeUrl(sender.tab.id, sender.tab.url).then(sendResponse);
      return true;
    }
  }

  if (message.type === "VERIFY_API_KEY") {
    // API 키 검증: 간단한 테스트 호출
    verifyApiKey(message.provider, message.apiKey).then(sendResponse);
    return true;
  }

  return false;
});

/**
 * API 키 검증 (간단한 테스트 호출)
 */
async function verifyApiKey(provider, apiKey) {
  try {
    // 임시로 LLMClient 설정을 바꿔서 테스트
    const prevProvider = LLMClient.getProvider();
    const prevHasKey = LLMClient.hasApiKey();

    LLMClient.setProvider(provider);
    LLMClient.setApiKey(apiKey);

    try {
      await LLMClient.analyze(
        '테스트 요청입니다. "ok"라고만 응답하세요.',
        '간단히 "ok"라고만 응답하세요.',
      );
      return { valid: true };
    } catch (error) {
      // 원래 설정 복원
      if (prevHasKey) {
        const data = await chrome.storage.sync.get(["llmProvider", "apiKey"]);
        LLMClient.setProvider(data.llmProvider || prevProvider);
        LLMClient.setApiKey(data.apiKey || "");
      } else {
        LLMClient.setApiKey("");
      }

      if (error.status === 401 || error.status === 403) {
        return { valid: false, error: "인증 실패 - API 키를 확인해주세요." };
      }
      if (error.status === 429) {
        // Rate limited means the key is valid
        return { valid: true };
      }
      return {
        valid: false,
        error: "키 검증에 실패했습니다. 잠시 후 다시 시도해주세요.",
      };
    }
  } catch (error) {
    return {
      valid: false,
      error: "검증 중 오류가 발생했습니다. 네트워크를 확인해주세요.",
    };
  }
}

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
  if (!extEnabled) return;
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
    pageTitle: domContent?.title,
  };

  // 이전 LLM 결과 보존 (analyzeUrl에서 이미 실행됨)
  const prevData = await chrome.storage.session.get(`tab_${tabId}`);
  const prevResult = prevData[`tab_${tabId}`];
  const prevLlm = prevResult?.results?.find(
    (r) => r.name === "LLMAnalyzer" && r.confidence > 0,
  );

  // 기존 캐시 삭제 후 재분석 (LLM 제외 - 중복 호출 방지)
  analysisCache.delete(parsed.hostname);
  await storeResult(tabId, { status: "analyzing", hostname: parsed.hostname });

  const result = await DetectorManager.analyze(context, {
    enableLLM: false,
    prompts: Prompts,
  });

  // 이전 LLM 결과 병합
  if (prevLlm) {
    result.results.push(prevLlm);
    result.totalRisk = DetectorManager._calculateTotalRisk(result.results);
    result.riskLevel = DetectorManager._getRiskLevel(result.totalRisk);
  }

  result.hostname = parsed.hostname;
  result.analyzedAt = Date.now();
  result.status = "complete";

  cacheResult(parsed.hostname, result);
  await RiskBadge.update(tabId, result.totalRisk, result.riskLevel);
  await storeResult(tabId, result);

  // Content script에 업데이트된 결과 전달
  try {
    await chrome.tabs.sendMessage(tabId, {
      type: "PHISHGUARD_RESULT",
      data: result,
    });
  } catch {
    // 전달 실패 무시
  }
}

/**
 * 설정 변경 시 LLM 클라이언트 업데이트
 */
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "sync") return;
  if (changes.llmProvider || changes.apiKey) {
    loadLlmSettings();
    // LLM 설정 변경 시 캐시 + 세션 스토리지 클리어 → 재분석 시 LLM 포함
    analysisCache.clear();
    chrome.storage.session.clear();
    Logger.info(
      "[ServiceWorker] Analysis cache cleared (LLM settings changed)",
    );
  }
  if (changes.extEnabled) {
    extEnabled = changes.extEnabled.newValue !== false;
    if (!extEnabled) {
      // 비활성화 시 모든 탭의 뱃지 클리어
      chrome.tabs.query({}, (tabs) => {
        for (const tab of tabs) {
          RiskBadge.clear(tab.id);
        }
      });
    }
  }
});

/**
 * 익스텐션 설치/업데이트 시 초기화
 */
chrome.runtime.onInstalled.addListener(() => {
  Logger.info("[PhishGuard] Extension installed/updated");
  loadWhitelist();
  loadLlmSettings();
  loadExtEnabled();
});

// 서비스워커 시작 시에도 설정 로드 (완료 후 initReady resolve)
Promise.all([loadLlmSettings(), loadExtEnabled()]).then(_initReady);
