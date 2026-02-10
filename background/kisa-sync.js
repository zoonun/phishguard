/**
 * PhishGuard - KISA 블랙리스트 동기화 엔진
 * 공공데이터포털(data.go.kr) API에서 피싱사이트 목록을 주기적으로 동기화
 */

import Logger from "../utils/logger.js";

const KISA_API_URL =
  "https://api.odcloud.kr/api/15109780/v1/uddi:707478dd-938f-4155-badb-fae6202ee7ed";
const PAGE_SIZE = 1000;
const SYNC_ALARM_NAME = "kisa-blacklist-sync";
const SYNC_INTERVAL_MINUTES = 1440; // 24시간
const FETCH_DELAY_MS = 300; // 페이지 간 딜레이
const INCREMENTAL_PAGES = 5; // 증분 동기화 시 최근 N페이지

const KisaSync = {
  /**
   * 초기화: 알람 설정 + 필요 시 동기화 시작
   */
  async init() {
    try {
      const settings = await chrome.storage.sync.get([
        "kisaApiKey",
        "kisaEnabled",
      ]);
      if (!settings.kisaApiKey || settings.kisaEnabled === false) {
        Logger.debug("[KisaSync] Not configured, skipping init");
        return;
      }

      // 24시간 주기 알람 설정
      await chrome.alarms.create(SYNC_ALARM_NAME, {
        periodInMinutes: SYNC_INTERVAL_MINUTES,
      });
      Logger.info("[KisaSync] Alarm scheduled (24h interval)");

      // 기존 데이터 확인 → 없으면 전체 동기화
      const existing = await chrome.storage.local.get("kisaBlacklist");
      if (!existing.kisaBlacklist || !existing.kisaBlacklist.hostnames) {
        // 미완료된 동기화가 있는지 확인
        const syncState = await chrome.storage.local.get("kisaSyncState");
        if (syncState.kisaSyncState?.status === "syncing") {
          Logger.info("[KisaSync] Resuming interrupted sync");
          this.startFullSync(settings.kisaApiKey);
        } else {
          Logger.info("[KisaSync] No data, starting full sync");
          this.startFullSync(settings.kisaApiKey);
        }
      } else {
        // 마지막 동기화가 24시간 이전이면 증분 동기화
        const lastSync = existing.kisaBlacklist.lastSync || 0;
        const elapsed = Date.now() - lastSync;
        if (elapsed > SYNC_INTERVAL_MINUTES * 60 * 1000) {
          Logger.info("[KisaSync] Data stale, starting incremental sync");
          this.startIncrementalSync(settings.kisaApiKey);
        }
      }
    } catch (error) {
      Logger.error("[KisaSync] Init failed:", error);
    }
  },

  /**
   * 전체 동기화: 모든 페이지를 순차적으로 가져옴
   */
  async startFullSync(serviceKey) {
    Logger.info("[KisaSync] Starting full sync...");

    try {
      // 동기화 상태 저장
      await this._setSyncState({
        status: "syncing",
        currentPage: 0,
        startedAt: Date.now(),
      });

      // 첫 페이지로 totalCount 확인
      const firstPage = await this._fetchPage(serviceKey, 1);
      if (!firstPage) {
        await this._setSyncState({ status: "error", error: "API 응답 없음" });
        return { success: false, error: "API 응답 없음" };
      }

      const totalCount = firstPage.totalCount || 0;
      const totalPages = Math.ceil(totalCount / PAGE_SIZE);
      Logger.info(
        `[KisaSync] Total: ${totalCount} entries, ${totalPages} pages`,
      );

      const allHostnames = new Set();

      // 첫 페이지 데이터 처리
      this._extractHostnames(firstPage.data, allHostnames);
      await this._setSyncState({
        status: "syncing",
        currentPage: 1,
        totalPages,
        totalCount,
      });

      // 나머지 페이지 순차 fetch
      for (let page = 2; page <= totalPages; page++) {
        await this._delay(FETCH_DELAY_MS);

        const pageData = await this._fetchPage(serviceKey, page);
        if (pageData && pageData.data) {
          this._extractHostnames(pageData.data, allHostnames);
        }

        // 5페이지마다 상태 업데이트
        if (page % 5 === 0) {
          await this._setSyncState({
            status: "syncing",
            currentPage: page,
            totalPages,
            totalCount,
          });
        }
      }

      // 저장
      await this._persist(allHostnames, totalCount);
      await this._setSyncState({
        status: "complete",
        lastSync: Date.now(),
        totalCount: allHostnames.size,
      });

      Logger.info(
        `[KisaSync] Full sync complete: ${allHostnames.size} hostnames`,
      );
      return { success: true, count: allHostnames.size };
    } catch (error) {
      Logger.error("[KisaSync] Full sync failed:", error);
      await this._setSyncState({ status: "error", error: error.message });
      return { success: false, error: error.message };
    }
  },

  /**
   * 증분 동기화: 최근 N페이지만 가져와 기존 데이터에 merge
   */
  async startIncrementalSync(serviceKey) {
    Logger.info("[KisaSync] Starting incremental sync...");

    try {
      await this._setSyncState({
        status: "syncing",
        type: "incremental",
        startedAt: Date.now(),
      });

      // 기존 데이터 로드
      const existing = await chrome.storage.local.get("kisaBlacklist");
      const existingHostnames = new Set(
        existing.kisaBlacklist?.hostnames || [],
      );

      // 최근 N페이지 fetch
      const newHostnames = new Set();
      for (let page = 1; page <= INCREMENTAL_PAGES; page++) {
        const pageData = await this._fetchPage(serviceKey, page);
        if (pageData && pageData.data) {
          this._extractHostnames(pageData.data, newHostnames);
        }
        if (page < INCREMENTAL_PAGES) await this._delay(FETCH_DELAY_MS);
      }

      // merge
      for (const h of newHostnames) {
        existingHostnames.add(h);
      }

      await this._persist(existingHostnames, existingHostnames.size);
      await this._setSyncState({
        status: "complete",
        lastSync: Date.now(),
        totalCount: existingHostnames.size,
      });

      Logger.info(
        `[KisaSync] Incremental sync complete: +${newHostnames.size} new, total ${existingHostnames.size}`,
      );
      return {
        success: true,
        added: newHostnames.size,
        total: existingHostnames.size,
      };
    } catch (error) {
      Logger.error("[KisaSync] Incremental sync failed:", error);
      await this._setSyncState({ status: "error", error: error.message });
      return { success: false, error: error.message };
    }
  },

  /**
   * 단일 페이지 API 호출
   */
  async _fetchPage(serviceKey, pageNo) {
    const url = `${KISA_API_URL}?serviceKey=${encodeURIComponent(serviceKey)}&page=${pageNo}&perPage=${PAGE_SIZE}&returnType=JSON`;

    try {
      const response = await fetch(url);

      if (response.status === 429) {
        Logger.warn("[KisaSync] Rate limited, stopping");
        return null;
      }

      if (!response.ok) {
        Logger.error(`[KisaSync] API error: ${response.status}`);
        return null;
      }

      return await response.json();
    } catch (error) {
      Logger.error(`[KisaSync] Fetch page ${pageNo} failed:`, error);
      return null;
    }
  },

  /**
   * API 응답 데이터에서 hostname 추출
   */
  _extractHostnames(entries, targetSet) {
    if (!entries || !Array.isArray(entries)) return;

    for (const entry of entries) {
      const rawUrl = entry["홈페이지주소"];
      if (!rawUrl) continue;

      try {
        // URL이 프로토콜 없이 시작할 수 있으므로 보정
        const urlStr = rawUrl.startsWith("http") ? rawUrl : `http://${rawUrl}`;
        const parsed = new URL(urlStr);
        const hostname = parsed.hostname.toLowerCase();
        if (hostname) {
          targetSet.add(hostname);
        }
      } catch {
        // URL 파싱 실패 시 무시
      }
    }
  },

  /**
   * 블랙리스트 데이터를 chrome.storage.local에 저장
   */
  async _persist(hostnameSet, totalCount) {
    const data = {
      hostnames: [...hostnameSet],
      lastSync: Date.now(),
      totalCount,
    };

    await chrome.storage.local.set({ kisaBlacklist: data });
    Logger.debug(`[KisaSync] Persisted ${hostnameSet.size} hostnames`);
  },

  /**
   * 동기화 상태 저장
   */
  async _setSyncState(state) {
    await chrome.storage.local.set({ kisaSyncState: state });
  },

  /**
   * 현재 동기화 상태 반환
   */
  async getSyncStatus() {
    const [syncState, blacklist] = await Promise.all([
      chrome.storage.local.get("kisaSyncState"),
      chrome.storage.local.get("kisaBlacklist"),
    ]);

    return {
      syncState: syncState.kisaSyncState || { status: "idle" },
      blacklistCount: blacklist.kisaBlacklist?.hostnames?.length || 0,
      lastSync: blacklist.kisaBlacklist?.lastSync || null,
    };
  },

  /**
   * 블랙리스트 데이터 삭제
   */
  async clearBlacklist() {
    await chrome.storage.local.remove(["kisaBlacklist", "kisaSyncState"]);
    Logger.info("[KisaSync] Blacklist cleared");
  },

  _delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  },
};

export default KisaSync;
