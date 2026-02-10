/**
 * PhishGuard - 설정 관리
 * chrome.storage.sync를 활용한 설정 저장/불러오기
 */

const DEFAULT_SETTINGS = {
  llmProvider: 'gemini',         // 'glm' | 'gemini'
  apiKey: '',
  enableLLM: true,
  enableNotifications: true,
  riskThreshold: {
    warning: 40,
    danger: 70
  },
  detectors: {
    typosquat: true,
    protocol: true,
    domainAge: true,
    contentAnalysis: true,
    llmAnalysis: true,
    kisaBlacklist: true
  },
  whitelist: [],
  cacheExpiry: 3600000           // 1시간 (ms)
};

const Settings = {
  _cache: null,

  /**
   * 전체 설정 불러오기
   */
  async getAll() {
    if (this._cache) return { ...this._cache };

    try {
      const stored = await chrome.storage.sync.get('phishguard_settings');
      const settings = { ...DEFAULT_SETTINGS, ...stored.phishguard_settings };
      this._cache = settings;
      return { ...settings };
    } catch {
      return { ...DEFAULT_SETTINGS };
    }
  },

  /**
   * 특정 설정값 가져오기
   */
  async get(key) {
    const all = await this.getAll();
    return key.split('.').reduce((obj, k) => obj?.[k], all);
  },

  /**
   * 설정 저장 (부분 업데이트)
   */
  async set(updates) {
    const current = await this.getAll();
    const merged = this._deepMerge(current, updates);

    try {
      await chrome.storage.sync.set({ phishguard_settings: merged });
      this._cache = merged;
      return true;
    } catch (error) {
      console.error('[PhishGuard:Settings] Save failed:', error);
      return false;
    }
  },

  /**
   * 설정 초기화
   */
  async reset() {
    try {
      await chrome.storage.sync.set({ phishguard_settings: DEFAULT_SETTINGS });
      this._cache = { ...DEFAULT_SETTINGS };
      return true;
    } catch {
      return false;
    }
  },

  /**
   * API 키 설정
   */
  async setApiKey(key) {
    return this.set({ apiKey: key });
  },

  /**
   * LLM 프로바이더 설정
   */
  async setProvider(provider) {
    return this.set({ llmProvider: provider });
  },

  /**
   * 화이트리스트에 도메인 추가
   */
  async addToWhitelist(domain) {
    const settings = await this.getAll();
    if (!settings.whitelist.includes(domain)) {
      settings.whitelist.push(domain);
      return this.set({ whitelist: settings.whitelist });
    }
    return true;
  },

  /**
   * 화이트리스트에서 도메인 제거
   */
  async removeFromWhitelist(domain) {
    const settings = await this.getAll();
    settings.whitelist = settings.whitelist.filter(d => d !== domain);
    return this.set({ whitelist: settings.whitelist });
  },

  /**
   * 설정 변경 감지 리스너
   */
  onChange(callback) {
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area === 'sync' && changes.phishguard_settings) {
        this._cache = changes.phishguard_settings.newValue;
        callback(this._cache);
      }
    });
  },

  /**
   * 딥 머지 유틸리티
   */
  _deepMerge(target, source) {
    const result = { ...target };
    for (const key of Object.keys(source)) {
      if (
        source[key] &&
        typeof source[key] === 'object' &&
        !Array.isArray(source[key]) &&
        target[key] &&
        typeof target[key] === 'object' &&
        !Array.isArray(target[key])
      ) {
        result[key] = this._deepMerge(target[key], source[key]);
      } else {
        result[key] = source[key];
      }
    }
    return result;
  },

  /**
   * 기본 설정값 반환
   */
  getDefaults() {
    return { ...DEFAULT_SETTINGS };
  }
};

export { DEFAULT_SETTINGS };
export default Settings;
