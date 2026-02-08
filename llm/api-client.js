/**
 * PhishGuard - LLM API 호출 클라이언트
 * Gemini 기본 지원, GLM(z.ai) 추가 가능
 */

import Settings from "../config/settings.js";
import Logger from "../utils/logger.js";

const PROVIDERS = {
  glm: {
    name: "GLM",
    endpoint: "https://api.z.ai/api/paas/v4/chat/completions",
    model: "glm-4.7-flash",
    buildHeaders(apiKey) {
      return {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      };
    },
    buildBody(prompt, systemPrompt, model) {
      return {
        model: model || "glm-4.7-flash",
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: prompt },
        ],
        temperature: 0.3,
        max_tokens: 1024,
        thinking: { type: "disabled" },
      };
    },
    extractContent(response) {
      return response.choices?.[0]?.message?.content || "";
    },
  },

  gemini: {
    name: "Gemini",
    buildHeaders() {
      return { "Content-Type": "application/json" };
    },
    buildBody(prompt, systemPrompt) {
      return {
        system_instruction: { parts: [{ text: systemPrompt }] },
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: {
          temperature: 0.3,
          maxOutputTokens: 1024,
        },
      };
    },
    extractContent(response) {
      return response.candidates?.[0]?.content?.parts?.[0]?.text || "";
    },
    getEndpoint(apiKey) {
      return `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:generateContent?key=${apiKey}`;
    },
  },
};

const LLMClient = {
  _provider: "gemini",
  _apiKey: "",
  _timeout: 30000,
  _maxRetries: 2,

  /**
   * 초기화 (설정에서 provider/apiKey 로드)
   */
  async init() {
    try {
      const settings = await Settings.getAll();
      this._provider = settings.llmProvider || "gemini";
      this._apiKey = settings.apiKey || "";
    } catch {
      Logger.warn("[LLMClient] Failed to load settings, using defaults");
    }
  },

  /**
   * LLM 분석 요청
   * @param {string} prompt - 분석 요청 프롬프트
   * @param {string} systemPrompt - 시스템 프롬프트
   * @returns {string} LLM 응답 텍스트
   */
  async analyze(prompt, systemPrompt) {
    if (!this._apiKey) {
      throw new Error("API 키가 설정되지 않았습니다.");
    }

    const provider = PROVIDERS[this._provider];
    if (!provider) {
      throw new Error(`지원하지 않는 LLM 프로바이더: ${this._provider}`);
    }

    let lastError;

    for (let attempt = 0; attempt <= this._maxRetries; attempt++) {
      try {
        if (attempt > 0) {
          const delay = Math.pow(2, attempt) * 1000; // exponential backoff
          Logger.debug(
            `[LLMClient] Retry ${attempt}/${this._maxRetries} after ${delay}ms`,
          );
          await new Promise((resolve) => setTimeout(resolve, delay));
        }

        const result = await this._callAPI(provider, prompt, systemPrompt);
        return result;
      } catch (error) {
        lastError = error;
        Logger.warn(
          `[LLMClient] Attempt ${attempt + 1} failed:`,
          error.message,
        );

        // 서버 일시적 오류(5xx)만 재시도
        if (error.status >= 500) {
          continue;
        }
        // 429 rate limit, 인증 에러 등은 재시도해도 소용없으므로 바로 throw
        throw error;
      }
    }

    throw lastError;
  },

  /**
   * 실제 API 호출
   */
  async _callAPI(provider, prompt, systemPrompt) {
    let endpoint = provider.endpoint;
    if (provider.getEndpoint) {
      endpoint = provider.getEndpoint(this._apiKey);
    }

    const headers = provider.buildHeaders(this._apiKey);
    const body = provider.buildBody(prompt, systemPrompt, provider.model);

    Logger.debug(`[LLMClient] Calling ${provider.name} API...`);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this._timeout);

    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorBody = await response.text().catch(() => "");
        const error = new Error(
          `API error ${response.status}: ${errorBody.substring(0, 200)}`,
        );
        error.status = response.status;
        throw error;
      }

      const data = await response.json();
      const content = provider.extractContent(data);

      if (!content) {
        throw new Error("LLM 응답이 비어있습니다.");
      }

      Logger.debug(`[LLMClient] Response received (${content.length} chars)`);
      return content;
    } catch (error) {
      clearTimeout(timeoutId);

      if (error.name === "AbortError") {
        throw new Error(`API 요청 타임아웃 (${this._timeout / 1000}초)`);
      }
      throw error;
    }
  },

  /**
   * 프로바이더 변경
   */
  setProvider(provider) {
    if (PROVIDERS[provider]) {
      this._provider = provider;
    } else {
      Logger.error(`[LLMClient] Unknown provider: ${provider}`);
    }
  },

  /**
   * API 키 설정
   */
  setApiKey(key) {
    this._apiKey = key;
  },

  /**
   * API 키가 설정되어 있는지 확인
   */
  hasApiKey() {
    return !!this._apiKey;
  },

  /**
   * 현재 프로바이더 반환
   */
  getProvider() {
    return this._provider;
  },
};

export default LLMClient;
