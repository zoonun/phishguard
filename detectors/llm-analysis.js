/**
 * PhishGuard - LLM 종합 분석 감지 모듈
 * 다른 detector들의 결과와 페이지 정보를 종합하여 LLM에게 최종 판단 요청
 */

import Logger from '../utils/logger.js';

const LLMAnalyzer = {
  name: 'LLMAnalyzer',
  weight: 0.3,

  // Rate limiting
  _requestTimestamps: [],
  _maxRequestsPerMinute: 5,

  async analyze(context, options = {}) {
    const { url, hostname, protocol, pathname, domContent, pageTitle } = context;
    const { previousResults, ragContext, apiClient, prompts } = options;

    Logger.debug(`[LLMAnalyzer] Analyzing with LLM: ${hostname}`);

    // 실행 조건 체크: 다른 detector 종합 점수가 30~80 사이일 때만 호출
    if (previousResults) {
      const avgRisk = this._calculateAverageRisk(previousResults);
      if (avgRisk < 30) {
        Logger.debug(`[LLMAnalyzer] Skipping - risk too low (${avgRisk})`);
        return {
          risk: 0,
          confidence: 0,
          reason: '다른 감지 모듈에서 안전하다고 판단하여 LLM 분석을 생략합니다.',
          details: { skipped: true, reason: 'low_risk', avgRisk }
        };
      }
      if (avgRisk > 80) {
        Logger.debug(`[LLMAnalyzer] Skipping - risk too high (${avgRisk})`);
        return {
          risk: 0,
          confidence: 0,
          reason: '다른 감지 모듈에서 이미 높은 위험으로 판단하여 LLM 분석을 생략합니다.',
          details: { skipped: true, reason: 'high_risk', avgRisk }
        };
      }
    }

    // Rate limiting 체크
    if (!this._checkRateLimit()) {
      Logger.warn(`[LLMAnalyzer] Rate limit exceeded`);
      return {
        risk: 0,
        confidence: 0,
        reason: 'LLM API 호출 제한에 도달했습니다. 잠시 후 다시 시도해주세요.',
        details: { skipped: true, reason: 'rate_limited' }
      };
    }

    // API 클라이언트 확인
    if (!apiClient) {
      Logger.warn(`[LLMAnalyzer] No API client available`);
      return {
        risk: 0,
        confidence: 0,
        reason: 'LLM API가 설정되지 않았습니다.',
        details: { skipped: true, reason: 'no_api_client' }
      };
    }

    try {
      // 프롬프트 구성
      const prompt = this._buildPrompt({
        url, hostname, protocol, pathname,
        pageTitle,
        domContent,
        previousResults,
        ragContext
      }, prompts);

      // LLM API 호출
      this._recordRequest();
      const systemPrompt = prompts?.getSystemPrompt?.() || this._getDefaultSystemPrompt();
      const response = await apiClient.analyze(prompt, systemPrompt);

      // 응답 파싱
      const parsed = this._parseResponse(response);

      return {
        risk: parsed.risk_score,
        confidence: parsed.confidence,
        reason: parsed.recommendation || 'LLM 분석 완료',
        details: {
          llmVerdict: parsed.verdict,
          explanation: parsed.reasons?.join('. ') || '',
          suggestedAction: this._getSuggestedAction(parsed.verdict),
          rawResponse: parsed
        }
      };
    } catch (error) {
      Logger.error(`[LLMAnalyzer] LLM analysis failed:`, error);
      return {
        risk: 0,
        confidence: 0,
        reason: 'LLM 분석 중 오류가 발생했습니다. 다른 감지 모듈의 결과만으로 판단합니다.',
        details: { error: error.message, skipped: true, reason: 'api_error' }
      };
    }
  },

  /**
   * 이전 분석 결과의 평균 위험도 계산
   */
  _calculateAverageRisk(results) {
    if (!results || results.length === 0) return 50;
    const validResults = results.filter(r => r.confidence > 0);
    if (validResults.length === 0) return 50;
    const sum = validResults.reduce((acc, r) => acc + r.risk, 0);
    return sum / validResults.length;
  },

  /**
   * Rate limit 체크
   */
  _checkRateLimit() {
    const now = Date.now();
    const oneMinuteAgo = now - 60000;
    this._requestTimestamps = this._requestTimestamps.filter(t => t > oneMinuteAgo);
    return this._requestTimestamps.length < this._maxRequestsPerMinute;
  },

  /**
   * 요청 기록
   */
  _recordRequest() {
    this._requestTimestamps.push(Date.now());
  },

  /**
   * LLM 프롬프트 구성
   */
  _buildPrompt(data, prompts) {
    if (prompts?.buildAnalysisPrompt) {
      return prompts.buildAnalysisPrompt(data);
    }

    // 기본 프롬프트 구성
    let prompt = `## 분석 대상 웹사이트 정보\n\n`;
    prompt += `- URL: ${data.url || `${data.protocol}//${data.hostname}${data.pathname || ''}`}\n`;
    prompt += `- 도메인: ${data.hostname}\n`;
    prompt += `- 프로토콜: ${data.protocol}\n`;
    prompt += `- 페이지 제목: ${data.pageTitle || '(없음)'}\n\n`;

    if (data.previousResults && data.previousResults.length > 0) {
      prompt += `## 사전 분석 결과\n\n`;
      for (const result of data.previousResults) {
        prompt += `- ${result.name}: 위험도 ${result.risk}/100 (신뢰도: ${result.confidence}) - ${result.reason}\n`;
      }
      prompt += '\n';
    }

    if (data.ragContext) {
      prompt += `## 관련 피싱 패턴 정보\n\n${data.ragContext}\n\n`;
    }

    if (data.domContent?.textContent) {
      const textPreview = data.domContent.textContent.substring(0, 500);
      prompt += `## 페이지 콘텐츠 일부\n\n${textPreview}\n\n`;
    }

    prompt += `위 정보를 종합적으로 분석하여 이 웹사이트가 피싱/스캠 사이트인지 판단해주세요.\n`;
    prompt += `반드시 지정된 JSON 형식으로만 응답하세요.`;

    return prompt;
  },

  /**
   * 기본 시스템 프롬프트
   */
  _getDefaultSystemPrompt() {
    return `당신은 사이버 보안 전문가로서 웹사이트의 피싱/스캠 여부를 분석합니다.
제공된 정보를 기반으로 해당 웹사이트가 피싱/스캠인지 판단하고,
반드시 아래 JSON 형식으로만 응답하세요.

{
  "verdict": "phishing" | "suspicious" | "safe",
  "confidence": 0.0~1.0,
  "risk_score": 0~100,
  "reasons": ["이유1", "이유2"],
  "recommendation": "사용자에게 보여줄 권고 메시지"
}`;
  },

  /**
   * LLM 응답 파싱
   */
  _parseResponse(response) {
    try {
      // JSON 블록 추출
      const jsonMatch = response.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        return {
          verdict: parsed.verdict || 'suspicious',
          confidence: Math.min(1, Math.max(0, parsed.confidence || 0.5)),
          risk_score: Math.min(100, Math.max(0, parsed.risk_score || 50)),
          reasons: parsed.reasons || [],
          recommendation: parsed.recommendation || ''
        };
      }
    } catch (e) {
      Logger.warn(`[LLMAnalyzer] Failed to parse LLM response:`, e.message);
    }

    // 파싱 실패 시 기본값
    return {
      verdict: 'suspicious',
      confidence: 0.3,
      risk_score: 50,
      reasons: ['LLM 응답을 파싱할 수 없습니다'],
      recommendation: '분석 결과를 확인할 수 없습니다. 주의하세요.'
    };
  },

  /**
   * 판정 결과에 따른 권고 액션
   */
  _getSuggestedAction(verdict) {
    switch (verdict) {
      case 'phishing':
        return '이 사이트를 떠나세요';
      case 'suspicious':
        return '주의하세요';
      case 'safe':
        return '안전합니다';
      default:
        return '주의하세요';
    }
  }
};

export default LLMAnalyzer;
