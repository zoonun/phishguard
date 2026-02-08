/**
 * PhishGuard - LLM 응답 파싱 및 구조화
 */

import Logger from '../utils/logger.js';

const ResponseParser = {
  /**
   * LLM 응답 텍스트를 구조화된 객체로 파싱
   * @param {string} responseText - LLM 원본 응답
   * @returns {object} 파싱된 결과
   */
  parse(responseText) {
    if (!responseText) {
      return this._defaultResult('LLM 응답이 비어있습니다.');
    }

    try {
      // JSON 블록 추출 (```json ... ``` 또는 { ... })
      let jsonStr = responseText;

      // 코드 블록에서 추출
      const codeBlockMatch = responseText.match(/```(?:json)?\s*([\s\S]*?)```/);
      if (codeBlockMatch) {
        jsonStr = codeBlockMatch[1].trim();
      } else {
        // 순수 JSON 객체 추출
        const jsonMatch = responseText.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          jsonStr = jsonMatch[0];
        }
      }

      const parsed = JSON.parse(jsonStr);
      return this._validate(parsed);
    } catch (error) {
      Logger.warn('[ResponseParser] JSON parse failed:', error.message);

      // 텍스트에서 키워드 기반 추론
      return this._inferFromText(responseText);
    }
  },

  /**
   * 파싱 결과 유효성 검증 및 정규화
   */
  _validate(parsed) {
    const validVerdicts = ['phishing', 'suspicious', 'safe'];
    const verdict = validVerdicts.includes(parsed.verdict) ? parsed.verdict : 'suspicious';

    return {
      verdict,
      confidence: Math.min(1, Math.max(0, Number(parsed.confidence) || 0.5)),
      risk_score: Math.min(100, Math.max(0, Number(parsed.risk_score) || 50)),
      reasons: Array.isArray(parsed.reasons) ? parsed.reasons : [],
      recommendation: String(parsed.recommendation || this._defaultRecommendation(verdict))
    };
  },

  /**
   * JSON 파싱 실패 시 텍스트에서 추론
   */
  _inferFromText(text) {
    const lower = text.toLowerCase();

    let verdict = 'suspicious';
    let risk_score = 50;

    if (lower.includes('phishing') || lower.includes('피싱') || lower.includes('위험')) {
      verdict = 'phishing';
      risk_score = 80;
    } else if (lower.includes('safe') || lower.includes('안전') || lower.includes('정상')) {
      verdict = 'safe';
      risk_score = 15;
    }

    return {
      verdict,
      confidence: 0.3,
      risk_score,
      reasons: ['LLM 응답을 정확히 파싱할 수 없어 텍스트에서 추론했습니다.'],
      recommendation: this._defaultRecommendation(verdict)
    };
  },

  /**
   * 기본 결과 (파싱 불가 시)
   */
  _defaultResult(reason) {
    return {
      verdict: 'suspicious',
      confidence: 0.1,
      risk_score: 50,
      reasons: [reason],
      recommendation: '분석 결과를 확인할 수 없습니다. 주의하세요.'
    };
  },

  /**
   * 판정별 기본 권고 메시지
   */
  _defaultRecommendation(verdict) {
    switch (verdict) {
      case 'phishing':
        return '이 사이트는 피싱 사이트로 판단됩니다. 개인정보를 입력하지 말고 즉시 떠나세요.';
      case 'suspicious':
        return '이 사이트에서 의심스러운 요소가 발견되었습니다. 주의하세요.';
      case 'safe':
        return '이 사이트는 안전한 것으로 판단됩니다.';
      default:
        return '주의하세요.';
    }
  }
};

export default ResponseParser;
