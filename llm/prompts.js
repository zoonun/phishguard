/**
 * PhishGuard - 프롬프트 템플릿 관리
 * LLM API에 보낼 프롬프트 구성
 */

const Prompts = {
  /**
   * 시스템 프롬프트 반환
   */
  getSystemPrompt() {
    return `당신은 사이버 보안 전문가로서 웹사이트의 피싱/스캠 여부를 분석합니다.
제공된 정보를 기반으로 해당 웹사이트가 피싱/스캠인지 판단하고,
반드시 아래 JSON 형식으로만 응답하세요.

{
  "verdict": "phishing" | "suspicious" | "safe",
  "confidence": 0.0~1.0,
  "risk_score": 0~100,
  "reasons": ["이유1", "이유2"],
  "recommendation": "사용자에게 보여줄 권고 메시지"
}

판단 기준:
- 도메인이 알려진 사이트와 유사하지만 정확히 일치하지 않으면 피싱 가능성이 높습니다.
- HTTP 프로토콜에서 민감 정보를 요구하면 위험합니다.
- 긴급성/공포를 유발하는 문구가 많으면 피싱 가능성이 높습니다.
- 과도한 개인정보를 동시에 요구하면 의심해야 합니다.
- 여러 위험 신호가 동시에 존재하면 종합적으로 위험도를 높여야 합니다.

반드시 한국어로 이유와 권고 메시지를 작성하세요.`;
  },

  /**
   * 분석 요청 프롬프트 구성
   * @param {object} data - { url, hostname, protocol, pathname, pageTitle, domContent, previousResults, ragContext }
   * @returns {string} 프롬프트 문자열
   */
  buildAnalysisPrompt(data) {
    let prompt = `## 웹사이트 피싱/스캠 분석 요청\n\n`;

    // URL 정보
    prompt += `### 1. URL 정보\n`;
    prompt += `- 전체 URL: ${data.url || `${data.protocol}//${data.hostname}${data.pathname || ''}`}\n`;
    prompt += `- 도메인: ${data.hostname}\n`;
    prompt += `- 프로토콜: ${data.protocol}\n`;
    prompt += `- 경로: ${data.pathname || '/'}\n`;
    prompt += `\n`;

    // 사전 분석 결과
    if (data.previousResults && data.previousResults.length > 0) {
      prompt += `### 2. 사전 분석 결과 (자동화 감지 모듈)\n`;
      for (const result of data.previousResults) {
        const level = result.risk >= 70 ? '🔴' : result.risk >= 40 ? '🟡' : '🟢';
        prompt += `- ${level} **${result.name}**: 위험도 ${result.risk}/100 (신뢰도: ${(result.confidence * 100).toFixed(0)}%)\n`;
        prompt += `  → ${result.reason}\n`;
      }
      prompt += `\n`;
    }

    // RAG 컨텍스트
    if (data.ragContext) {
      prompt += `### 3. 관련 피싱 패턴 DB 검색 결과\n`;
      prompt += data.ragContext;
      prompt += `\n`;
    }

    // 페이지 콘텐츠
    prompt += `### 4. 페이지 정보\n`;
    prompt += `- 페이지 제목: ${data.pageTitle || '(없음)'}\n`;

    if (data.domContent) {
      if (data.domContent.metaDescription) {
        prompt += `- 메타 설명: ${data.domContent.metaDescription}\n`;
      }
      if (data.domContent.forms && data.domContent.forms.length > 0) {
        prompt += `- 입력 폼 ${data.domContent.forms.length}개 감지\n`;
        for (const form of data.domContent.forms.slice(0, 3)) {
          const types = form.inputs.map(i => i.type).join(', ');
          prompt += `  - 폼 (${form.method}): 입력 필드 타입 [${types}]\n`;
        }
      }
      if (data.domContent.textContent) {
        const preview = data.domContent.textContent.substring(0, 300).replace(/\n+/g, ' ').trim();
        prompt += `- 페이지 텍스트 일부: "${preview}"\n`;
      }
    }

    prompt += `\n### 분석 요청\n`;
    prompt += `위 정보를 종합적으로 분석하여 이 웹사이트가 피싱/스캠인지 판단해주세요.\n`;
    prompt += `반드시 지정된 JSON 형식으로만 응답하세요.\n`;

    return prompt;
  },

  /**
   * 템플릿 변수 치환
   * @param {string} template - {{변수명}} 형태의 템플릿
   * @param {object} vars - 변수 값 객체
   */
  render(template, vars) {
    return template.replace(/\{\{(\w+)\}\}/g, (_, key) => {
      return vars[key] !== undefined ? String(vars[key]) : `{{${key}}}`;
    });
  }
};

export default Prompts;
