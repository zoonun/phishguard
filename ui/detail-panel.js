/**
 * PhishGuard - 상세 분석 패널
 * 왜 위험한지 설명하는 상세 패널 (Alert Banner 내부에서 사용)
 */

const DetailPanel = {
  /**
   * 상세 결과를 HTML로 렌더링
   * @param {Array} results - 각 detector의 분석 결과
   * @param {number} totalRisk - 종합 위험도
   * @returns {string} HTML 문자열
   */
  render(results, totalRisk) {
    if (!results || results.length === 0) {
      return '<p>분석 결과가 없습니다.</p>';
    }

    const moduleLabels = {
      'TyposquatDetector': '도메인 유사도 검사',
      'ProtocolDetector': '프로토콜 보안 검사',
      'DomainAgeDetector': '도메인 연령 검사',
      'ContentAnalyzer': '콘텐츠 분석',
      'LLMAnalyzer': 'AI 종합 분석'
    };

    const items = results
      .filter(r => r.confidence > 0)
      .sort((a, b) => (b.name === 'LLMAnalyzer') - (a.name === 'LLMAnalyzer') || b.risk - a.risk)
      .map(r => {
        const label = moduleLabels[r.name] || r.name;
        const riskClass = r.risk >= 70 ? 'danger' : r.risk >= 40 ? 'warning' : 'safe';

        let detailsHTML = '';
        if (r.details) {
          const detailEntries = this._formatDetails(r.details);
          if (detailEntries) {
            detailsHTML = `<div class="pg-detail__extra">${detailEntries}</div>`;
          }
        }

        return `
          <div class="pg-detail__item">
            <div class="pg-detail__item-header">
              <span class="pg-detail__module">${label}</span>
              <span class="pg-detail__risk pg-detail__risk--${riskClass}">${r.risk}</span>
            </div>
            <div class="pg-detail__reason">${r.reason}</div>
            ${detailsHTML}
          </div>`;
      }).join('');

    return `
      <div class="pg-detail__summary">
        종합 위험도: <strong>${totalRisk}/100</strong>
      </div>
      ${items}`;
  },

  /**
   * 상세 정보 포맷팅
   */
  _formatDetails(details) {
    const entries = [];

    if (details.matchedDomain) {
      entries.push(`매칭 도메인: ${details.matchedDomain}`);
    }
    if (details.similarity !== undefined) {
      entries.push(`유사도: ${(details.similarity * 100).toFixed(0)}%`);
    }
    if (details.technique) {
      const techniques = {
        'character_repetition': '문자 반복',
        'character_substitution': '문자 치환',
        'character_insertion': '문자 삽입',
        'character_deletion': '문자 삭제',
        'homoglyph': '동형문자(Homoglyph)',
        'tld_change': 'TLD 변경',
        'hyphen_insertion': '하이픈 삽입',
        'subdomain_impersonation': '서브도메인 위장'
      };
      entries.push(`기법: ${techniques[details.technique] || details.technique}`);
    }
    if (details.ageDays !== undefined) {
      entries.push(`도메인 나이: ${details.ageDays}일`);
    }
    if (details.llmVerdict) {
      entries.push(`AI 판정: ${details.llmVerdict}`);
    }

    if (entries.length === 0) return '';
    return entries.map(e => `<span class="pg-detail__tag">${e}</span>`).join(' ');
  }
};

export default DetailPanel;
