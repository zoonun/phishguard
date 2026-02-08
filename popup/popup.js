/**
 * PhishGuard - 팝업 UI 스크립트
 */

const MODULE_LABELS = {
  'TyposquatDetector': '도메인 유사도',
  'ProtocolDetector': '프로토콜 보안',
  'DomainAgeDetector': '도메인 연령',
  'ContentAnalyzer': '콘텐츠 분석',
  'LLMAnalyzer': 'AI 종합 분석'
};

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;

  // 도메인 표시
  const domainEl = document.getElementById('current-domain');
  try {
    const url = new URL(tab.url);
    domainEl.textContent = url.hostname;
  } catch {
    domainEl.textContent = tab.url || '알 수 없음';
  }

  // 분석 결과 요청
  chrome.runtime.sendMessage({ type: 'GET_RESULT', tabId: tab.id }, (result) => {
    if (chrome.runtime.lastError || !result) {
      showEmpty('이 페이지에 대한 분석 결과가 없습니다.');
      updateGauge(0, 'safe');
      return;
    }
    render(result);
  });
}

function render(result) {
  const { totalRisk, riskLevel, results, whitelisted } = result;

  updateGauge(totalRisk, riskLevel);

  const list = document.getElementById('results-list');

  if (whitelisted) {
    list.innerHTML = '<p class="results__empty">알려진 안전한 사이트입니다.</p>';
    return;
  }

  if (!results || results.length === 0) {
    list.innerHTML = '<p class="results__empty">분석 결과가 없습니다.</p>';
    return;
  }

  list.innerHTML = results
    .filter(r => r.confidence > 0)
    .map(r => {
      const cls = r.risk >= 70 ? 'danger' : r.risk >= 40 ? 'warning' : 'safe';
      return `
        <div class="result-card" onclick="this.classList.toggle('result-card--expanded')">
          <div class="result-card__header">
            <span class="result-card__name">${MODULE_LABELS[r.name] || r.name}</span>
            <span class="result-card__risk result-card__risk--${cls}">${r.risk}</span>
          </div>
          <p class="result-card__reason">${r.reason}</p>
        </div>`;
    }).join('');
}

function updateGauge(score, level) {
  const fill = document.getElementById('gauge-fill');
  const scoreEl = document.getElementById('gauge-score');
  const labelEl = document.getElementById('gauge-label');

  const circumference = 314; // 2 * π * 50
  const offset = circumference - (score / 100) * circumference;
  fill.style.strokeDashoffset = offset;

  const colors = { danger: '#dc2626', warning: '#f59e0b', safe: '#16a34a' };
  const labels = { danger: '위험', warning: '주의', safe: '안전' };

  fill.style.stroke = colors[level] || colors.safe;
  scoreEl.textContent = score;
  labelEl.textContent = labels[level] || '안전';
}

function showEmpty(msg) {
  document.getElementById('results-list').innerHTML =
    `<p class="results__empty">${msg}</p>`;
}

document.addEventListener('DOMContentLoaded', init);
