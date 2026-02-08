/**
 * PhishGuard - 경고 배너 컴포넌트
 * 위험 감지 시 페이지 상단에 경고 배너를 삽입 (Shadow DOM 사용)
 */

const AlertBanner = {
  _container: null,
  _shadowRoot: null,
  _isVisible: false,

  /**
   * 배너 표시
   * @param {object} analysisResult - { totalRisk, riskLevel, results }
   */
  show(analysisResult) {
    const { totalRisk, riskLevel, results } = analysisResult;

    // safe이고 risk가 낮으면 배너 미표시
    if (riskLevel === 'safe' && totalRisk < 10) {
      this.hide();
      return;
    }

    // 기존 배너가 있으면 업데이트
    if (this._container) {
      this._update(totalRisk, riskLevel, results);
      return;
    }

    // Shadow DOM 컨테이너 생성
    this._container = document.createElement('div');
    this._container.id = 'phishguard-alert-root';
    this._shadowRoot = this._container.attachShadow({ mode: 'closed' });

    // CSS 로드
    const style = document.createElement('style');
    style.textContent = this._getStyles();
    this._shadowRoot.appendChild(style);

    // 배너 HTML 생성
    const wrapper = document.createElement('div');
    wrapper.id = 'phishguard-wrapper';
    wrapper.innerHTML = this._buildBannerHTML(totalRisk, riskLevel, results);
    this._shadowRoot.appendChild(wrapper);

    // 이벤트 바인딩
    this._bindEvents();

    // 페이지 최상단에 삽입 (push-down 방식)
    document.body.insertBefore(this._container, document.body.firstChild);
    this._isVisible = true;
  },

  /**
   * 배너 숨기기
   */
  hide() {
    if (this._container && this._container.parentNode) {
      this._container.parentNode.removeChild(this._container);
    }
    this._container = null;
    this._shadowRoot = null;
    this._isVisible = false;
  },

  /**
   * 배너 업데이트
   */
  _update(totalRisk, riskLevel, results) {
    if (!this._shadowRoot) return;
    const wrapper = this._shadowRoot.getElementById('phishguard-wrapper');
    if (wrapper) {
      wrapper.innerHTML = this._buildBannerHTML(totalRisk, riskLevel, results);
      this._bindEvents();
    }
  },

  /**
   * 배너 HTML 생성
   */
  _buildBannerHTML(totalRisk, riskLevel, results) {
    const config = this._getLevelConfig(riskLevel);

    let detailItems = '';
    if (results && results.length > 0) {
      detailItems = results
        .filter(r => r.confidence > 0)
        .map(r => {
          const riskClass = r.risk >= 70 ? 'danger' : r.risk >= 40 ? 'warning' : 'safe';
          return `
            <div class="phishguard-detail__item">
              <span class="phishguard-detail__module">${this._getModuleLabel(r.name)}</span>
              <span class="phishguard-detail__risk phishguard-detail__risk--${riskClass}">${r.risk}</span>
              <span class="phishguard-detail__reason">${r.reason}</span>
            </div>`;
        }).join('');
    }

    return `
      <div class="phishguard-banner phishguard-banner--${riskLevel}" role="alert">
        <div class="phishguard-banner__content">
          <span class="phishguard-banner__icon">${config.icon}</span>
          <p class="phishguard-banner__text">${config.prefix} ${config.message}</p>
        </div>
        <div class="phishguard-banner__actions">
          <button class="phishguard-banner__btn phishguard-banner__btn--detail" id="phishguard-detail-btn">
            자세히 보기
          </button>
          <button class="phishguard-banner__btn phishguard-banner__btn--close" id="phishguard-close-btn" aria-label="닫기">
            ✕
          </button>
        </div>
      </div>
      <div class="phishguard-detail" id="phishguard-detail-panel">
        <h3 class="phishguard-detail__title">PhishGuard 상세 분석 결과 (위험도: ${totalRisk}/100)</h3>
        ${detailItems}
      </div>`;
  },

  /**
   * 위험 수준별 설정
   */
  _getLevelConfig(riskLevel) {
    switch (riskLevel) {
      case 'danger':
        return {
          icon: '\u26A0\uFE0F',
          prefix: '경고:',
          message: '이 사이트는 피싱 사이트로 의심됩니다! 개인정보를 입력하지 마세요.'
        };
      case 'warning':
        return {
          icon: '\u26A1',
          prefix: '주의:',
          message: '이 사이트에서 의심스러운 요소가 감지되었습니다.'
        };
      case 'safe':
        return {
          icon: '\u2705',
          prefix: '참고:',
          message: '일부 주의 사항이 감지되었습니다.'
        };
      default:
        return {
          icon: '\u2139\uFE0F',
          prefix: '정보:',
          message: '분석 결과를 확인하세요.'
        };
    }
  },

  /**
   * 모듈 이름을 한글 레이블로 변환
   */
  _getModuleLabel(name) {
    const labels = {
      'TyposquatDetector': '도메인 유사도',
      'ProtocolDetector': '프로토콜 보안',
      'DomainAgeDetector': '도메인 연령',
      'ContentAnalyzer': '콘텐츠 분석',
      'LLMAnalyzer': 'AI 종합 분석'
    };
    return labels[name] || name;
  },

  /**
   * 이벤트 바인딩
   */
  _bindEvents() {
    if (!this._shadowRoot) return;

    const closeBtn = this._shadowRoot.getElementById('phishguard-close-btn');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => this.hide());
    }

    const detailBtn = this._shadowRoot.getElementById('phishguard-detail-btn');
    const detailPanel = this._shadowRoot.getElementById('phishguard-detail-panel');
    if (detailBtn && detailPanel) {
      detailBtn.addEventListener('click', () => {
        const isVisible = detailPanel.classList.contains('phishguard-detail--visible');
        detailPanel.classList.toggle('phishguard-detail--visible');
        detailBtn.textContent = isVisible ? '자세히 보기' : '접기';
      });
    }
  },

  /**
   * 인라인 CSS 반환 (Shadow DOM용, chrome.runtime.getURL 불가 시 폴백)
   */
  _getStyles() {
    // alert-banner.css의 내용을 인라인으로 포함
    // 크롬 익스텐션에서 Shadow DOM 내부에 외부 CSS를 로드하기 어려우므로 인라인 사용
    return `
:host {
  all: initial;
  display: block;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
  font-size: 14px;
  line-height: 1.5;
  z-index: 2147483647;
}
.phishguard-banner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 20px;
  margin: 0;
  border: none;
  box-sizing: border-box;
  width: 100%;
  animation: slideDown 0.3s ease-out;
  position: relative;
}
.phishguard-banner--danger {
  background: linear-gradient(135deg, #dc2626, #b91c1c);
  color: #ffffff;
  border-bottom: 3px solid #991b1b;
}
.phishguard-banner--warning {
  background: linear-gradient(135deg, #f59e0b, #d97706);
  color: #1a1a1a;
  border-bottom: 3px solid #b45309;
}
.phishguard-banner--safe {
  background: linear-gradient(135deg, #16a34a, #15803d);
  color: #ffffff;
  border-bottom: 3px solid #166534;
}
.phishguard-banner__content {
  display: flex;
  align-items: center;
  gap: 10px;
  flex: 1;
}
.phishguard-banner__icon { font-size: 20px; flex-shrink: 0; }
.phishguard-banner__text { font-size: 14px; font-weight: 600; margin: 0; }
.phishguard-banner__actions { display: flex; align-items: center; gap: 8px; flex-shrink: 0; }
.phishguard-banner__btn {
  border: none;
  border-radius: 6px;
  padding: 6px 14px;
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
  transition: opacity 0.2s, transform 0.1s;
  white-space: nowrap;
}
.phishguard-banner__btn:hover { opacity: 0.9; transform: translateY(-1px); }
.phishguard-banner__btn:active { transform: translateY(0); }
.phishguard-banner__btn--detail { background: rgba(255,255,255,0.25); color: inherit; backdrop-filter: blur(4px); }
.phishguard-banner--warning .phishguard-banner__btn--detail { background: rgba(0,0,0,0.15); }
.phishguard-banner__btn--close { background: transparent; color: inherit; font-size: 18px; padding: 4px 8px; line-height: 1; opacity: 0.7; }
.phishguard-banner__btn--close:hover { opacity: 1; }
.phishguard-detail {
  display: none;
  padding: 16px 20px;
  background: #1a1a2e;
  color: #e0e0e0;
  border-bottom: 2px solid #333;
  font-size: 13px;
}
.phishguard-detail--visible { display: block; animation: fadeIn 0.2s ease-out; }
.phishguard-detail__title { font-size: 15px; font-weight: 700; margin: 0 0 12px 0; color: #fff; }
.phishguard-detail__item { display: flex; align-items: flex-start; gap: 10px; padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.08); }
.phishguard-detail__item:last-child { border-bottom: none; }
.phishguard-detail__module { font-weight: 600; min-width: 120px; color: #a0a0a0; }
.phishguard-detail__risk { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 700; min-width: 36px; text-align: center; }
.phishguard-detail__risk--danger { background: #dc2626; color: #fff; }
.phishguard-detail__risk--warning { background: #f59e0b; color: #1a1a1a; }
.phishguard-detail__risk--safe { background: #16a34a; color: #fff; }
.phishguard-detail__reason { flex: 1; color: #d0d0d0; }
@keyframes slideDown { from { transform: translateY(-100%); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
@keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
    `;
  }
};

export default AlertBanner;
