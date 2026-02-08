/**
 * PhishGuard - 콘텐츠 스크립트
 * 페이지 DOM 정보 수집 + 경고 UI 삽입
 */

(function () {
  'use strict';

  // 중복 실행 방지
  if (window.__phishguardLoaded) return;
  window.__phishguardLoaded = true;

  // ============================================================
  // AlertBanner (인라인 - content script는 ES module 불가)
  // ============================================================
  const AlertBanner = {
    _container: null,
    _shadowRoot: null,

    show(analysisResult) {
      const { totalRisk, riskLevel, results } = analysisResult;

      if (riskLevel === 'safe' && totalRisk < 10) {
        this.hide();
        return;
      }

      if (this._container) {
        this._update(totalRisk, riskLevel, results);
        return;
      }

      this._container = document.createElement('div');
      this._container.id = 'phishguard-alert-root';
      // 호스트 요소에 인라인 스타일 강제 적용 — 페이지 CSS에 의해 잘리는 것을 방지
      this._container.style.cssText = 'position:fixed!important;top:0!important;left:0!important;width:100vw!important;z-index:2147483647!important;display:block!important;overflow:visible!important;margin:0!important;padding:0!important;border:none!important;max-height:none!important;min-height:0!important;box-sizing:border-box!important;pointer-events:auto!important;opacity:1!important;visibility:visible!important;transform:none!important;';
      this._shadowRoot = this._container.attachShadow({ mode: 'closed' });

      const style = document.createElement('style');
      style.textContent = this._getStyles();
      this._shadowRoot.appendChild(style);

      const wrapper = document.createElement('div');
      wrapper.id = 'phishguard-wrapper';
      wrapper.innerHTML = this._buildHTML(totalRisk, riskLevel, results);
      this._shadowRoot.appendChild(wrapper);

      this._bindEvents();
      document.body.insertBefore(this._container, document.body.firstChild);
    },

    hide() {
      if (this._container && this._container.parentNode) {
        this._container.parentNode.removeChild(this._container);
      }
      this._container = null;
      this._shadowRoot = null;
    },

    _update(totalRisk, riskLevel, results) {
      if (!this._shadowRoot) return;
      const wrapper = this._shadowRoot.getElementById('phishguard-wrapper');
      if (wrapper) {
        wrapper.innerHTML = this._buildHTML(totalRisk, riskLevel, results);
        this._bindEvents();
      }
    },

    _buildHTML(totalRisk, riskLevel, results) {
      const cfg = {
        danger: { icon: '\u26A0\uFE0F', prefix: '\uACBD\uACE0:', msg: '\uC774 \uC0AC\uC774\uD2B8\uB294 \uD53C\uC2F1 \uC0AC\uC774\uD2B8\uB85C \uC758\uC2EC\uB429\uB2C8\uB2E4! \uAC1C\uC778\uC815\uBCF4\uB97C \uC785\uB825\uD558\uC9C0 \uB9C8\uC138\uC694.' },
        warning: { icon: '\u26A1', prefix: '\uC8FC\uC758:', msg: '\uC774 \uC0AC\uC774\uD2B8\uC5D0\uC11C \uC758\uC2EC\uC2A4\uB7EC\uC6B4 \uC694\uC18C\uAC00 \uAC10\uC9C0\uB418\uC5C8\uC2B5\uB2C8\uB2E4.' },
        safe: { icon: '\u2705', prefix: '\uCC38\uACE0:', msg: '\uC77C\uBD80 \uC8FC\uC758 \uC0AC\uD56D\uC774 \uAC10\uC9C0\uB418\uC5C8\uC2B5\uB2C8\uB2E4.' }
      }[riskLevel] || { icon: '\u2139\uFE0F', prefix: '\uC815\uBCF4:', msg: '\uBD84\uC11D \uACB0\uACFC\uB97C \uD655\uC778\uD558\uC138\uC694.' };

      const moduleLabels = {
        'TyposquatDetector': '\uB3C4\uBA54\uC778 \uC720\uC0AC\uB3C4',
        'ProtocolDetector': '\uD504\uB85C\uD1A0\uCF5C \uBCF4\uC548',
        'DomainAgeDetector': '\uB3C4\uBA54\uC778 \uC5F0\uB839',
        'ContentAnalyzer': '\uCF58\uD150\uCE20 \uBD84\uC11D',
        'LLMAnalyzer': 'AI \uC885\uD569 \uBD84\uC11D'
      };

      const details = (results || [])
        .filter(r => r.confidence > 0)
        .sort((a, b) => (b.name === 'LLMAnalyzer') - (a.name === 'LLMAnalyzer'))
        .map(r => {
          const cls = r.risk >= 70 ? 'danger' : r.risk >= 40 ? 'warning' : 'safe';
          return `<div class="pg-detail__item">
            <span class="pg-detail__module">${moduleLabels[r.name] || r.name}</span>
            <span class="pg-detail__risk pg-detail__risk--${cls}">${r.risk}</span>
            <span class="pg-detail__reason">${r.reason}</span>
          </div>`;
        }).join('');

      return `
        <div class="pg-banner pg-banner--${riskLevel}" role="alert">
          <div class="pg-banner__content">
            <span class="pg-banner__icon">${cfg.icon}</span>
            <p class="pg-banner__text">${cfg.prefix} ${cfg.msg}</p>
          </div>
          <div class="pg-banner__actions">
            <button class="pg-btn pg-btn--detail" id="pg-detail-btn">\uC790\uC138\uD788 \uBCF4\uAE30</button>
            <button class="pg-btn pg-btn--close" id="pg-close-btn">\u2715</button>
          </div>
        </div>
        <div class="pg-detail" id="pg-detail-panel">
          <h3 class="pg-detail__title">PhishGuard \uC0C1\uC138 \uBD84\uC11D (\uC704\uD5D8\uB3C4: ${totalRisk}/100)</h3>
          ${details}
        </div>`;
    },

    _bindEvents() {
      if (!this._shadowRoot) return;
      const closeBtn = this._shadowRoot.getElementById('pg-close-btn');
      if (closeBtn) closeBtn.addEventListener('click', () => this.hide());

      const detailBtn = this._shadowRoot.getElementById('pg-detail-btn');
      const panel = this._shadowRoot.getElementById('pg-detail-panel');
      if (detailBtn && panel) {
        detailBtn.addEventListener('click', () => {
          const vis = panel.classList.toggle('pg-detail--visible');
          detailBtn.textContent = vis ? '\uC811\uAE30' : '\uC790\uC138\uD788 \uBCF4\uAE30';
        });
      }
    },

    _getStyles() {
      return `
:host {
  all: initial;
  display: block !important;
  width: 100vw !important;
  max-width: 100vw !important;
  position: relative !important;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  font-size: 14px;
  line-height: 1.5;
  z-index: 2147483647;
  overflow: visible !important;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
.pg-banner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 20px;
  width: 100%;
  min-height: 48px;
  box-sizing: border-box;
  animation: pgSlide 0.3s ease-out;
  flex-wrap: nowrap;
  overflow: hidden;
}
.pg-banner--danger { background: linear-gradient(135deg, #dc2626, #b91c1c); color: #fff; border-bottom: 3px solid #991b1b; }
.pg-banner--warning { background: linear-gradient(135deg, #f59e0b, #d97706); color: #1a1a1a; border-bottom: 3px solid #b45309; }
.pg-banner--safe { background: linear-gradient(135deg, #16a34a, #15803d); color: #fff; border-bottom: 3px solid #166534; }
.pg-banner__content { display: flex; align-items: center; gap: 10px; flex: 1; min-width: 0; overflow: hidden; }
.pg-banner__icon { font-size: 20px; flex-shrink: 0; }
.pg-banner__text { font-size: 14px; font-weight: 600; margin: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.pg-banner__actions { display: flex; align-items: center; gap: 8px; flex-shrink: 0; margin-left: 12px; }
.pg-btn { border: none; border-radius: 6px; padding: 6px 14px; font-size: 12px; font-weight: 600; cursor: pointer; transition: opacity 0.2s; white-space: nowrap; line-height: 1.4; }
.pg-btn:hover { opacity: 0.85; }
.pg-btn--detail { background: rgba(255,255,255,0.25); color: inherit; }
.pg-banner--warning .pg-btn--detail { background: rgba(0,0,0,0.12); }
.pg-btn--close { background: transparent; color: inherit; font-size: 18px; padding: 4px 8px; opacity: 0.7; line-height: 1; }
.pg-btn--close:hover { opacity: 1; }
.pg-detail { display: none; padding: 16px 20px; background: #1a1a2e; color: #e0e0e0; font-size: 13px; border-bottom: 2px solid #333; width: 100%; box-sizing: border-box; }
.pg-detail--visible { display: block; animation: pgFade 0.2s ease-out; }
.pg-detail__title { font-size: 15px; font-weight: 700; margin: 0 0 12px; color: #fff; }
.pg-detail__item { display: flex; align-items: flex-start; gap: 10px; padding: 8px 0; border-bottom: 1px solid rgba(255,255,255,0.08); }
.pg-detail__item:last-child { border-bottom: none; }
.pg-detail__module { font-weight: 600; min-width: 110px; flex-shrink: 0; color: #a0a0a0; }
.pg-detail__risk { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 700; min-width: 32px; text-align: center; flex-shrink: 0; }
.pg-detail__risk--danger { background: #dc2626; color: #fff; }
.pg-detail__risk--warning { background: #f59e0b; color: #1a1a1a; }
.pg-detail__risk--safe { background: #16a34a; color: #fff; }
.pg-detail__reason { flex: 1; color: #d0d0d0; word-break: break-word; min-width: 0; }
@keyframes pgSlide { from { transform: translateY(-100%); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
@keyframes pgFade { from { opacity: 0; } to { opacity: 1; } }`;
    }
  };

  // ============================================================
  // DOM 정보 수집
  // ============================================================

  function collectDOMInfo() {
    const info = {
      title: document.title || '',
      metaDescription: '',
      favicon: '',
      textContent: '',
      forms: [],
      externalResources: []
    };

    // Meta description
    const metaDesc = document.querySelector('meta[name="description"]');
    if (metaDesc) info.metaDescription = metaDesc.getAttribute('content') || '';

    // Favicon
    const favicon = document.querySelector('link[rel="icon"], link[rel="shortcut icon"]');
    if (favicon) info.favicon = favicon.href || '';

    // 페이지 텍스트 (본문 일부, 최대 2000자)
    const bodyText = document.body?.innerText || '';
    info.textContent = bodyText.substring(0, 2000);

    // Form 분석
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
      const formInfo = {
        action: form.action || '',
        method: (form.method || 'get').toUpperCase(),
        inputs: []
      };

      const inputs = form.querySelectorAll('input, select, textarea');
      inputs.forEach(input => {
        formInfo.inputs.push({
          type: input.type || 'text',
          name: input.name || '',
          placeholder: input.placeholder || '',
          id: input.id || ''
        });
      });

      info.forms.push(formInfo);
    });

    // 외부 리소스 URL 수집
    const images = document.querySelectorAll('img[src]');
    images.forEach(img => {
      if (img.src && img.src.startsWith('http')) {
        info.externalResources.push(img.src);
      }
    });

    const scripts = document.querySelectorAll('script[src]');
    scripts.forEach(script => {
      if (script.src && script.src.startsWith('http')) {
        info.externalResources.push(script.src);
      }
    });

    // 최대 50개 리소스만
    info.externalResources = info.externalResources.slice(0, 50);

    return info;
  }

  // ============================================================
  // 초기화
  // ============================================================

  function init() {
    // DOM 정보 수집 후 background에 전달
    const domInfo = collectDOMInfo();

    chrome.runtime.sendMessage({
      type: 'DOM_CONTENT',
      data: domInfo
    }, () => {
      // 응답 무시 (에러 방지)
      if (chrome.runtime.lastError) {
        // background가 아직 준비되지 않았을 수 있음
      }
    });
  }

  // ============================================================
  // 메시지 리스너
  // ============================================================

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'PHISHGUARD_RESULT') {
      // 분석 결과 수신 → 배너 표시
      AlertBanner.show(message.data);
      sendResponse({ received: true });
    }

    if (message.type === 'GET_DOM_CONTENT') {
      // background에서 DOM 정보 재요청
      const domInfo = collectDOMInfo();
      sendResponse(domInfo);
    }

    return false;
  });

  // 페이지 로드 완료 시 초기화
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
