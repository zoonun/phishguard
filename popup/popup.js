/**
 * PhishGuard - Popup UI Script
 * No ES modules -- plain IIFE for MV3 popup compatibility.
 */

(function () {
  'use strict';

  /* ====== Constants ====== */

  var MODULE_LABELS = {
    TyposquatDetector:  '도메인 유사도',
    ProtocolDetector:   '프로토콜 보안',
    DomainAgeDetector:  '도메인 연령',
    ContentAnalyzer:    '콘텐츠 분석',
    LLMAnalyzer:        'AI 종합 분석'
  };

  var RISK_COLORS = {
    safe:    '#16a34a',
    warning: '#f59e0b',
    danger:  '#dc2626'
  };

  var RISK_LABELS = {
    safe:    '안전',
    warning: '주의',
    danger:  '위험'
  };

  // Circumference for r=56: 2 * Math.PI * 56 = 351.858...
  var CIRCUMFERENCE = 2 * Math.PI * 56;

  /* ====== DOM References ====== */

  var domainEl       = document.getElementById('current-domain');
  var gaugeFill      = document.getElementById('gauge-fill');
  var gaugeScore     = document.getElementById('gauge-score');
  var gaugeLabel     = document.getElementById('gauge-label');
  var gaugeRiskText  = document.getElementById('gauge-risk-text');
  var mainView       = document.getElementById('main-view');
  var resultsList    = document.getElementById('results-list');
  var settingsPanel  = document.getElementById('settings-panel');
  var settingsToggle = document.getElementById('settings-toggle');
  var providerSelect = document.getElementById('llm-provider');
  var apiKeyInput    = document.getElementById('api-key');
  var saveBtn        = document.getElementById('settings-save');
  var statusEl       = document.getElementById('settings-status');

  /* ====== Initialization ====== */

  document.addEventListener('DOMContentLoaded', init);

  function init() {
    bindEvents();
    loadActiveTab();
  }

  /* ====== Event Binding ====== */

  function bindEvents() {
    // Settings toggle
    settingsToggle.addEventListener('click', toggleSettings);

    // Save settings
    saveBtn.addEventListener('click', saveSettings);
  }

  /* ====== Active Tab & Analysis ====== */

  function loadActiveTab() {
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      var tab = tabs && tabs[0];
      if (!tab) return;

      // Display current domain
      try {
        var url = new URL(tab.url);
        domainEl.textContent = url.hostname;
      } catch (e) {
        domainEl.textContent = tab.url || '알 수 없음';
      }

      // Request analysis result from background
      chrome.runtime.sendMessage(
        { type: 'GET_RESULT', tabId: tab.id },
        function (result) {
          if (chrome.runtime.lastError || !result) {
            showEmpty('이 페이지에 대한 분석 결과가 없습니다.');
            updateGauge(0, 'safe');
            return;
          }
          render(result);
        }
      );
    });
  }

  /* ====== Rendering ====== */

  function render(result) {
    var totalRisk   = result.totalRisk   || 0;
    var riskLevel   = result.riskLevel   || 'safe';
    var results     = result.results     || [];
    var whitelisted = result.whitelisted || false;

    updateGauge(totalRisk, riskLevel);

    if (whitelisted) {
      resultsList.innerHTML =
        '<p class="results__empty">알려진 안전한 사이트입니다.</p>';
      return;
    }

    // Filter to results with confidence > 0
    var filtered = results.filter(function (r) { return r.confidence > 0; });

    if (filtered.length === 0) {
      resultsList.innerHTML =
        '<p class="results__empty">분석 결과가 없습니다.</p>';
      return;
    }

    resultsList.innerHTML = filtered.map(function (r) {
      var cls = riskClass(r.risk);
      var label = MODULE_LABELS[r.name] || r.name;
      var reason = escapeHtml(r.reason || '');

      return (
        '<div class="result-card" data-expanded="false">' +
          '<div class="result-card__header">' +
            '<span class="result-card__name">' + label + '</span>' +
            '<span class="result-card__risk result-card__risk--' + cls + '">' + r.risk + '</span>' +
            '<span class="result-card__chevron">&#9660;</span>' +
          '</div>' +
          '<p class="result-card__reason">' + reason + '</p>' +
        '</div>'
      );
    }).join('');

    // Bind accordion click handlers
    var cards = resultsList.querySelectorAll('.result-card');
    for (var i = 0; i < cards.length; i++) {
      cards[i].addEventListener('click', handleCardToggle);
    }
  }

  function handleCardToggle() {
    this.classList.toggle('result-card--expanded');
  }

  /* ====== Gauge ====== */

  function updateGauge(score, level) {
    // Clamp score 0-100
    score = Math.max(0, Math.min(100, score));

    // Animate stroke-dashoffset
    var offset = CIRCUMFERENCE - (score / 100) * CIRCUMFERENCE;
    gaugeFill.style.strokeDashoffset = offset;

    // Color
    var color = RISK_COLORS[level] || RISK_COLORS.safe;
    gaugeFill.style.stroke = color;

    // Score text
    gaugeScore.textContent = score;

    // Label inside SVG
    gaugeLabel.textContent = RISK_LABELS[level] || '안전';

    // Large risk text below gauge
    gaugeRiskText.textContent = RISK_LABELS[level] || '분석 중...';
    gaugeRiskText.className = 'gauge__risk-text';
    if (level && RISK_LABELS[level]) {
      gaugeRiskText.classList.add('gauge__risk-text--' + level);
    }
  }

  /* ====== Settings Panel ====== */

  function toggleSettings() {
    var isVisible = settingsPanel.classList.contains('settings--visible');

    if (isVisible) {
      // Hide settings, show main
      settingsPanel.classList.remove('settings--visible');
      mainView.style.display = '';
      settingsToggle.classList.remove('footer__settings-btn--active');
      clearStatus();
    } else {
      // Show settings, hide main
      mainView.style.display = 'none';
      settingsPanel.classList.add('settings--visible');
      settingsToggle.classList.add('footer__settings-btn--active');
      loadSettings();
    }
  }

  function loadSettings() {
    chrome.storage.sync.get(['llmProvider', 'apiKey'], function (data) {
      if (data.llmProvider) {
        providerSelect.value = data.llmProvider;
      }
      if (data.apiKey) {
        apiKeyInput.value = data.apiKey;
      }
    });
  }

  function saveSettings() {
    var provider = providerSelect.value;
    var apiKey   = apiKeyInput.value.trim();

    if (!apiKey) {
      showStatus('API 키를 입력해주세요.', 'error');
      return;
    }

    var settings = {
      llmProvider: provider,
      apiKey: apiKey
    };

    // Save to chrome.storage.sync
    chrome.storage.sync.set(settings, function () {
      if (chrome.runtime.lastError) {
        showStatus('저장 실패: ' + chrome.runtime.lastError.message, 'error');
        return;
      }

      // Also notify background script
      chrome.runtime.sendMessage({
        type: 'SAVE_SETTINGS',
        settings: settings
      }, function () {
        // Ignore errors from sendMessage (background may not handle it)
        if (chrome.runtime.lastError) { /* noop */ }
      });

      showStatus('설정이 저장되었습니다.', 'success');
    });
  }

  function showStatus(message, type) {
    statusEl.textContent = message;
    statusEl.className = 'settings__status';
    if (type) {
      statusEl.classList.add('settings__status--' + type);
    }

    // Auto-clear after 3 seconds
    setTimeout(clearStatus, 3000);
  }

  function clearStatus() {
    statusEl.textContent = '';
    statusEl.className = 'settings__status';
  }

  /* ====== Helpers ====== */

  function riskClass(score) {
    if (score >= 70) return 'danger';
    if (score >= 40) return 'warning';
    return 'safe';
  }

  function showEmpty(msg) {
    resultsList.innerHTML =
      '<p class="results__empty">' + escapeHtml(msg) + '</p>';
  }

  function escapeHtml(str) {
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
  }

})();
