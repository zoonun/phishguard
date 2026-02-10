/**
 * PhishGuard - Popup UI Script
 * No ES modules -- plain IIFE for MV3 popup compatibility.
 */

(function () {
  "use strict";

  /* ====== Constants ====== */

  var MODULE_LABELS = {
    TyposquatDetector: "도메인 유사도",
    ProtocolDetector: "프로토콜 보안",
    DomainAgeDetector: "도메인 연령",
    ContentAnalyzer: "콘텐츠 분석",
    LLMAnalyzer: "AI 종합 분석",
  };

  var RISK_COLORS = {
    safe: "#16a34a",
    warning: "#f59e0b",
    danger: "#dc2626",
  };

  var RISK_LABELS = {
    safe: "안전",
    warning: "주의",
    danger: "위험",
  };

  // Circumference for r=56: 2 * Math.PI * 56 = 351.858...
  var CIRCUMFERENCE = 2 * Math.PI * 56;

  var PROVIDER_LOGOS = {
    glm: '<svg width="14" height="14" viewBox="0 0 30 30" fill="none"><rect x="1.49" y="1.49" rx="4" width="27.02" height="27.02" fill="#16162b"/><path d="M15.47,7.1l-1.3,1.85c-0.2,0.29-0.54,0.47-0.9,0.47h-7.1V7.09C6.16,7.1,15.47,7.1,15.47,7.1z" fill="white"/><polygon points="24.3,7.1 13.14,22.91 5.7,22.91 16.86,7.1" fill="white"/><path d="M14.53,22.91l1.31-1.86c0.2-0.29,0.54-0.47,0.9-0.47h7.09v2.33H14.53z" fill="white"/></svg>',
    gemini:
      '<svg width="14" height="14" viewBox="0 0 28 28" fill="none"><defs><linearGradient id="g-chip" x1="0" y1="0" x2="28" y2="28" gradientUnits="userSpaceOnUse"><stop stop-color="#1BA1E3"/><stop offset=".3" stop-color="#5489D6"/><stop offset=".6" stop-color="#9B72CB"/><stop offset=".9" stop-color="#D96570"/><stop offset="1" stop-color="#F49C46"/></linearGradient></defs><path d="M14 0C14 7.732 7.732 14 0 14c7.732 0 14 6.268 14 14 0-7.732 6.268-14 14-14-7.732 0-14-6.268-14-14z" fill="url(#g-chip)"/></svg>',
  };

  var PROVIDER_NAMES = { glm: "GLM", gemini: "Gemini" };

  /* ====== DOM References ====== */

  var popupEl = document.getElementById("popup");
  var domainEl = document.getElementById("current-domain");
  var gaugeFill = document.getElementById("gauge-fill");
  var gaugeScore = document.getElementById("gauge-score");
  var gaugeLabel = document.getElementById("gauge-label");
  var gaugeRiskText = document.getElementById("gauge-risk-text");
  var mainView = document.getElementById("main-view");
  var resultsList = document.getElementById("results-list");
  var settingsPanel = document.getElementById("settings-panel");
  var settingsToggle = document.getElementById("settings-toggle");
  var llmChip = document.getElementById("llm-chip");
  var llmChipIcon = document.getElementById("llm-chip-icon");
  var llmChipText = document.getElementById("llm-chip-text");
  var modelPicker = document.getElementById("model-picker");
  var apiKeyInput = document.getElementById("api-key");
  var _selectedProvider = "gemini";
  var saveBtn = document.getElementById("settings-save");
  var statusEl = document.getElementById("settings-status");

  // Toggle elements
  var extToggleLabel = document.getElementById("ext-toggle-label");
  var extToggle = document.getElementById("ext-toggle");
  var settingsExtToggle = document.getElementById("settings-ext-toggle");
  var settingsLlmToggle = document.getElementById("settings-llm-toggle");
  var llmSettingsGroup = document.getElementById("llm-settings-group");

  /* ====== Initialization ====== */

  document.addEventListener("DOMContentLoaded", init);

  function init() {
    bindEvents();
    loadToggles();
    loadLlmChip();
    loadActiveTab();
  }

  /* ====== Event Binding ====== */

  function bindEvents() {
    // Settings toggle
    settingsToggle.addEventListener("click", toggleSettings);
    llmChip.addEventListener("click", toggleSettings);

    // Save settings
    saveBtn.addEventListener("click", saveSettings);

    // Model picker
    var items = modelPicker.querySelectorAll(".model-picker__item");
    for (var i = 0; i < items.length; i++) {
      items[i].addEventListener("click", function () {
        selectProvider(this.getAttribute("data-value"));
      });
    }

    // Extension on/off toggles (header + settings synced)
    extToggle.addEventListener("change", function () {
      setExtEnabled(this.checked);
    });
    settingsExtToggle.addEventListener("change", function () {
      setExtEnabled(this.checked);
    });

    // LLM on/off toggle
    settingsLlmToggle.addEventListener("change", function () {
      setLlmEnabled(this.checked);
    });
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
        domainEl.textContent = tab.url || "알 수 없음";
      }

      // Request analysis result from background
      chrome.runtime.sendMessage(
        { type: "GET_RESULT", tabId: tab.id },
        function (result) {
          if (chrome.runtime.lastError || !result) {
            // 결과 없음 → 자동 분석 트리거
            triggerAnalysis(tab.id, tab.url);
            return;
          }

          if (result.status === "analyzing") {
            // 검증 중: 분석 진행 중
            showAnalyzing();
            // 분석 완료될 때까지 폴링
            pollForResult(tab.id);
            return;
          }

          // 검증 후: 결과 표시
          render(result);
        },
      );
    });
  }

  /**
   * 미분석 탭에 대해 백그라운드에 분석 요청
   */
  function triggerAnalysis(tabId, url) {
    showAnalyzing();
    chrome.runtime.sendMessage(
      { type: "TRIGGER_ANALYZE", tabId: tabId, url: url },
      function () {
        if (chrome.runtime.lastError) {
          showEmpty("분석을 시작할 수 없습니다.");
          return;
        }
        pollForResult(tabId);
      },
    );
  }

  /**
   * 검증 중 UI
   */
  function showAnalyzing() {
    gaugeScore.textContent = "...";
    gaugeLabel.textContent = "분석 중";
    gaugeRiskText.textContent = "사이트를 분석하고 있습니다";
    gaugeRiskText.className = "gauge__risk-text";
    gaugeFill.style.strokeDashoffset = CIRCUMFERENCE * 0.65;
    gaugeFill.style.stroke = "#a78bfa";
    gaugeFill.classList.add("gauge__fill--analyzing");
    resultsList.innerHTML =
      '<div class="results__loading">' +
      '<div class="loading-dots"><span></span><span></span><span></span></div>' +
      "<p>검증 모듈을 실행 중입니다...</p>" +
      "</div>";
  }

  /**
   * 분석 결과 폴링 (1초 간격, 최대 30초)
   */
  function pollForResult(tabId) {
    var attempts = 0;
    var maxAttempts = 30;
    var interval = setInterval(function () {
      attempts++;
      if (attempts >= maxAttempts) {
        clearInterval(interval);
        showEmpty("분석 시간이 초과되었습니다.");
        return;
      }
      chrome.runtime.sendMessage(
        { type: "GET_RESULT", tabId: tabId },
        function (result) {
          if (chrome.runtime.lastError) return;
          if (result && result.status === "complete") {
            clearInterval(interval);
            gaugeFill.classList.remove("gauge__fill--analyzing");
            render(result);
          }
        },
      );
    }, 1000);
  }

  /* ====== Rendering ====== */

  function render(result) {
    var totalRisk = result.totalRisk || 0;
    var riskLevel = result.riskLevel || "safe";
    var results = result.results || [];
    var whitelisted = result.whitelisted || false;

    updateGauge(totalRisk, riskLevel);

    if (whitelisted) {
      resultsList.innerHTML =
        '<p class="results__empty">알려진 안전한 사이트입니다.</p>';
      return;
    }

    // Filter to results with confidence > 0, 또는 LLM 에러 결과 포함
    // AI 카드를 최상단에 배치
    var filtered = results
      .filter(function (r) {
        return r.confidence > 0 || (r.name === "LLMAnalyzer" && r.details && r.details.apiError);
      })
      .sort(function (a, b) {
        return (b.name === "LLMAnalyzer") - (a.name === "LLMAnalyzer");
      });

    if (filtered.length === 0) {
      resultsList.innerHTML =
        '<p class="results__empty">분석 결과가 없습니다.</p>';
      return;
    }

    resultsList.innerHTML = filtered
      .map(function (r) {
        var cls = riskClass(r.risk);
        var label = MODULE_LABELS[r.name] || r.name;
        var reason = escapeHtml(r.reason || "");
        var isAI = r.name === "LLMAnalyzer";
        var isAIError = isAI && r.details && r.details.apiError;
        var cardClass = "result-card" + (isAI ? " result-card--ai" : "") + (isAIError ? " result-card--error" : "");
        var aiBadge = isAI
          ? '<span class="result-card__ai-badge">' + (isAIError ? "Error" : "AI") + '</span>'
          : "";

        var errorDetail = "";
        if (isAIError && r.details.error) {
          errorDetail = '<div class="result-card__error-detail">' +
            '<span class="result-card__error-label">API Response</span>' +
            '<pre class="result-card__error-body">' + escapeHtml(r.details.error) + '</pre>' +
            '</div>';
        }

        var findingsList = "";
        if (r.name === "ContentAnalyzer" && r.details && r.details.findings && r.details.findings.length > 0) {
          var items = r.details.findings.map(function (f) {
            var bullets = [];
            if (f.matches && f.matches.length > 0) {
              bullets = f.matches;
            } else if (f.details && f.details.length > 0) {
              bullets = f.details;
            }
            var bulletHtml = bullets.length > 0
              ? '<ul class="result-card__finding-bullets">' +
                bullets.map(function (b) {
                  return '<li>' + escapeHtml(b) + '</li>';
                }).join("") +
                '</ul>'
              : "";
            return '<li><strong>' + escapeHtml(f.description) + '</strong>' + bulletHtml + '</li>';
          }).join("");
          findingsList = '<ul class="result-card__findings">' + items + '</ul>';
        }

        return (
          '<div class="' +
          cardClass +
          '">' +
          '<div class="result-card__header">' +
          '<span class="result-card__name">' +
          label +
          aiBadge +
          "</span>" +
          '<span class="result-card__risk result-card__risk--' +
          cls +
          '">' +
          (isAIError ? "오류" : r.risk) +
          "</span>" +
          '<span class="result-card__chevron">&#9660;</span>' +
          "</div>" +
          '<p class="result-card__reason">' +
          reason +
          "</p>" +
          findingsList +
          errorDetail +
          "</div>"
        );
      })
      .join("");

    // Bind accordion click handlers
    var cards = resultsList.querySelectorAll(".result-card");
    for (var i = 0; i < cards.length; i++) {
      cards[i].addEventListener("click", handleCardToggle);
    }
  }

  function handleCardToggle() {
    this.classList.toggle("result-card--expanded");
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
    gaugeLabel.textContent = RISK_LABELS[level] || "안전";

    // Large risk text below gauge
    gaugeRiskText.textContent = RISK_LABELS[level] || "분석 중...";
    gaugeRiskText.className = "gauge__risk-text";
    if (level && RISK_LABELS[level]) {
      gaugeRiskText.classList.add("gauge__risk-text--" + level);
    }
  }

  /* ====== Toggle Controls ====== */

  function loadToggles() {
    chrome.storage.sync.get(["extEnabled", "llmEnabled"], function (data) {
      // extEnabled defaults to true
      var ext = data.extEnabled !== false;
      var llm = !!data.llmEnabled;

      extToggle.checked = ext;
      settingsExtToggle.checked = ext;
      applyExtState(ext);

      settingsLlmToggle.checked = llm;
      applyLlmState(llm);
    });
  }

  function setExtEnabled(enabled) {
    // Sync both toggles
    extToggle.checked = enabled;
    settingsExtToggle.checked = enabled;

    chrome.storage.sync.set({ extEnabled: enabled });
    applyExtState(enabled);
  }

  function applyExtState(enabled) {
    if (enabled) {
      popupEl.classList.remove("popup--disabled");
      extToggleLabel.textContent = "보호 중";
      extToggleLabel.classList.remove("header__toggle-label--off");
    } else {
      popupEl.classList.add("popup--disabled");
      extToggleLabel.textContent = "꺼짐";
      extToggleLabel.classList.add("header__toggle-label--off");
    }
  }

  function setLlmEnabled(enabled) {
    settingsLlmToggle.checked = enabled;
    chrome.storage.sync.set({ llmEnabled: enabled });

    if (!enabled) {
      // LLM off → delete API key and provider
      chrome.storage.sync.remove(["apiKey", "llmProvider"], function () {
        if (chrome.runtime.lastError) {
          /* noop */
        }
      });
      apiKeyInput.value = "";
      updateLlmChip("", false);
      showStatus(
        "AI 분석이 비활성화되었습니다. API 키가 삭제되었습니다.",
        "success",
      );
    }

    applyLlmState(enabled);
  }

  function applyLlmState(enabled) {
    if (enabled) {
      llmSettingsGroup.classList.remove("llm-settings-group--hidden");
    } else {
      llmSettingsGroup.classList.add("llm-settings-group--hidden");
    }
  }

  /* ====== Settings Panel ====== */

  function toggleSettings() {
    var isVisible = settingsPanel.classList.contains("settings--visible");

    if (isVisible) {
      // Hide settings, show main
      settingsPanel.classList.remove("settings--visible");
      mainView.style.display = "";
      settingsToggle.classList.remove("footer__settings-btn--active");
      clearStatus();

      // LLM 활성화했지만 API 키가 없으면 토글 off로 복원
      revertLlmIfNoKey();
    } else {
      // Show settings, hide main
      mainView.style.display = "none";
      settingsPanel.classList.add("settings--visible");
      settingsToggle.classList.add("footer__settings-btn--active");
      loadSettings();
    }
  }

  function loadLlmChip() {
    chrome.storage.sync.get(["llmProvider", "apiKey"], function (data) {
      updateLlmChip(data.llmProvider || "", !!data.apiKey);
    });
  }

  function updateLlmChip(provider, hasKey) {
    if (provider && hasKey) {
      llmChipIcon.innerHTML = PROVIDER_LOGOS[provider] || "";
      llmChipText.textContent = PROVIDER_NAMES[provider] || provider;
      llmChip.classList.add("llm-chip--active");
    } else {
      llmChipIcon.innerHTML = "";
      llmChipText.textContent = "AI 검증 활성화하기";
      llmChip.classList.remove("llm-chip--active");
    }
  }

  function selectProvider(value) {
    _selectedProvider = value;
    var items = modelPicker.querySelectorAll(".model-picker__item");
    for (var i = 0; i < items.length; i++) {
      if (items[i].getAttribute("data-value") === value) {
        items[i].classList.add("model-picker__item--selected");
      } else {
        items[i].classList.remove("model-picker__item--selected");
      }
    }
  }

  function loadSettings() {
    chrome.storage.sync.get(
      ["llmProvider", "apiKey", "extEnabled", "llmEnabled"],
      function (data) {
        // Sync toggles
        var ext = data.extEnabled !== false;
        var llm = !!data.llmEnabled;
        extToggle.checked = ext;
        settingsExtToggle.checked = ext;
        settingsLlmToggle.checked = llm;
        applyLlmState(llm);

        selectProvider(data.llmProvider || "gemini");
        if (data.apiKey) {
          apiKeyInput.value = data.apiKey;
        }
      },
    );
  }

  function saveSettings() {
    var provider = _selectedProvider || "gemini";
    var apiKey = apiKeyInput.value.trim();

    if (!apiKey) {
      showStatus("API 키를 입력해주세요.", "error");
      return;
    }

    // 버튼 비활성화 + 검증 중 표시
    saveBtn.disabled = true;
    saveBtn.textContent = "키 검증 중...";
    showStatus("API 키를 검증하고 있습니다...", "success");

    // 백그라운드에서 실제 API 호출로 키 검증
    chrome.runtime.sendMessage(
      {
        type: "VERIFY_API_KEY",
        provider: provider,
        apiKey: apiKey,
      },
      function (response) {
        saveBtn.disabled = false;
        saveBtn.textContent = "저장";

        if (chrome.runtime.lastError) {
          showStatus("검증 실패: 백그라운드 연결 오류", "error");
          return;
        }

        if (!response || !response.valid) {
          showStatus(response?.error || "API 키 검증에 실패했습니다.", "error");
          return;
        }

        // 검증 성공 → 저장
        var settings = {
          llmProvider: provider,
          apiKey: apiKey,
        };

        chrome.storage.sync.set(settings, function () {
          if (chrome.runtime.lastError) {
            showStatus(
              "저장 실패: " + chrome.runtime.lastError.message,
              "error",
            );
            return;
          }

          updateLlmChip(provider, true);
          showStatus("API 키가 검증되어 저장되었습니다.", "success");
        });
      },
    );
  }

  function showStatus(message, type) {
    statusEl.textContent = message;
    statusEl.className = "settings__status";
    if (type) {
      statusEl.classList.add("settings__status--" + type);
    }

    // Auto-clear after 3 seconds
    setTimeout(clearStatus, 3000);
  }

  function clearStatus() {
    statusEl.textContent = "";
    statusEl.className = "settings__status";
  }

  /* ====== LLM Key Guard ====== */

  function revertLlmIfNoKey() {
    chrome.storage.sync.get(["llmEnabled", "apiKey"], function (data) {
      if (data.llmEnabled && !data.apiKey) {
        settingsLlmToggle.checked = false;
        chrome.storage.sync.set({ llmEnabled: false });
        applyLlmState(false);
        updateLlmChip("", false);
      }
    });
  }

  /* ====== Helpers ====== */

  function riskClass(score) {
    if (score >= 70) return "danger";
    if (score >= 40) return "warning";
    return "safe";
  }

  function showEmpty(msg) {
    resultsList.innerHTML =
      '<p class="results__empty">' + escapeHtml(msg) + "</p>";
  }

  function escapeHtml(str) {
    var div = document.createElement("div");
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
  }
})();
