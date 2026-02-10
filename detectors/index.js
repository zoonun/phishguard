/**
 * PhishGuard - 감지 모듈 통합 매니저 (DetectorManager)
 * 모든 감지 모듈을 등록하고 실행하여 종합 위험도를 산출
 */

import TyposquatDetector from './domain-typosquat.js';
import ProtocolDetector from './protocol-check.js';
import DomainAgeDetector from './domain-age.js';
import ContentAnalyzer from './content-analysis.js';
import KisaBlacklistDetector from './kisa-blacklist.js';
import LLMAnalyzer from './llm-analysis.js';
import Logger from '../utils/logger.js';

const DetectorManager = {
  // 등록된 감지 모듈 목록
  _detectors: [
    TyposquatDetector,
    ProtocolDetector,
    DomainAgeDetector,
    ContentAnalyzer,
    KisaBlacklistDetector
  ],

  // LLM 분석기 (별도 관리 - 조건부 실행)
  _llmAnalyzer: LLMAnalyzer,

  /**
   * 감지 모듈 등록
   */
  register(detector) {
    if (!detector.name || typeof detector.analyze !== 'function') {
      Logger.error('[DetectorManager] Invalid detector:', detector);
      return;
    }
    this._detectors.push(detector);
    Logger.info(`[DetectorManager] Registered: ${detector.name}`);
  },

  /**
   * 모든 감지 모듈 실행 및 종합 위험도 산출
   * @param {object} context - { url, hostname, protocol, pathname, domContent?, pageTitle? }
   * @param {object} options - { enableLLM, apiClient, prompts, ragContext, enabledDetectors }
   * @returns {object} { totalRisk, riskLevel, results }
   */
  async analyze(context, options = {}) {
    const {
      enableLLM = false,
      apiClient = null,
      prompts = null,
      ragContext = null,
      enabledDetectors = null
    } = options;

    Logger.info(`[DetectorManager] Starting analysis for: ${context.hostname}`);

    const results = [];

    // 활성화된 감지 모듈 필터링
    const activeDetectors = this._detectors.filter(detector => {
      if (!enabledDetectors) return true;
      const nameMap = {
        'TyposquatDetector': 'typosquat',
        'ProtocolDetector': 'protocol',
        'DomainAgeDetector': 'domainAge',
        'ContentAnalyzer': 'contentAnalysis',
        'KisaBlacklistDetector': 'kisaBlacklist'
      };
      const key = nameMap[detector.name];
      return key ? enabledDetectors[key] !== false : true;
    });

    // 각 감지 모듈 실행 (병렬)
    const detectorPromises = activeDetectors.map(async (detector) => {
      try {
        Logger.debug(`[DetectorManager] Running: ${detector.name}`);
        const result = await detector.analyze(context);
        return {
          name: detector.name,
          weight: detector.weight,
          ...result
        };
      } catch (error) {
        Logger.error(`[DetectorManager] ${detector.name} failed:`, error);
        return {
          name: detector.name,
          weight: detector.weight,
          risk: 0,
          confidence: 0,
          reason: `${detector.name} 분석 중 오류 발생`,
          details: { error: error.message }
        };
      }
    });

    const detectorResults = await Promise.all(detectorPromises);
    results.push(...detectorResults);

    // 1차 종합 점수 산출 (LLM 제외)
    const preliminaryScore = this._calculateTotalRisk(results);

    // LLM 분석 (조건부 실행)
    if (enableLLM && enabledDetectors?.llmAnalysis !== false) {
      const llmResult = await this._runLLMAnalysis(context, {
        previousResults: results,
        apiClient,
        prompts,
        ragContext,
        preliminaryScore
      });

      if (llmResult) {
        results.push({
          name: this._llmAnalyzer.name,
          weight: this._llmAnalyzer.weight,
          ...llmResult
        });
      }
    }

    // 최종 종합 점수 산출
    const totalRisk = this._calculateTotalRisk(results);
    const riskLevel = this._getRiskLevel(totalRisk);

    Logger.info(`[DetectorManager] Analysis complete: risk=${totalRisk}, level=${riskLevel}`);

    return {
      totalRisk,
      riskLevel,
      results
    };
  },

  /**
   * LLM 분석 실행 (조건부)
   */
  async _runLLMAnalysis(context, options) {
    const { previousResults, apiClient, prompts, ragContext, preliminaryScore } = options;

    // 의미 있는 범위(20점 이상)일 때 LLM 호출
    if (preliminaryScore < 20) {
      Logger.debug(`[DetectorManager] Skipping LLM (score: ${preliminaryScore})`);
      return null;
    }

    if (!apiClient) {
      Logger.debug(`[DetectorManager] Skipping LLM (no API client)`);
      return null;
    }

    try {
      return await this._llmAnalyzer.analyze(context, {
        previousResults,
        apiClient,
        prompts,
        ragContext
      });
    } catch (error) {
      Logger.error(`[DetectorManager] LLM analysis failed:`, error);
      return null;
    }
  },

  /**
   * 종합 위험도 점수 산출 (가중 평균)
   */
  _calculateTotalRisk(results) {
    // confidence가 0인 결과는 제외 (데이터 없음/오류)
    const validResults = results.filter(r => r.confidence > 0);

    if (validResults.length === 0) return 0;

    // 가중 평균 계산
    let weightedSum = 0;
    let totalWeight = 0;

    for (const result of validResults) {
      const effectiveWeight = result.weight * result.confidence;
      weightedSum += result.risk * effectiveWeight;
      totalWeight += effectiveWeight;
    }

    let totalRisk = totalWeight > 0 ? Math.round(weightedSum / totalWeight) : 0;

    // risk가 90 이상인 모듈이 하나라도 있으면 최소 70점
    const hasHighRisk = validResults.some(r => r.risk >= 90 && r.confidence >= 0.5);
    if (hasHighRisk && totalRisk < 70) {
      totalRisk = 70;
    }

    return Math.min(100, Math.max(0, totalRisk));
  },

  /**
   * 위험도 수준 분류
   */
  _getRiskLevel(totalRisk) {
    if (totalRisk >= 70) return 'danger';
    if (totalRisk >= 40) return 'warning';
    return 'safe';
  },

  /**
   * 등록된 감지 모듈 목록 반환
   */
  getDetectors() {
    return this._detectors.map(d => ({
      name: d.name,
      weight: d.weight
    }));
  }
};

export default DetectorManager;
