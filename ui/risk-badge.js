/**
 * PhishGuard - 익스텐션 아이콘 뱃지 (위험도 색상 표시)
 */

const RiskBadge = {
  /**
   * 뱃지 업데이트
   * @param {number} tabId - 탭 ID
   * @param {number} totalRisk - 종합 위험도 (0~100)
   * @param {string} riskLevel - 'safe' | 'warning' | 'danger'
   */
  async update(tabId, totalRisk, riskLevel) {
    const config = this._getConfig(riskLevel, totalRisk);

    try {
      await chrome.action.setBadgeText({
        text: config.text,
        tabId
      });

      await chrome.action.setBadgeBackgroundColor({
        color: config.color,
        tabId
      });

      await chrome.action.setTitle({
        title: config.title,
        tabId
      });
    } catch (error) {
      console.error('[PhishGuard:RiskBadge] Failed to update badge:', error);
    }
  },

  /**
   * 뱃지 초기화
   */
  async clear(tabId) {
    try {
      await chrome.action.setBadgeText({ text: '', tabId });
      await chrome.action.setTitle({ title: 'PhishGuard - AI 피싱 감지', tabId });
    } catch (error) {
      console.error('[PhishGuard:RiskBadge] Failed to clear badge:', error);
    }
  },

  /**
   * 분석 중 표시
   */
  async showLoading(tabId) {
    try {
      await chrome.action.setBadgeText({ text: '...', tabId });
      await chrome.action.setBadgeBackgroundColor({ color: '#6b7280', tabId });
      await chrome.action.setTitle({ title: 'PhishGuard - 분석 중...', tabId });
    } catch (error) {
      console.error('[PhishGuard:RiskBadge] Failed to show loading:', error);
    }
  },

  _getConfig(riskLevel, totalRisk) {
    switch (riskLevel) {
      case 'danger':
        return {
          text: String(totalRisk),
          color: '#dc2626',
          title: `PhishGuard - 위험! (${totalRisk}/100)`
        };
      case 'warning':
        return {
          text: String(totalRisk),
          color: '#f59e0b',
          title: `PhishGuard - 주의 (${totalRisk}/100)`
        };
      case 'safe':
        return {
          text: '',
          color: '#16a34a',
          title: 'PhishGuard - 안전'
        };
      default:
        return {
          text: '',
          color: '#6b7280',
          title: 'PhishGuard - AI 피싱 감지'
        };
    }
  }
};

export default RiskBadge;
