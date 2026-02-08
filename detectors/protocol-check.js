/**
 * PhishGuard - 프로토콜 검사 감지 모듈
 * HTTP(비암호화) 프로토콜 사용 사이트 감지
 */

import Logger from '../utils/logger.js';

const ProtocolDetector = {
  name: 'ProtocolDetector',
  weight: 0.15,

  async analyze(context) {
    const { protocol, domContent } = context;

    Logger.debug(`[ProtocolDetector] Analyzing protocol: ${protocol}`);

    // HTTPS 정상
    if (protocol === 'https:') {
      const mixedContent = this._checkMixedContent(domContent);
      if (mixedContent.found) {
        return {
          risk: 30,
          confidence: 0.7,
          reason: '이 HTTPS 사이트에서 암호화되지 않은 HTTP 리소스가 로드되고 있습니다 (Mixed Content).',
          details: {
            protocol: 'https',
            issue: 'mixed_content',
            mixedResources: mixedContent.resources
          }
        };
      }

      return {
        risk: 0,
        confidence: 1.0,
        reason: '이 사이트는 안전한 HTTPS 연결을 사용합니다.',
        details: { protocol: 'https', issue: 'none' }
      };
    }

    // HTTP 사이트
    if (protocol === 'http:') {
      const hasSensitiveForms = this._checkSensitiveForms(domContent);

      if (hasSensitiveForms.found) {
        return {
          risk: 80,
          confidence: 0.9,
          reason: '이 사이트는 암호화되지 않은 HTTP 연결을 사용하며, 로그인 또는 개인정보 입력 폼이 존재합니다. 입력하는 정보가 노출될 수 있습니다.',
          details: {
            protocol: 'http',
            issue: 'sensitive_form_on_http',
            formTypes: hasSensitiveForms.types
          }
        };
      }

      return {
        risk: 40,
        confidence: 0.8,
        reason: '이 사이트는 암호화되지 않은 HTTP 연결을 사용합니다. 입력하는 정보가 노출될 수 있습니다.',
        details: {
          protocol: 'http',
          issue: 'no_encryption'
        }
      };
    }

    // 기타 프로토콜 (file:, ftp: 등)
    return {
      risk: 20,
      confidence: 0.5,
      reason: `이 사이트는 일반적이지 않은 프로토콜(${protocol})을 사용합니다.`,
      details: { protocol, issue: 'unusual_protocol' }
    };
  },

  /**
   * 민감한 입력 폼 감지 (password, 카드번호, 주민번호 등)
   */
  _checkSensitiveForms(domContent) {
    if (!domContent) {
      return { found: false, types: [] };
    }

    const types = [];

    // password 필드 확인
    if (domContent.forms) {
      for (const form of domContent.forms) {
        if (form.inputs) {
          for (const input of form.inputs) {
            const type = (input.type || '').toLowerCase();
            const name = (input.name || '').toLowerCase();
            const placeholder = (input.placeholder || '').toLowerCase();

            if (type === 'password') {
              types.push('password');
            }

            // 카드번호 패턴
            if (name.includes('card') || name.includes('카드') ||
                placeholder.includes('카드') || placeholder.includes('card')) {
              types.push('credit_card');
            }

            // 주민등록번호 패턴
            if (name.includes('ssn') || name.includes('jumin') || name.includes('주민') ||
                placeholder.includes('주민등록')) {
              types.push('ssn');
            }

            // 계좌번호 패턴
            if (name.includes('account') || name.includes('계좌') ||
                placeholder.includes('계좌')) {
              types.push('bank_account');
            }
          }
        }
      }
    }

    return {
      found: types.length > 0,
      types: [...new Set(types)]
    };
  },

  /**
   * Mixed Content 감지 (HTTPS 페이지 내 HTTP 리소스)
   */
  _checkMixedContent(domContent) {
    if (!domContent || !domContent.externalResources) {
      return { found: false, resources: [] };
    }

    const httpResources = domContent.externalResources.filter(
      url => url.startsWith('http://')
    );

    return {
      found: httpResources.length > 0,
      resources: httpResources.slice(0, 10) // 최대 10개만
    };
  }
};

export default ProtocolDetector;
