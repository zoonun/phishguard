/**
 * PhishGuard - 콘텐츠 분석 감지 모듈
 * 페이지 DOM 내용을 분석하여 피싱 특징적 패턴 감지
 */

import Logger from '../utils/logger.js';

// 긴급성/공포 유도 문구 패턴
const URGENT_PATTERNS_KO = [
  { pattern: /계정이?\s*정지/gi, weight: 0.8 },
  { pattern: /즉시\s*확인/gi, weight: 0.7 },
  { pattern: /24시간\s*내/gi, weight: 0.6 },
  { pattern: /보안\s*위협/gi, weight: 0.7 },
  { pattern: /비밀번호\s*변경\s*필요/gi, weight: 0.6 },
  { pattern: /본인\s*확인/gi, weight: 0.5 },
  { pattern: /계정이?\s*잠겼/gi, weight: 0.8 },
  { pattern: /접속이?\s*제한/gi, weight: 0.7 },
  { pattern: /이상\s*거래/gi, weight: 0.8 },
  { pattern: /긴급\s*조치/gi, weight: 0.7 },
  { pattern: /보안\s*업데이트/gi, weight: 0.5 },
  { pattern: /개인\s*정보.*유출/gi, weight: 0.8 },
  { pattern: /법적\s*조치/gi, weight: 0.7 },
  { pattern: /48시간\s*이내/gi, weight: 0.6 }
];

const URGENT_PATTERNS_EN = [
  { pattern: /account\s*suspended/gi, weight: 0.8 },
  { pattern: /verify\s*immediately/gi, weight: 0.7 },
  { pattern: /urgent\s*action\s*required/gi, weight: 0.8 },
  { pattern: /your\s*account\s*has\s*been/gi, weight: 0.6 },
  { pattern: /unauthorized\s*access/gi, weight: 0.7 },
  { pattern: /security\s*alert/gi, weight: 0.6 },
  { pattern: /confirm\s*your\s*identity/gi, weight: 0.6 },
  { pattern: /unusual\s*activity/gi, weight: 0.6 },
  { pattern: /immediate\s*action/gi, weight: 0.7 },
  { pattern: /will\s*be\s*(locked|closed|suspended)/gi, weight: 0.8 }
];

// 보상/당첨 유도 문구
const REWARD_PATTERNS_KO = [
  { pattern: /당첨/gi, weight: 0.8 },
  { pattern: /무료\s*제공/gi, weight: 0.6 },
  { pattern: /이벤트\s*당선/gi, weight: 0.8 },
  { pattern: /상금/gi, weight: 0.7 },
  { pattern: /경품/gi, weight: 0.6 },
  { pattern: /축하합니다/gi, weight: 0.7 },
  { pattern: /선정되었습니다/gi, weight: 0.7 },
  { pattern: /수령하세요/gi, weight: 0.6 },
  { pattern: /지급\s*대기/gi, weight: 0.7 }
];

const REWARD_PATTERNS_EN = [
  { pattern: /congratulations.*won/gi, weight: 0.8 },
  { pattern: /free\s*gift/gi, weight: 0.7 },
  { pattern: /claim\s*your\s*prize/gi, weight: 0.8 },
  { pattern: /you\s*(have\s*)?won/gi, weight: 0.7 },
  { pattern: /selected\s*winner/gi, weight: 0.8 }
];

// 알려진 브랜드 키워드 (타이틀/이미지 URL에서 감지)
const KNOWN_BRANDS = [
  'naver', 'kakao', 'google', 'apple', 'samsung', 'microsoft',
  'facebook', 'instagram', 'amazon', 'paypal', 'netflix',
  '네이버', '카카오', '구글', '삼성', '애플', '국민은행', '신한은행',
  '우리은행', '하나은행', '농협', '토스', '쿠팡'
];

const ContentAnalyzer = {
  name: 'ContentAnalyzer',
  weight: 0.2,

  async analyze(context) {
    const { hostname, domContent, pageTitle } = context;

    Logger.debug(`[ContentAnalyzer] Analyzing content for: ${hostname}`);

    if (!domContent && !pageTitle) {
      return {
        risk: 0,
        confidence: 0,
        reason: '페이지 콘텐츠 정보가 없어 분석할 수 없습니다.',
        details: { error: 'no_content' }
      };
    }

    const findings = [];
    let totalWeight = 0;

    // 1. 긴급성/공포 유도 문구 감지
    const urgencyResult = this._checkUrgencyPatterns(domContent?.textContent || '');
    if (urgencyResult.found) {
      findings.push({
        type: 'urgency',
        description: '긴급성/공포 유도 문구 감지',
        matches: urgencyResult.matches,
        weight: urgencyResult.totalWeight
      });
      totalWeight += urgencyResult.totalWeight;
    }

    // 2. 보상/당첨 유도 문구 감지
    const rewardResult = this._checkRewardPatterns(domContent?.textContent || '');
    if (rewardResult.found) {
      findings.push({
        type: 'reward',
        description: '보상/당첨 유도 문구 감지',
        matches: rewardResult.matches,
        weight: rewardResult.totalWeight
      });
      totalWeight += rewardResult.totalWeight;
    }

    // 3. 의심스러운 입력 폼 감지
    const formResult = this._checkSuspiciousForms(domContent, hostname);
    if (formResult.found) {
      findings.push({
        type: 'suspicious_form',
        description: '의심스러운 입력 폼 감지',
        details: formResult.details,
        weight: formResult.weight
      });
      totalWeight += formResult.weight;
    }

    // 4. 브랜드 위장 감지 (타이틀/로고)
    const brandResult = this._checkBrandImpersonation(hostname, pageTitle, domContent);
    if (brandResult.found) {
      findings.push({
        type: 'brand_impersonation',
        description: '브랜드 위장 감지',
        details: brandResult.details,
        weight: brandResult.weight
      });
      totalWeight += brandResult.weight;
    }

    // 5. 외부 리소스 분석
    const externalResult = this._checkExternalResources(hostname, domContent);
    if (externalResult.found) {
      findings.push({
        type: 'external_resource',
        description: '의심스러운 외부 리소스 감지',
        details: externalResult.details,
        weight: externalResult.weight
      });
      totalWeight += externalResult.weight;
    }

    // 종합 위험도 산출
    const risk = Math.min(100, Math.round(totalWeight * 100));
    const confidence = findings.length > 0 ? Math.min(0.95, 0.5 + findings.length * 0.1) : 0.9;

    if (findings.length === 0) {
      return {
        risk: 0,
        confidence: 0.8,
        reason: '페이지 콘텐츠에서 의심스러운 패턴이 감지되지 않았습니다.',
        details: { findings: [] }
      };
    }

    const reasons = findings.map(f => f.description).join(', ');

    return {
      risk,
      confidence,
      reason: `이 페이지에서 의심스러운 요소가 감지되었습니다: ${reasons}`,
      details: { findings, totalPatterns: findings.length }
    };
  },

  /**
   * 긴급성/공포 유도 문구 검사
   */
  _checkUrgencyPatterns(text) {
    const matches = [];
    let totalWeight = 0;

    const allPatterns = [...URGENT_PATTERNS_KO, ...URGENT_PATTERNS_EN];

    for (const { pattern, weight } of allPatterns) {
      const match = text.match(pattern);
      if (match) {
        matches.push(match[0]);
        totalWeight += weight;
      }
    }

    // 최대 가중치 제한
    totalWeight = Math.min(totalWeight, 1.0);

    return {
      found: matches.length > 0,
      matches: [...new Set(matches)],
      totalWeight: totalWeight * 0.8 // 긴급성만으로 최대 80%
    };
  },

  /**
   * 보상/당첨 유도 문구 검사
   */
  _checkRewardPatterns(text) {
    const matches = [];
    let totalWeight = 0;

    const allPatterns = [...REWARD_PATTERNS_KO, ...REWARD_PATTERNS_EN];

    for (const { pattern, weight } of allPatterns) {
      const match = text.match(pattern);
      if (match) {
        matches.push(match[0]);
        totalWeight += weight;
      }
    }

    totalWeight = Math.min(totalWeight, 1.0);

    return {
      found: matches.length > 0,
      matches: [...new Set(matches)],
      totalWeight: totalWeight * 0.7
    };
  },

  /**
   * 의심스러운 입력 폼 검사
   */
  _checkSuspiciousForms(domContent, hostname) {
    if (!domContent || !domContent.forms || domContent.forms.length === 0) {
      return { found: false, weight: 0 };
    }

    const details = [];
    let weight = 0;

    for (const form of domContent.forms) {
      if (!form.inputs) continue;

      const inputTypes = form.inputs.map(i => (i.type || '').toLowerCase());
      const inputNames = form.inputs.map(i => (i.name || '').toLowerCase());
      const inputPlaceholders = form.inputs.map(i => (i.placeholder || '').toLowerCase());
      const allText = [...inputNames, ...inputPlaceholders].join(' ');

      // 패스워드 필드가 있는 알 수 없는 사이트
      if (inputTypes.includes('password')) {
        const isKnown = KNOWN_BRANDS.some(brand =>
          hostname.includes(brand)
        );
        if (!isKnown) {
          details.push('알 수 없는 사이트에서 비밀번호 입력 요구');
          weight += 0.3;
        }
      }

      // 주민등록번호 패턴
      if (allText.includes('주민') || allText.includes('ssn') ||
          allText.includes('resident')) {
        details.push('주민등록번호 입력 폼 감지');
        weight += 0.4;
      }

      // 카드번호 패턴
      if (allText.includes('카드') || allText.includes('card number') ||
          allText.includes('cvv') || allText.includes('cvc')) {
        details.push('카드번호 입력 폼 감지');
        weight += 0.3;
      }

      // 과도한 개인정보 요구 (이름+생년월일+전화번호+주소 동시)
      const personalFields = [
        allText.includes('이름') || allText.includes('name'),
        allText.includes('생년월일') || allText.includes('birth'),
        allText.includes('전화') || allText.includes('phone'),
        allText.includes('주소') || allText.includes('address')
      ].filter(Boolean).length;

      if (personalFields >= 3) {
        details.push('과도한 개인정보 동시 요구');
        weight += 0.4;
      }
    }

    weight = Math.min(weight, 1.0);

    return {
      found: details.length > 0,
      details,
      weight: weight * 0.8
    };
  },

  /**
   * 브랜드 위장 감지 (타이틀에 유명 브랜드명이 있지만 도메인이 다른 경우)
   */
  _checkBrandImpersonation(hostname, pageTitle, domContent) {
    const details = [];
    let weight = 0;

    const titleText = (pageTitle || '').toLowerCase();
    const metaDescription = (domContent?.metaDescription || '').toLowerCase();
    const textToCheck = titleText + ' ' + metaDescription;

    for (const brand of KNOWN_BRANDS) {
      const brandLower = brand.toLowerCase();

      // 도메인에 해당 브랜드가 포함되지 않는데 타이틀에 있는 경우
      if (textToCheck.includes(brandLower) && !hostname.includes(brandLower)) {
        details.push(`타이틀에 "${brand}" 브랜드명이 있지만 도메인(${hostname})이 일치하지 않음`);
        weight += 0.4;
        break; // 하나만 감지해도 충분
      }
    }

    // 외부 파비콘 사용 감지
    if (domContent?.favicon) {
      for (const brand of KNOWN_BRANDS) {
        if (domContent.favicon.includes(brand) && !hostname.includes(brand)) {
          details.push(`${brand}의 파비콘을 사용하지만 도메인이 다름`);
          weight += 0.3;
          break;
        }
      }
    }

    weight = Math.min(weight, 1.0);

    return {
      found: details.length > 0,
      details,
      weight: weight * 0.9
    };
  },

  /**
   * 외부 리소스 분석
   */
  _checkExternalResources(hostname, domContent) {
    if (!domContent || !domContent.externalResources) {
      return { found: false, weight: 0 };
    }

    const details = [];
    let weight = 0;

    // 유명 사이트의 이미지/로고를 사용하는데 도메인이 다른 경우
    for (const resourceUrl of domContent.externalResources) {
      for (const brand of KNOWN_BRANDS) {
        if (resourceUrl.includes(brand) && !hostname.includes(brand)) {
          // 이미지 리소스인 경우 (로고 도용 의심)
          if (/\.(png|jpg|jpeg|gif|svg|ico)/i.test(resourceUrl) &&
              /(logo|brand|icon)/i.test(resourceUrl)) {
            details.push(`${brand}의 로고/이미지를 외부에서 로드`);
            weight += 0.3;
          }
        }
      }
    }

    weight = Math.min(weight, 0.5);

    return {
      found: details.length > 0,
      details,
      weight
    };
  }
};

export default ContentAnalyzer;
