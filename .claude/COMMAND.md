# 🛡️ PhishGuard — 피싱/스캠 감지 크롬 익스텐션 개발 커맨드 문서

## 프로젝트 개요

| 항목           | 내용                                                                 |
| -------------- | -------------------------------------------------------------------- |
| **프로젝트명** | **PhishGuard** (피시가드)                                            |
| **슬로건**     | "당신의 브라우저를 지키는 AI 경비원"                                 |
| **목적**       | 경진대회 제출용 MVP                                                  |
| **형태**       | Chrome Extension (Manifest V3)                                       |
| **핵심 기술**  | LLM API + Prompt Engineering + RAG 기반 피싱/스캠 사이트 실시간 감지 |

---

## 1. 프로젝트 초기 세팅

### Command 1: 프로젝트 구조 생성

```
아래 구조로 PhishGuard 크롬 익스텐션 프로젝트를 생성해줘.
Manifest V3 기반이고, 각 감지 로직은 독립 모듈로 분리해줘.

phishguard/
├── manifest.json                  # Chrome Extension Manifest V3
├── background/
│   └── service-worker.js          # 백그라운드 서비스 워커 (탭 URL 변경 감지, 분석 오케스트레이션)
├── content/
│   └── content-script.js          # 콘텐츠 스크립트 (페이지 DOM 정보 수집, alert UI 삽입)
├── popup/
│   ├── popup.html                 # 팝업 UI (현재 사이트 위험도, 상세 분석 결과)
│   ├── popup.css
│   └── popup.js
├── detectors/                     # 🔍 감지 모듈 (각 로직별 독립 파일)
│   ├── index.js                   # 감지 모듈 통합 매니저 (모든 detector 등록/실행)
│   ├── domain-typosquat.js        # 도메인 유사도 감지 (타이포스쿼팅)
│   ├── protocol-check.js          # HTTP/비보안 프로토콜 감지
│   ├── domain-age.js              # 도메인 등록일 기반 감지 (신규 도메인 경고)
│   ├── content-analysis.js        # 페이지 콘텐츠 분석 (긴급성 문구, 개인정보 입력폼 등)
│   └── llm-analysis.js            # LLM API 기반 종합 분석
├── rag/
│   ├── known-domains.json         # 주요 사이트 정규 도메인 DB (naver.com, kakao.com 등)
│   ├── phishing-patterns.json     # 알려진 피싱 패턴 DB (URL 패턴, 키워드 등)
│   └── rag-engine.js              # RAG 엔진 (로컬 DB 검색 + 컨텍스트 구성)
├── llm/
│   ├── api-client.js              # LLM API 호출 클라이언트 (Claude/OpenAI 등)
│   ├── prompts.js                 # 프롬프트 템플릿 관리
│   └── response-parser.js         # LLM 응답 파싱 및 구조화
├── ui/
│   ├── alert-banner.js            # 경고 배너 컴포넌트 (페이지 상단 삽입)
│   ├── alert-banner.css
│   ├── risk-badge.js              # 익스텐션 아이콘 뱃지 (위험도 색상 표시)
│   └── detail-panel.js            # 상세 분석 패널 (왜 위험한지 설명)
├── utils/
│   ├── string-similarity.js       # 문자열 유사도 계산 (Levenshtein, Jaro-Winkler 등)
│   ├── url-parser.js              # URL 파싱 유틸리티
│   └── logger.js                  # 디버그 로거
├── config/
│   └── settings.js                # 설정값 관리 (API 키, 임계값, 활성화 토글 등)
├── assets/
│   ├── icon-16.png
│   ├── icon-48.png
│   └── icon-128.png
└── README.md
```

---

## 2. 핵심 감지 모듈 구현

### Command 2: 감지 모듈 매니저 (detectors/index.js)

```
detectors/index.js를 구현해줘.

역할:
- 모든 감지 모듈을 등록하고, URL이 전달되면 각 모듈을 순차적으로 실행
- 각 모듈의 결과를 수집하여 종합 위험도 점수(0~100)를 산출
- 모듈마다 가중치(weight)를 설정할 수 있도록 설계

인터페이스:
- 각 detector 모듈은 동일한 인터페이스를 따름:
  {
    name: string,           // 모듈 이름
    weight: number,         // 가중치 (0~1)
    async analyze(context): {
      risk: number,         // 0~100
      confidence: number,   // 0~1
      reason: string,       // 감지 사유
      details: object       // 상세 데이터
    }
  }
- context 객체: { url, hostname, protocol, pathname, domContent?, pageTitle? }

종합 점수 산출:
- 가중 평균 방식이되, risk가 90 이상인 모듈이 하나라도 있으면 최소 70점 이상으로 설정
- 최종 결과: { totalRisk, riskLevel('safe'|'warning'|'danger'), results: [...] }
```

### Command 3: 타이포스쿼팅 감지 (detectors/domain-typosquat.js)

```
detectors/domain-typosquat.js를 구현해줘.

목적: 유명 사이트 도메인과 유사한 피싱 도메인을 감지

구현 내용:
1. rag/known-domains.json에서 주요 도메인 목록을 로드
2. 현재 접속한 도메인과 각 정규 도메인 간의 유사도를 계산
3. 유사도가 임계값(예: 0.85) 이상이면서 정확히 일치하지 않는 경우 피싱 의심

유사도 판별 기법 (utils/string-similarity.js 활용):
- Levenshtein Distance: 편집 거리 기반
- Jaro-Winkler Similarity: 문자 순서 유사도
- 문자 치환/추가/삭제 패턴 감지:
  - 글자 반복: naver → naverr, navver
  - 유사 문자 치환: google → g00gle (o→0), kakao → kakaq (o→q)
  - 글자 삽입: daum → dauim
  - 하이픈 삽입: naver-login.com
  - TLD 변경: naver.com → naver.net, naver.co
  - 서브도메인 위장: naver.com.evil.com

Homoglyph(동형문자) 감지:
- 키릴 문자 등 시각적으로 유사한 유니코드 문자 매핑 테이블 포함
  (예: а↔a, е↔e, о↔o, р↔p 등)
- 퓨니코드(Punycode) 도메인 디코딩하여 검사

반환값 예시:
{
  risk: 92,
  confidence: 0.95,
  reason: "이 도메인은 'naver.com'과 매우 유사합니다 (naverr.com). 타이포스쿼팅 피싱이 의심됩니다.",
  details: {
    matchedDomain: "naver.com",
    similarity: 0.92,
    technique: "character_repetition"
  }
}
```

### Command 4: 프로토콜 검사 (detectors/protocol-check.js)

```
detectors/protocol-check.js를 구현해줘.

목적: HTTP(비암호화) 프로토콜 사용 사이트 감지

구현 내용:
1. URL의 프로토콜이 http://인지 확인
2. 단순 HTTP 사이트는 중간 위험도, 개인정보 입력 폼이 있는 HTTP 사이트는 고위험
3. 추가 검사:
   - Mixed Content 감지 (HTTPS 페이지 내 HTTP 리소스 로드)
   - 유효하지 않은 SSL 인증서 관련 정보 (가능한 경우)
   - HTTP에서 민감한 폼(로그인, 결제 등)이 있는지 확인

위험도 산정:
- http:// + 일반 페이지: risk 40
- http:// + 로그인/개인정보 입력 폼 존재: risk 80
- https:// 정상: risk 0

reason 예시: "이 사이트는 암호화되지 않은 HTTP 연결을 사용합니다. 입력하는 정보가 노출될 수 있습니다."
```

### Command 5: 도메인 연령 감지 (detectors/domain-age.js)

```
detectors/domain-age.js를 구현해줘.

목적: 최근 등록된 도메인(신생 도메인)은 피싱에 자주 사용됨

구현 내용:
1. WHOIS API 또는 대안 API를 활용하여 도메인 등록일 조회
   (MVP에서는 무료 API 사용: 예시 - whoisjson.com, ip2whois 등)
2. 등록일 기준 위험도 산정:
   - 30일 미만: risk 70
   - 90일 미만: risk 50
   - 1년 미만: risk 30
   - 1년 이상: risk 5
3. API 호출 실패 시 graceful하게 처리 (risk: 0, confidence: 0 반환)
4. 결과 캐싱: 동일 도메인 반복 조회 방지 (chrome.storage.local 활용)

reason 예시: "이 도메인은 15일 전에 등록되었습니다. 최근 생성된 도메인은 피싱에 자주 사용됩니다."
```

### Command 6: 콘텐츠 분석 (detectors/content-analysis.js)

```
detectors/content-analysis.js를 구현해줘.

목적: 페이지 DOM 내용을 분석하여 피싱 특징적 패턴 감지

구현 내용:
1. 긴급성/공포 유도 문구 감지:
   - 한국어: "계정이 정지", "즉시 확인", "24시간 내", "보안 위협", "비밀번호 변경 필요",
     "당첨", "무료 제공", "지금 바로", "본인 확인" 등
   - 영어: "account suspended", "verify immediately", "urgent action required" 등
   - 정규식 패턴 매칭 + 가중치 부여

2. 의심스러운 입력 폼 감지:
   - password 필드가 있는데 도메인이 알려진 사이트가 아닌 경우
   - 주민등록번호, 카드번호 패턴의 입력 필드
   - 과도한 개인정보 요구 (이름+생년월일+전화번호+주소 동시 요구)

3. 외부 리소스 분석:
   - 이미지/로고는 유명 사이트 것인데 도메인은 다른 경우
   - 외부 사이트의 파비콘을 사용하는 경우

4. 메타 정보 분석:
   - <title>이 유명 사이트명을 포함하는데 도메인이 다른 경우
   - Open Graph 태그와 실제 도메인 불일치

위험도: 감지된 패턴 수와 종류에 따라 0~100 산출
```

### Command 7: LLM 종합 분석 (detectors/llm-analysis.js)

```
detectors/llm-analysis.js를 구현해줘.

목적: 다른 detector들의 결과와 페이지 정보를 종합하여 LLM에게 최종 판단을 요청

구현 내용:
1. 다른 모든 detector의 결과를 먼저 수집
2. RAG 엔진으로 관련 피싱 패턴 DB 검색
3. 아래 정보를 LLM에게 전달:
   - URL 정보 (도메인, 경로, 쿼리 파라미터)
   - 각 detector의 분석 결과 요약
   - RAG로 검색된 유사 피싱 패턴
   - 페이지 메타데이터 (title, description, 주요 텍스트)
4. LLM 응답을 파싱하여 구조화된 결과 반환

실행 조건:
- 다른 detector의 종합 점수가 30~80 사이일 때만 호출 (확실한 안전/위험은 호출 불필요)
- API 호출 실패 시 LLM 없이 다른 detector 결과만으로 판단
- rate limiting 적용 (분당 최대 5회)

반환값:
{
  risk: number,
  confidence: number,
  reason: "LLM 분석 결과 설명",
  details: {
    llmVerdict: "phishing" | "suspicious" | "safe",
    explanation: "상세 설명",
    suggestedAction: "이 사이트를 떠나세요" | "주의하세요" | "안전합니다"
  }
}
```

---

## 3. RAG 시스템 구현

### Command 8: 정규 도메인 DB (rag/known-domains.json)

```
rag/known-domains.json을 구현해줘.

한국 주요 사이트 위주 + 글로벌 주요 사이트를 포함하여 최소 50개 이상의 도메인을 등록해줘.

구조:
{
  "domains": [
    {
      "name": "네이버",
      "primary": "naver.com",
      "aliases": ["naver.me", "nid.naver.com", "m.naver.com"],
      "category": "portal",
      "country": "KR"
    },
    ...
  ]
}

포함 카테고리:
- portal: 네이버, 다음, 구글
- social: 카카오톡, 인스타그램, 페이스북, 트위터(X)
- banking: 국민은행, 신한은행, 우리은행, 하나은행, 농협, 카카오뱅크, 토스
- ecommerce: 쿠팡, 11번가, G마켓, 옥션
- government: 정부24, 국세청, 건강보험공단
- global: Google, Apple, Amazon, Microsoft, PayPal
```

### Command 9: 피싱 패턴 DB (rag/phishing-patterns.json)

```
rag/phishing-patterns.json을 구현해줘.

알려진 피싱 URL 패턴과 수법을 데이터베이스로 구성.

구조:
{
  "patterns": [
    {
      "id": "pattern_001",
      "type": "url_pattern",
      "pattern": "login.*verify.*account",
      "description": "로그인 인증을 가장한 URL 경로 패턴",
      "risk_weight": 0.7,
      "examples": ["/login/verify-account", "/user/login-verification"]
    },
    {
      "id": "pattern_002",
      "type": "domain_pattern",
      "pattern": "서브도메인에 유명 브랜드명을 포함하고 알 수 없는 TLD를 사용",
      "description": "naver.evil-domain.com 형태",
      "risk_weight": 0.9
    },
    ...
  ],
  "keywords": {
    "urgent_ko": ["긴급", "계정 정지", "보안 경고", "본인 확인 필요", ...],
    "urgent_en": ["urgent", "suspended", "verify now", ...],
    "reward_ko": ["당첨", "무료", "이벤트 당선", "상금", ...],
    "credential_ko": ["비밀번호", "주민등록번호", "카드번호", ...]
  }
}

최소 20개 이상의 패턴을 포함해줘.
```

### Command 10: RAG 엔진 (rag/rag-engine.js)

```
rag/rag-engine.js를 구현해줘.

목적: 로컬 JSON DB를 검색하여 LLM 프롬프트에 포함할 관련 컨텍스트를 구성

구현 내용:
1. known-domains.json에서 현재 도메인과 관련된 정규 도메인 검색
2. phishing-patterns.json에서 현재 URL/콘텐츠와 매칭되는 패턴 검색
3. 검색 결과를 LLM 프롬프트에 삽입할 수 있는 텍스트 형태로 포맷팅

메서드:
- findSimilarDomains(hostname): 유사 정규 도메인 목록 반환
- matchPhishingPatterns(url, content): 매칭되는 패턴 목록 반환
- buildContext(url, content): LLM에 전달할 RAG 컨텍스트 문자열 생성
```

---

## 4. LLM 연동

### Command 11: 프롬프트 설계 (llm/prompts.js)

```
llm/prompts.js를 구현해줘.

LLM API에 보낼 프롬프트 템플릿을 관리하는 모듈.

시스템 프롬프트:
"당신은 사이버 보안 전문가로서 웹사이트의 피싱/스캠 여부를 분석합니다.
제공된 정보를 기반으로 해당 웹사이트가 피싱/스캠인지 판단하고,
반드시 아래 JSON 형식으로만 응답하세요."

분석 요청 프롬프트 템플릿:
- URL 정보 (도메인, 프로토콜, 경로 등)
- 사전 분석 결과 (각 detector의 결과 요약)
- RAG 컨텍스트 (유사 도메인, 매칭 패턴)
- 페이지 콘텐츠 요약 (title, meta, 주요 텍스트 일부)

응답 형식 지정:
{
  "verdict": "phishing" | "suspicious" | "safe",
  "confidence": 0.0~1.0,
  "risk_score": 0~100,
  "reasons": ["이유1", "이유2"],
  "recommendation": "사용자에게 보여줄 권고 메시지"
}

템플릿은 변수 치환 방식으로 설계 (예: {{url}}, {{detectorResults}}, {{ragContext}})
```

### Command 12: API 클라이언트 (llm/api-client.js)

```
llm/api-client.js를 구현해줘.

목적: LLM API 호출을 추상화하는 클라이언트

구현 내용:
1. GLM API (z.ai) 기본 지원, Gemini도 쉽게 추가 가능한 구조
2. API 키는 config/settings.js에서 관리 (chrome.storage.sync에 저장)
3. 에러 처리: 타임아웃, rate limit, API 키 누락 등
4. 요청/응답 로깅 (디버그 모드)
5. 재시도 로직 (최대 2회, exponential backoff)

인터페이스:
- async analyze(prompt, systemPrompt): LLM 응답 반환
- setProvider(provider): 'claude' | 'openai' 전환
- setApiKey(key): API 키 설정
```

---

## 5. UI 구현

### Command 13: 경고 배너 (ui/alert-banner.js + css)

```
ui/alert-banner.js와 alert-banner.css를 구현해줘.

목적: 위험 감지 시 페이지 상단에 경고 배너를 삽입

디자인:
- 위험 수준별 색상:
  - danger (70~100): 빨간색 배경, 흰색 텍스트, ⚠️ 아이콘
  - warning (40~69): 노란색 배경, 검정 텍스트, ⚡ 아이콘
  - safe (0~39): 배너 미표시 (또는 작은 녹색 표시)
- 닫기(X) 버튼 포함
- "자세히 보기" 버튼 → detail-panel 표시
- 애니메이션: 상단에서 슬라이드 다운
- 페이지 기존 콘텐츠 밀어내기 (position: fixed가 아닌 push-down 방식)
- Shadow DOM 사용하여 기존 페이지 CSS와 충돌 방지

배너 텍스트 예시:
- danger: "⚠️ 경고: 이 사이트는 피싱 사이트로 의심됩니다! [자세히 보기]"
- warning: "⚡ 주의: 이 사이트에서 의심스러운 요소가 감지되었습니다. [자세히 보기]"
```

### Command 14: 팝업 UI (popup/)

```
popup/popup.html, popup.css, popup.js를 구현해줘.

목적: 익스텐션 아이콘 클릭 시 표시되는 팝업

구성:
1. 헤더: PhishGuard 로고 + 현재 사이트 도메인 표시
2. 위험도 게이지: 원형 게이지로 0~100 점수 시각화
3. 위험 수준 라벨: "안전" / "주의" / "위험" + 색상
4. 감지 항목 리스트: 각 detector의 결과를 카드 형태로 표시
   - 모듈명, 위험도, 감지 사유
   - 접었다 펼 수 있는 아코디언 형태
5. 하단: API 설정 버튼, 피드백 링크

스타일: 깔끔한 다크 모드 기본, 너비 360px, 최대 높이 500px (스크롤)
```

---

## 6. 백그라운드 및 콘텐츠 스크립트

### Command 15: Service Worker (background/service-worker.js)

```
background/service-worker.js를 구현해줘.

목적: 탭 URL 변경 감지 → 분석 오케스트레이션 → 결과 전달

구현 내용:
1. chrome.tabs.onUpdated 리스너: URL 변경 감지
2. 분석 흐름:
   a. URL 파싱 (utils/url-parser.js)
   b. 화이트리스트 체크 (known-domains.json의 정확한 매칭)
   c. 화이트리스트가 아니면 detectors/index.js 통해 분석 실행
   d. 결과를 content script에 메시지로 전달
   e. 익스텐션 아이콘 뱃지 업데이트 (risk-badge.js)
3. 분석 결과 캐싱 (동일 도메인 재방문 시 캐시 활용)
4. chrome.runtime.onMessage 리스너: popup/content script와 통신
```

### Command 16: Content Script (content/content-script.js)

```
content/content-script.js를 구현해줘.

목적: 페이지 DOM 정보 수집 + 경고 UI 삽입

구현 내용:
1. 페이지 로드 시 DOM 정보 수집:
   - document.title
   - meta description
   - 모든 <form> 태그의 input type 분석
   - 외부 리소스 (이미지, 스크립트) URL 목록
   - 페이지 내 텍스트 중 긴급성/보상 관련 키워드 존재 여부
2. 수집 정보를 background script에 전달
3. background로부터 분석 결과 수신 시:
   - alert-banner 삽입/업데이트
   - detail-panel 데이터 설정
```

---

## 7. 유틸리티

### Command 17: 문자열 유사도 (utils/string-similarity.js)

```
utils/string-similarity.js를 구현해줘.

구현 알고리즘:
1. Levenshtein Distance: 두 문자열 간 편집 거리 계산
2. Jaro-Winkler Similarity: 0~1 사이 유사도 (문자열 시작 부분에 가중치)
3. normalizedSimilarity(a, b): 위 두 알고리즘의 가중 결합 (0~1)
4. homoglyphNormalize(str): 동형문자를 ASCII 대응 문자로 변환
5. detectTechnique(original, suspect): 어떤 타이포스쿼팅 기법인지 분류
   반환값: 'character_repetition' | 'character_substitution' | 'character_insertion'
           | 'character_deletion' | 'homoglyph' | 'tld_change' | 'hyphen_insertion'
           | 'subdomain_impersonation'
```

### Command 18: URL 파서 (utils/url-parser.js)

```
utils/url-parser.js를 구현해줘.

구현 내용:
- parseUrl(urlString): URL을 구성 요소로 분해
  반환: { protocol, hostname, port, pathname, queryParams, hash,
          domain, subdomain, tld, isIP, isLocalhost }
- extractRegistrableDomain(hostname): 등록 가능 도메인 추출 (예: sub.naver.com → naver.com)
- isKnownTLD(tld): 알려진 TLD인지 확인
- decodePunycode(hostname): 퓨니코드 디코딩
```

---

## 8. 설정 및 Manifest

### Command 19: 설정 관리 (config/settings.js)

```
config/settings.js를 구현해줘.

구현 내용:
- chrome.storage.sync를 활용한 설정 저장/불러오기
- 기본 설정값:
  {
    llmProvider: 'claude',        // 'claude' | 'openai'
    apiKey: '',                    // 사용자 입력
    enableLLM: true,               // LLM 분석 활성화 여부
    enableNotifications: true,     // 알림 활성화
    riskThreshold: {
      warning: 40,                 // warning 이상 경고 표시
      danger: 70                   // danger 이상 강한 경고
    },
    detectors: {                   // 각 모듈 활성화 토글
      typosquat: true,
      protocol: true,
      domainAge: true,
      contentAnalysis: true,
      llmAnalysis: true
    },
    whitelist: [],                 // 사용자 지정 안전 도메인
    cacheExpiry: 3600000           // 캐시 만료 시간 (1시간, ms)
  }
```

### Command 20: Manifest 파일 (manifest.json)

```
manifest.json을 Manifest V3 규격으로 작성해줘.

필요 권한:
- activeTab: 현재 탭 정보 접근
- storage: 설정 및 캐시 저장
- tabs: 탭 URL 변경 감지
- scripting: 동적 콘텐츠 스크립트 삽입

host_permissions: "<all_urls>" (모든 사이트 분석 필요)

content_scripts: content/content-script.js (모든 URL에 자동 삽입)
background: background/service-worker.js (서비스 워커)
action: popup/popup.html
icons: assets/ 폴더의 아이콘들

web_accessible_resources: ui/ 폴더의 CSS 파일들 (Shadow DOM에서 사용)
```

---

## 9. 테스트 및 마무리

### Command 21: 테스트 환경 구성

```
아래 테스트 시나리오에 대해 각각 동작을 확인할 수 있는 테스트 코드를 작성해줘.

1. 타이포스쿼팅 감지 테스트:
   - "naverr.com" → naver.com과 유사 감지, risk 90+
   - "kkakao.com" → kakao.com과 유사 감지
   - "g00gle.com" → google.com 동형문자 감지
   - "naver.com" → 정확히 일치하므로 safe

2. 프로토콜 감지 테스트:
   - "http://example.com" → HTTP 경고
   - "https://example.com" → safe

3. 통합 테스트:
   - "http://naverr.com" → 타이포스쿼팅 + HTTP → 매우 높은 위험도
   - "https://naver.com" → 모든 항목 safe
```

### Command 22: README 작성

```
README.md를 작성해줘. 아래 내용을 포함:

1. PhishGuard 소개 및 주요 기능
2. 아키텍처 다이어그램 (Mermaid)
3. 설치 및 실행 방법 (Chrome 개발자 모드 로드)
4. 감지 모듈 설명 및 각 모듈의 역할
5. LLM API 설정 방법
6. 기술 스택
7. 향후 개선 계획 (경진대회 이후 로드맵)
8. 라이선스
```

### Command 23: 팝업 LLM 설정 UX 개선

```
popup의 LLM 설정 접근성을 개선해줘.

문제점:
- 기존에는 footer의 ⚙️ 버튼만으로 설정에 접근 가능
- LLM을 설정할 수 있다는 것을 사용자가 직관적으로 인지하기 어려움

개선 내용:

1. LLM 상태 칩 (header 영역):
   - 헤더의 도메인 표시 아래에 LLM 상태 칩 버튼 추가
   - API 미설정 시: "AI 모델을 설정해주세요" (dashed border, 흐린 색상)
   - API 설정 완료 시: "[제공자 로고] GLM" 또는 "[제공자 로고] Gemini" (solid border)
   - 클릭 시 설정 패널 토글 (기존 ⚙️ 버튼과 동일 동작)

2. 커스텀 모델 피커 (설정 패널):
   - 기존 <select> 드롭다운을 로고가 포함된 카드형 선택기로 교체
   - GLM / Gemini 두 장의 카드를 나란히 배치
   - 각 카드에 해당 제공자의 SVG 로고 표시
   - 선택된 카드는 #a78bfa 보라색 테두리로 하이라이트

3. 제공자 로고 (utils/logo.js):
   - Gemini: Sparkle 형태 SVG + 그라데이션 (파랑→보라→주황)
   - GLM (Z.AI): Z자 형태 흰색 로고 SVG
   - JSX 제거, 순수 SVG 문자열 상수로 변환
```

---

## 부록: 개발 순서 권장

| 순서 | 명령          | 설명                                          | 우선순위 |
| ---- | ------------- | --------------------------------------------- | -------- |
| 1    | Command 1     | 프로젝트 구조 생성                            | 🔴 필수  |
| 2    | Command 17~18 | 유틸리티 (string-similarity, url-parser)      | 🔴 필수  |
| 3    | Command 8~9   | RAG 데이터 (known-domains, phishing-patterns) | 🔴 필수  |
| 4    | Command 3     | 타이포스쿼팅 감지                             | 🔴 필수  |
| 5    | Command 4     | 프로토콜 감지                                 | 🔴 필수  |
| 6    | Command 2     | 감지 매니저                                   | 🔴 필수  |
| 7    | Command 13    | 경고 배너 UI                                  | 🔴 필수  |
| 8    | Command 15~16 | 서비스 워커 + 콘텐츠 스크립트                 | 🔴 필수  |
| 9    | Command 20    | manifest.json                                 | 🔴 필수  |
| 10   | Command 19    | 설정 관리                                     | 🟡 권장  |
| 11   | Command 14    | 팝업 UI                                       | 🟡 권장  |
| 12   | Command 6     | 콘텐츠 분석                                   | 🟡 권장  |
| 13   | Command 10~12 | RAG 엔진 + LLM 연동                           | 🟡 권장  |
| 14   | Command 5     | 도메인 연령 감지                              | 🟢 선택  |
| 15   | Command 7     | LLM 종합 분석                                 | 🟢 선택  |
| 16   | Command 21    | 테스트                                        | 🟡 권장  |
| 17   | Command 22    | README                                        | 🟡 권장  |
| 18   | Command 23    | 팝업 LLM 설정 UX 개선                         | 🟡 권장  |

> 💡 **MVP 전략**: 순서 1~9까지 완성하면 **LLM 없이도 동작하는 기본 피싱 감지 익스텐션**이 완성됩니다. 이후 10~17을 추가하여 LLM 분석 및 UX를 강화하세요.

---

## 네이밍 정리

| 항목                    | 이름                      | 비고                          |
| ----------------------- | ------------------------- | ----------------------------- |
| **프로젝트명**          | PhishGuard                | Phishing + Guard              |
| **패키지명**            | phishguard                | npm/디렉토리명                |
| **익스텐션 표시명**     | PhishGuard - AI 피싱 감지 | Chrome 웹스토어 표시용        |
| **감지 매니저**         | DetectorManager           | detectors/index.js            |
| **타이포스쿼팅 감지기** | TyposquatDetector         | detectors/domain-typosquat.js |
| **프로토콜 감지기**     | ProtocolDetector          | detectors/protocol-check.js   |
| **도메인 연령 감지기**  | DomainAgeDetector         | detectors/domain-age.js       |
| **콘텐츠 분석기**       | ContentAnalyzer           | detectors/content-analysis.js |
| **LLM 분석기**          | LLMAnalyzer               | detectors/llm-analysis.js     |
| **RAG 엔진**            | RAGEngine                 | rag/rag-engine.js             |
| **경고 배너**           | AlertBanner               | ui/alert-banner.js            |
| **위험도 뱃지**         | RiskBadge                 | ui/risk-badge.js              |
