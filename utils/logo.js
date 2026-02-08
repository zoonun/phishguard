/**
 * PhishGuard - Provider Logo SVGs
 * 각 LLM 제공자의 로고 SVG 문자열
 */

// Gemini 로고 SVG (Sparkle 형태 + 그라데이션)
const GeminiLogoSVG = `<svg viewBox="0 0 28 28" fill="none" aria-hidden="true">
  <defs>
    <linearGradient id="gemini-gradient" x1="0" y1="0" x2="28" y2="28" gradientUnits="userSpaceOnUse">
      <stop stop-color="#1BA1E3"/>
      <stop offset="0.3" stop-color="#5489D6"/>
      <stop offset="0.6" stop-color="#9B72CB"/>
      <stop offset="0.9" stop-color="#D96570"/>
      <stop offset="1" stop-color="#F49C46"/>
    </linearGradient>
  </defs>
  <path d="M14 0C14 7.732 7.732 14 0 14c7.732 0 14 6.268 14 14 0-7.732 6.268-14 14-14-7.732 0-14-6.268-14-14z" fill="url(#gemini-gradient)"/>
</svg>`;

// Z.AI (Zhipu) 로고 SVG
const ZhipuLogoSVG = `<svg viewBox="0 0 30 30" fill="none" aria-hidden="true">
  <path d="M24.51,28.51H5.49c-2.21,0-4-1.79-4-4V5.49c0-2.21,1.79-4,4-4h19.03c2.21,0,4,1.79,4,4v19.03C28.51,26.72,26.72,28.51,24.51,28.51z" fill="#1A1A2E"/>
  <path d="M15.47,7.1l-1.3,1.85c-0.2,0.29-0.54,0.47-0.9,0.47h-7.1V7.09C6.16,7.1,15.47,7.1,15.47,7.1z" fill="white"/>
  <polygon points="24.3,7.1 13.14,22.91 5.7,22.91 16.86,7.1" fill="white"/>
  <path d="M14.53,22.91l1.31-1.86c0.2-0.29,0.54-0.47,0.9-0.47h7.09v2.33H14.53z" fill="white"/>
</svg>`;

export { GeminiLogoSVG, ZhipuLogoSVG };
