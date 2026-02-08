/**
 * PhishGuard 디버그 로거
 */

const LOG_LEVELS = {
  DEBUG: 0,
  INFO: 1,
  WARN: 2,
  ERROR: 3,
  NONE: 4
};

let currentLevel = LOG_LEVELS.DEBUG;

const Logger = {
  setLevel(level) {
    currentLevel = LOG_LEVELS[level] ?? LOG_LEVELS.DEBUG;
  },

  debug(...args) {
    if (currentLevel <= LOG_LEVELS.DEBUG) {
      console.log('[PhishGuard:DEBUG]', ...args);
    }
  },

  info(...args) {
    if (currentLevel <= LOG_LEVELS.INFO) {
      console.log('[PhishGuard:INFO]', ...args);
    }
  },

  warn(...args) {
    if (currentLevel <= LOG_LEVELS.WARN) {
      console.warn('[PhishGuard:WARN]', ...args);
    }
  },

  error(...args) {
    if (currentLevel <= LOG_LEVELS.ERROR) {
      console.error('[PhishGuard:ERROR]', ...args);
    }
  }
};

export default Logger;
