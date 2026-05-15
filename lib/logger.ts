/**
 * Structured error logger — writes JSON-formatted entries to console.error
 * so they appear correctly in Cloudflare Workers tail logs.
 *
 * Usage:
 *   log.error('internetdb', '1.2.3.4', 'HTTP 429', { retrying: true })
 *   log.warn('keyring', 'ghw', 'all keys exhausted')
 *   log.info('lookup', '1.2.3.4', 'completed', { durationMs: 312 })
 */

type LogLevel = 'info' | 'warn' | 'error'

interface LogEntry {
  level: LogLevel
  source: string
  query: string
  message: string
  ts: number
  [key: string]: unknown
}

function emit(
  level: LogLevel,
  source: string,
  query: string,
  message: string,
  extra?: Record<string, unknown>,
): void {
  const entry: LogEntry = {
    level,
    source,
    query,
    message,
    ts: Date.now(),
    ...extra,
  }
  const line = JSON.stringify(entry)
  if (level === 'error') {
    console.error(line)
  } else if (level === 'warn') {
    console.warn(line)
  } else {
    console.log(line)
  }
}

export const log = {
  info(source: string, query: string, message: string, extra?: Record<string, unknown>): void {
    emit('info', source, query, message, extra)
  },
  warn(source: string, query: string, message: string, extra?: Record<string, unknown>): void {
    emit('warn', source, query, message, extra)
  },
  error(source: string, query: string, message: string, extra?: Record<string, unknown>): void {
    emit('error', source, query, message, extra)
  },
}
