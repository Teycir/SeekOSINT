/**
 * test/logger.test.ts — structured log output shape
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { log } from '../lib/logger'

describe('log', () => {
  let errorSpy: ReturnType<typeof vi.spyOn>
  let warnSpy:  ReturnType<typeof vi.spyOn>
  let logSpy:   ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    warnSpy  = vi.spyOn(console, 'warn').mockImplementation(() => {})
    logSpy   = vi.spyOn(console, 'log').mockImplementation(() => {})
  })

  afterEach(() => vi.restoreAllMocks())

  function lastCallArg(spy: ReturnType<typeof vi.spyOn>) {
    const call = spy.mock.calls[spy.mock.calls.length - 1]
    return JSON.parse(call![0] as string)
  }

  it('log.error emits to console.error with level=error', () => {
    log.error('internetdb', '1.2.3.4', 'HTTP 429')
    expect(errorSpy).toHaveBeenCalledOnce()
    const entry = lastCallArg(errorSpy)
    expect(entry.level).toBe('error')
    expect(entry.source).toBe('internetdb')
    expect(entry.query).toBe('1.2.3.4')
    expect(entry.message).toBe('HTTP 429')
    expect(entry.ts).toBeTypeOf('number')
  })

  it('log.warn emits to console.warn with level=warn', () => {
    log.warn('keyring', 'ghw', 'all keys exhausted')
    expect(warnSpy).toHaveBeenCalledOnce()
    const entry = lastCallArg(warnSpy)
    expect(entry.level).toBe('warn')
  })

  it('log.info emits to console.log with level=info', () => {
    log.info('lookup', 'example.com', 'completed', { durationMs: 312 })
    expect(logSpy).toHaveBeenCalledOnce()
    const entry = lastCallArg(logSpy)
    expect(entry.level).toBe('info')
    expect(entry.durationMs).toBe(312)
  })

  it('merges extra fields into the log entry', () => {
    log.error('src', 'q', 'msg', { retrying: true, attempt: 2 })
    const entry = lastCallArg(errorSpy)
    expect(entry.retrying).toBe(true)
    expect(entry.attempt).toBe(2)
  })

  it('emits valid JSON', () => {
    log.info('src', 'q', 'test')
    const raw = logSpy.mock.calls[0]![0] as string
    expect(() => JSON.parse(raw)).not.toThrow()
  })
})
