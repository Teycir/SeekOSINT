/**
 * test/sanitize.test.ts — Input sanitization test suite.
 */
import { describe, it, expect } from 'vitest'
import {
  sanitizeString,
  sanitizeLabel,
  sanitizeNotes,
  sanitizeQueryParam,
  sanitizeNumber,
  sanitizeInteger,
  sanitizeStringArray,
  containsSQLInjection,
  sanitizeSQLLike,
  escapeHTML,
  containsXSS,
  containsPathTraversal,
  containsCommandInjection,
  validateInput,
  sanitizeJSON,
  sanitizeURL,
  sanitizeEmail,
} from '../lib/sanitize'

describe('sanitizeString', () => {
  it('trims whitespace', () => {
    expect(sanitizeString('  hello  ')).toBe('hello')
  })

  it('enforces max length', () => {
    expect(sanitizeString('a'.repeat(2000), 100)).toHaveLength(100)
  })

  it('removes null bytes', () => {
    expect(sanitizeString('hello\0world')).toBe('helloworld')
  })

  it('removes control characters', () => {
    expect(sanitizeString('hello\x01\x02world')).toBe('helloworld')
  })

  it('preserves tabs, newlines, carriage returns', () => {
    expect(sanitizeString('hello\t\n\rworld')).toBe('hello\t\n\rworld')
  })
})

describe('sanitizeLabel', () => {
  it('allows alphanumeric and common punctuation', () => {
    expect(sanitizeLabel('Test-Label_123')).toBe('Test-Label_123')
  })

  it('removes special characters', () => {
    expect(sanitizeLabel('Test<script>alert(1)</script>')).toBe('Testscriptalert(1)script')
  })

  it('enforces max length', () => {
    expect(sanitizeLabel('a'.repeat(500), 50)).toHaveLength(50)
  })
})

describe('sanitizeQueryParam', () => {
  it('removes injection characters', () => {
    expect(sanitizeQueryParam('test<script>')).toBe('testscript')
    expect(sanitizeQueryParam('test"OR"1"="1')).toBe('testOR1=1')
  })

  it('preserves safe characters', () => {
    expect(sanitizeQueryParam('example.com')).toBe('example.com')
    expect(sanitizeQueryParam('192.168.1.1')).toBe('192.168.1.1')
  })
})

describe('sanitizeNumber', () => {
  it('parses valid numbers', () => {
    expect(sanitizeNumber('42', 0)).toBe(42)
    expect(sanitizeNumber(42, 0)).toBe(42)
  })

  it('returns default for invalid input', () => {
    expect(sanitizeNumber('abc', 10)).toBe(10)
    expect(sanitizeNumber(null, 10)).toBe(10)
    expect(sanitizeNumber(undefined, 10)).toBe(10)
  })

  it('enforces min/max bounds', () => {
    expect(sanitizeNumber('5', 10, 0, 3)).toBe(10)
    expect(sanitizeNumber('-5', 10, 0, 100)).toBe(10)
    expect(sanitizeNumber('50', 10, 0, 30)).toBe(10)
  })

  it('rejects Infinity and NaN', () => {
    expect(sanitizeNumber(Infinity, 10)).toBe(10)
    expect(sanitizeNumber(NaN, 10)).toBe(10)
  })
})

describe('sanitizeInteger', () => {
  it('floors decimal values', () => {
    expect(sanitizeInteger('42.7', 0)).toBe(42)
    expect(sanitizeInteger(42.9, 0)).toBe(42)
  })
})

describe('sanitizeStringArray', () => {
  it('filters non-strings', () => {
    expect(sanitizeStringArray([1, 'test', null, 'valid'])).toEqual(['test', 'valid'])
  })

  it('enforces max items', () => {
    const arr = Array(200).fill('test')
    expect(sanitizeStringArray(arr, 50)).toHaveLength(50)
  })

  it('sanitizes each item', () => {
    const result = sanitizeStringArray(['  test  ', 'hello\0world'])
    expect(result).toEqual(['test', 'helloworld'])
  })

  it('returns empty array for non-array input', () => {
    expect(sanitizeStringArray('not an array')).toEqual([])
    expect(sanitizeStringArray(null)).toEqual([])
  })
})

describe('containsSQLInjection', () => {
  it('detects SQL keywords', () => {
    expect(containsSQLInjection('SELECT * FROM users')).toBe(true)
    expect(containsSQLInjection('DROP TABLE users')).toBe(true)
    expect(containsSQLInjection('UNION SELECT password')).toBe(true)
  })

  it('detects SQL comment patterns', () => {
    expect(containsSQLInjection('test--comment')).toBe(true)
    expect(containsSQLInjection('test/*comment*/')).toBe(true)
  })

  it('detects OR/AND injection patterns', () => {
    expect(containsSQLInjection("' OR '1'='1")).toBe(true)
    expect(containsSQLInjection("' AND '1'='1")).toBe(true)
  })

  it('allows safe input', () => {
    expect(containsSQLInjection('example.com')).toBe(false)
    expect(containsSQLInjection('192.168.1.1')).toBe(false)
  })
})

describe('sanitizeSQLLike', () => {
  it('escapes wildcards', () => {
    expect(sanitizeSQLLike('test%value')).toBe('test\\%value')
    expect(sanitizeSQLLike('test_value')).toBe('test\\_value')
  })

  it('escapes backslashes', () => {
    expect(sanitizeSQLLike('test\\value')).toBe('test\\\\value')
  })
})

describe('escapeHTML', () => {
  it('escapes HTML special characters', () => {
    expect(escapeHTML('<script>alert("XSS")</script>'))
      .toBe('&lt;script&gt;alert(&quot;XSS&quot;)&lt;&#x2F;script&gt;')
  })

  it('escapes ampersands', () => {
    expect(escapeHTML('Tom & Jerry')).toBe('Tom &amp; Jerry')
  })
})

describe('containsXSS', () => {
  it('detects script tags', () => {
    expect(containsXSS('<script>alert(1)</script>')).toBe(true)
  })

  it('detects iframe tags', () => {
    expect(containsXSS('<iframe src="evil.com"></iframe>')).toBe(true)
  })

  it('detects javascript: protocol', () => {
    expect(containsXSS('javascript:alert(1)')).toBe(true)
  })

  it('detects event handlers', () => {
    expect(containsXSS('<img onerror="alert(1)">')).toBe(true)
    expect(containsXSS('<div onclick="evil()">')).toBe(true)
  })

  it('allows safe input', () => {
    expect(containsXSS('This is a normal string')).toBe(false)
  })
})

describe('containsPathTraversal', () => {
  it('detects dot-dot-slash patterns', () => {
    expect(containsPathTraversal('../etc/passwd')).toBe(true)
    expect(containsPathTraversal('..\\windows\\system32')).toBe(true)
  })

  it('detects URL-encoded traversal', () => {
    expect(containsPathTraversal('%2e%2e/etc/passwd')).toBe(true)
    expect(containsPathTraversal('%252e%252e/etc/passwd')).toBe(true)
  })

  it('allows safe paths', () => {
    expect(containsPathTraversal('normal/path/file.txt')).toBe(false)
  })
})

describe('containsCommandInjection', () => {
  it('detects shell metacharacters', () => {
    expect(containsCommandInjection('test; rm -rf /')).toBe(true)
    expect(containsCommandInjection('test | cat /etc/passwd')).toBe(true)
    expect(containsCommandInjection('test && evil')).toBe(true)
  })

  it('detects command substitution', () => {
    expect(containsCommandInjection('test$(whoami)')).toBe(true)
    expect(containsCommandInjection('test`whoami`')).toBe(true)
  })

  it('allows safe input', () => {
    expect(containsCommandInjection('example.com')).toBe(false)
  })
})

describe('validateInput', () => {
  it('rejects SQL injection', () => {
    const result = validateInput('SELECT * FROM users')
    expect(result.valid).toBe(false)
    expect(result.reason).toContain('SQL injection')
  })

  it('rejects XSS', () => {
    const result = validateInput('<script>alert(1)</script>')
    expect(result.valid).toBe(false)
    expect(result.reason).toContain('XSS')
  })

  it('rejects path traversal', () => {
    const result = validateInput('../etc/passwd')
    expect(result.valid).toBe(false)
    expect(result.reason).toContain('path traversal')
  })

  it('rejects command injection', () => {
    // Note: semicolon is caught by SQL injection check first
    const result = validateInput('test; rm -rf /')
    expect(result.valid).toBe(false)
    expect(result.reason).toBeDefined()
  })

  it('accepts safe input', () => {
    expect(validateInput('example.com').valid).toBe(true)
    expect(validateInput('192.168.1.1').valid).toBe(true)
    expect(validateInput('AS13335').valid).toBe(true)
  })
})

describe('sanitizeJSON', () => {
  it('parses valid JSON', () => {
    const result = sanitizeJSON('{"key":"value"}')
    expect(result.success).toBe(true)
    if (result.success) {
      expect(result.data).toEqual({ key: 'value' })
    }
  })

  it('rejects oversized input', () => {
    const large = JSON.stringify({ data: 'x'.repeat(200000) })
    const result = sanitizeJSON(large, 1000)
    expect(result.success).toBe(false)
    if (!result.success) {
      expect(result.error).toContain('size limit')
    }
  })

  it('rejects invalid JSON', () => {
    const result = sanitizeJSON('not json')
    expect(result.success).toBe(false)
    if (!result.success) {
      expect(result.error).toContain('invalid JSON')
    }
  })

  it('validates with custom validator', () => {
    const validator = (data: unknown): data is { id: number } =>
      typeof data === 'object' && data !== null && 'id' in data
    
    const valid = sanitizeJSON('{"id":123}', 1000, validator)
    expect(valid.success).toBe(true)
    
    const invalid = sanitizeJSON('{"name":"test"}', 1000, validator)
    expect(invalid.success).toBe(false)
  })
})

describe('sanitizeURL', () => {
  it('accepts valid HTTP/HTTPS URLs', () => {
    expect(sanitizeURL('https://example.com')).toBe('https://example.com/')
    expect(sanitizeURL('http://example.com')).toBe('http://example.com/')
  })

  it('rejects non-HTTP protocols', () => {
    expect(sanitizeURL('javascript:alert(1)')).toBeNull()
    expect(sanitizeURL('file:///etc/passwd')).toBeNull()
    expect(sanitizeURL('ftp://example.com')).toBeNull()
  })

  it('removes credentials', () => {
    const result = sanitizeURL('https://user:pass@example.com')
    expect(result).toBe('https://example.com/')
  })

  it('rejects invalid URLs', () => {
    expect(sanitizeURL('not a url')).toBeNull()
  })
})

describe('sanitizeEmail', () => {
  it('accepts valid emails', () => {
    expect(sanitizeEmail('test@example.com')).toBe('test@example.com')
    expect(sanitizeEmail('user.name+tag@example.co.uk')).toBe('user.name+tag@example.co.uk')
  })

  it('rejects invalid emails', () => {
    expect(sanitizeEmail('not-an-email')).toBeNull()
    expect(sanitizeEmail('@example.com')).toBeNull()
    expect(sanitizeEmail('test@')).toBeNull()
  })

  it('normalizes to lowercase', () => {
    expect(sanitizeEmail('Test@Example.COM')).toBe('test@example.com')
  })

  it('enforces length limit', () => {
    const long = 'a'.repeat(300) + '@example.com'
    expect(sanitizeEmail(long)).toBeNull()
  })
})
