/**
 * lib/sanitize.ts — Input sanitization and validation utilities.
 *
 * Provides defense-in-depth sanitization for all user inputs:
 * - String length limits
 * - Character whitelist enforcement
 * - SQL injection prevention
 * - XSS prevention
 * - Path traversal prevention
 * - Command injection prevention
 */

// ─── String sanitization ──────────────────────────────────────────────────────

/**
 * Sanitize a generic string input by:
 * - Trimming whitespace
 * - Enforcing max length
 * - Removing null bytes and control characters
 */
export function sanitizeString(input: string, maxLength = 1000): string {
  return input
    .trim()
    .slice(0, maxLength)
    .replace(/\0/g, '')                    // null bytes
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')  // control chars except \t \n \r
}

/**
 * Sanitize a label/name field (alphanumeric + common punctuation only).
 * Used for target labels, notes, etc.
 *
 * Single and double quotes are intentionally excluded: labels have no
 * legitimate need for unescaped quotes and they are a latent SQL/template
 * injection risk if labels are ever interpolated into a query or template.
 */
export function sanitizeLabel(input: string, maxLength = 200): string {
  return sanitizeString(input, maxLength)
    .replace(/[^\w\s\-_.,:;!?()\[\]{}@#$%&+=]/g, '')  // quotes excluded — see above
}

/**
 * Sanitize a notes/description field (more permissive than label).
 */
export function sanitizeNotes(input: string, maxLength = 2000): string {
  return sanitizeString(input, maxLength)
}

/**
 * Sanitize a query parameter (strict - only allow safe characters).
 */
export function sanitizeQueryParam(input: string, maxLength = 500): string {
  return sanitizeString(input, maxLength)
    .replace(/[<>'"`;\\]/g, '')  // remove potential injection chars
}

// ─── Number sanitization ──────────────────────────────────────────────────────

/**
 * Parse and sanitize a numeric input with bounds checking.
 * Returns the default value if parsing fails or value is out of bounds.
 */
export function sanitizeNumber(
  input: string | number | null | undefined,
  defaultValue: number,
  min?: number,
  max?: number,
): number {
  if (input === null || input === undefined) return defaultValue
  
  const num = typeof input === 'number' ? input : Number(input)
  
  if (!Number.isFinite(num)) return defaultValue
  if (min !== undefined && num < min) return defaultValue
  if (max !== undefined && num > max) return defaultValue
  
  return num
}

/**
 * Sanitize an integer input (no decimals allowed).
 */
export function sanitizeInteger(
  input: string | number | null | undefined,
  defaultValue: number,
  min?: number,
  max?: number,
): number {
  const num = sanitizeNumber(input, defaultValue, min, max)
  return Math.floor(num)
}

// ─── Array sanitization ───────────────────────────────────────────────────────

/**
 * Sanitize an array of strings with per-item validation.
 */
export function sanitizeStringArray(
  input: unknown,
  maxItems = 100,
  maxItemLength = 500,
): string[] {
  if (!Array.isArray(input)) return []
  
  return input
    .filter(item => typeof item === 'string')
    .slice(0, maxItems)
    .map(item => sanitizeString(item, maxItemLength))
    .filter(item => item.length > 0)
}

// ─── SQL injection prevention ─────────────────────────────────────────────────

/**
 * Detect potential SQL injection patterns.
 * This is a defense-in-depth measure — parameterized queries are the primary defense.
 * Only applied to free-text fields (labels, notes), NOT to query strings.
 */
export function containsSQLInjection(input: string): boolean {
  const sqlPatterns = [
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|DECLARE)\b)/i,
    /(\/\*|\*\/|xp_|sp_)/i,           // comment delimiters, stored-proc prefixes
    /('(\s)*(OR|AND)(\s)*')/i,         // classic ' OR '1'='1 pattern
  ]

  return sqlPatterns.some(pattern => pattern.test(input))
}

/**
 * Detect SQL injection in query strings (IPs, domains, ASNs).
 * Much stricter subset — only patterns that cannot appear in any valid query.
 */
export function containsSQLInjectionInQuery(input: string): boolean {
  const sqlPatterns = [
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|DECLARE)\b)/i,
    /(\/\*|\*\/)/i,  // comment delimiters only — ; and -- can appear in labels
  ]

  return sqlPatterns.some(pattern => pattern.test(input))
}

/**
 * Sanitize input for use in SQL LIKE patterns (escape wildcards).
 */
export function sanitizeSQLLike(input: string): string {
  return input
    .replace(/\\/g, '\\\\')
    .replace(/%/g, '\\%')
    .replace(/_/g, '\\_')
}

// ─── XSS prevention ───────────────────────────────────────────────────────────

/**
 * Escape HTML special characters to prevent XSS.
 * Note: React already escapes by default, but this is useful for raw HTML contexts.
 */
export function escapeHTML(input: string): string {
  const map: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#x27;',
    '/': '&#x2F;',
  }
  
  return input.replace(/[&<>"'/]/g, char => map[char] || char)
}

/**
 * Detect potential XSS patterns.
 */
export function containsXSS(input: string): boolean {
  const xssPatterns = [
    /<script[^>]*>.*?<\/script>/gi,
    /<iframe[^>]*>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,  // event handlers like onclick=
    /<embed[^>]*>/gi,
    /<object[^>]*>/gi,
  ]
  
  return xssPatterns.some(pattern => pattern.test(input))
}

// ─── Path traversal prevention ────────────────────────────────────────────────

/**
 * Detect path traversal attempts.
 */
export function containsPathTraversal(input: string): boolean {
  const pathPatterns = [
    /\.\./,
    /\.\.\\/, 
    /%2e%2e/i,
    /%252e%252e/i,
    /\.\.\//,
  ]
  
  return pathPatterns.some(pattern => pattern.test(input))
}

// ─── Command injection prevention ─────────────────────────────────────────────

/**
 * Detect command injection patterns in free-text fields (labels, notes).
 * Not used for query strings — IPs/domains/ASNs have their own validator.
 */
export function containsCommandInjection(input: string): boolean {
  const cmdPatterns = [
    /`.*`/,    // backtick command substitution
    /\$\(/,    // $(command)
    /\|\|/,    // ||
    /&&/,      // &&
  ]

  return cmdPatterns.some(pattern => pattern.test(input))
}

// ─── Comprehensive validation ─────────────────────────────────────────────────

/**
 * Validate a query string (IP, domain, ASN) for injection patterns.
 * Deliberately narrow — only rejects patterns that cannot appear in any
 * legitimate IP, domain, or ASN string. Does NOT check for command
 * injection characters like ()[]{}; which are valid in some contexts.
 */
export function validateQueryInput(input: string): { valid: boolean; reason?: string } {
  if (containsSQLInjectionInQuery(input)) {
    return { valid: false, reason: 'potential SQL injection detected' }
  }

  if (containsXSS(input)) {
    return { valid: false, reason: 'potential XSS detected' }
  }

  // Path traversal: only flag actual traversal sequences, not single dots
  if (/(\.\.[/\\]|%2e%2e|%252e%252e)/i.test(input)) {
    return { valid: false, reason: 'path traversal detected' }
  }

  return { valid: true }
}

/**
 * Validate a free-text field (label, notes, admin input).
 * Applies the full set of injection checks including SQL and command injection.
 */
export function validateInput(input: string): { valid: boolean; reason?: string } {
  if (containsSQLInjection(input)) {
    return { valid: false, reason: 'potential SQL injection detected' }
  }

  if (containsXSS(input)) {
    return { valid: false, reason: 'potential XSS detected' }
  }

  if (containsPathTraversal(input)) {
    return { valid: false, reason: 'path traversal detected' }
  }

  if (containsCommandInjection(input)) {
    return { valid: false, reason: 'command injection detected' }
  }

  return { valid: true }
}

// ─── JSON sanitization ────────────────────────────────────────────────────────

/**
 * Safely parse JSON with size limits and validation.
 */
export function sanitizeJSON<T>(
  input: string,
  maxSize = 1024 * 100, // 100KB default
  validator?: (data: unknown) => data is T,
): { success: true; data: T } | { success: false; error: string } {
  if (input.length > maxSize) {
    return { success: false, error: 'JSON input exceeds size limit' }
  }
  
  let parsed: unknown
  try {
    parsed = JSON.parse(input)
  } catch (err) {
    return { success: false, error: `invalid JSON: ${err}` }
  }
  
  if (validator && !validator(parsed)) {
    return { success: false, error: 'JSON validation failed' }
  }
  
  return { success: true, data: parsed as T }
}

// ─── URL sanitization ─────────────────────────────────────────────────────────

/**
 * Validate and sanitize a URL.
 */
export function sanitizeURL(input: string, allowedProtocols = ['http:', 'https:']): string | null {
  try {
    const url = new URL(input)
    
    if (!allowedProtocols.includes(url.protocol)) {
      return null
    }
    
    // Remove credentials if present
    url.username = ''
    url.password = ''
    
    return url.toString()
  } catch (_err) {
    // URL constructor throws TypeError on invalid input — expected, not a bug
    return null
  }
}

// ─── Email sanitization ───────────────────────────────────────────────────────

/**
 * Basic email validation and sanitization.
 */
export function sanitizeEmail(input: string): string | null {
  const sanitized = sanitizeString(input, 254).toLowerCase()
  
  // Basic RFC 5322 pattern (simplified)
  const emailPattern = /^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/
  
  if (!emailPattern.test(sanitized)) {
    return null
  }
  
  return sanitized
}
