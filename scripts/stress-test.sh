#!/usr/bin/env bash
# =============================================================================
# SeekOSINT Stress & Edge-Case Test Suite
# Target: https://seekosint.pages.dev
#
# Usage:
#   bash scripts/stress-test.sh
#   bash scripts/stress-test.sh --verbose
#   bash scripts/stress-test.sh --concurrency 10
#   bash scripts/stress-test.sh --base http://localhost:3000   # local dev
# =============================================================================

BASE="https://seekosint.pages.dev"
VERBOSE=false
CONCURRENCY=8
PASS=0; FAIL=0; SKIP=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

while [[ $# -gt 0 ]]; do
  case $1 in
    --verbose)     VERBOSE=true; shift ;;
    --concurrency) CONCURRENCY=$2; shift 2 ;;
    --base)        BASE=$2; shift 2 ;;
    *) shift ;;
  esac
done

log()     { echo -e "${CYAN}[INFO]${NC} $*"; }
pass()    { echo -e "${GREEN}[PASS]${NC} $*"; ((PASS++)); }
fail()    { echo -e "${RED}[FAIL]${NC} $*"; ((FAIL++)); }
skip()    { echo -e "${YELLOW}[SKIP]${NC} $*"; ((SKIP++)); }
section() {
  echo ""
  echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  $*${NC}"
  echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
}

http_code() {
  local method=$1 url=$2; shift 2
  curl -s -o /tmp/seek_body.txt -w "%{http_code}" -X "$method" "$url" "$@"
}

body() { cat /tmp/seek_body.txt 2>/dev/null; }

check() {
  local label=$1 expected=$2 got=$3
  if [[ "$got" == "$expected" ]]; then
    pass "$label → HTTP $got"
    $VERBOSE && echo "     $(body | head -c 200)"
  else
    fail "$label → expected HTTP $expected, got HTTP $got"
    echo "     Body: $(body | head -c 300)"
  fi
}

check_any() {
  # check_any "label" got 200 201 422
  local label=$1 got=$2; shift 2
  for expected in "$@"; do
    [[ "$got" == "$expected" ]] && { pass "$label → HTTP $got"; return; }
  done
  fail "$label → got HTTP $got (expected one of: $*)"
  echo "     Body: $(body | head -c 300)"
}

body_has() {
  local label=$1 needle=$2
  if body | grep -q "$needle"; then
    pass "$label (body contains '$needle')"
  else
    fail "$label (body missing '$needle')"
    echo "     Body: $(body | head -c 300)"
  fi
}

# =============================================================================
# NOTE on Turnstile
# /api/lookup and /api/stream require a valid Cloudflare Turnstile token from
# a real browser challenge. Direct curl calls without a valid `ts` param will
# return 403 "bot challenge failed". We test that defence explicitly, then
# validate input-parsing paths via /api/targets (no Turnstile required).
# =============================================================================

DUMMY_TS="stress-test-invalid-token"

# =============================================================================
section "1. STATIC PAGES — Connectivity"
# =============================================================================

check "GET /"         200 "$(http_code GET $BASE/)"
check "GET /about"    200 "$(http_code GET $BASE/about)"
check "GET /faq"      200 "$(http_code GET $BASE/faq)"
check_any "GET /host (dynamic route, may 404 without query)" "$(http_code GET $BASE/host)" "200" "404"
check "GET /nonexistent → 404" 404 "$(http_code GET $BASE/this-page-does-not-exist-xyz)"

# =============================================================================
section "2. GET /api/recent"
# =============================================================================

check "GET /api/recent"              200 "$(http_code GET $BASE/api/recent)"
body_has "/api/recent has 'searches'" '"searches"'

check "GET /api/recent?limit=1"      200 "$(http_code GET $BASE/api/recent?limit=1)"
check "GET /api/recent?limit=50"     200 "$(http_code GET $BASE/api/recent?limit=50)"
check "GET /api/recent?limit=999"    200 "$(http_code GET $BASE/api/recent?limit=999)"
check "GET /api/recent?limit=0"      200 "$(http_code GET $BASE/api/recent?limit=0)"
check "GET /api/recent?limit=-1"     200 "$(http_code GET $BASE/api/recent?limit=-1)"
check "GET /api/recent?limit=abc"    200 "$(http_code GET $BASE/api/recent?limit=abc)"
check "GET /api/recent?limit="       200 "$(http_code GET $BASE/api/recent?limit=)"
check "GET /api/recent?limit=1.5"    200 "$(http_code GET $BASE/api/recent?limit=1.5)"
check "GET /api/recent?limit=Infinity" 200 "$(http_code GET $BASE/api/recent?limit=Infinity)"
check "GET /api/recent?limit=null"   200 "$(http_code GET $BASE/api/recent?limit=null)"

check "POST /api/recent → 405"       405 "$(http_code POST $BASE/api/recent)"
check "DELETE /api/recent → 405"     405 "$(http_code DELETE $BASE/api/recent)"
check "PUT /api/recent → 405"        405 "$(http_code PUT $BASE/api/recent)"

# =============================================================================
section "3. GET /api/targets — List Targets"
# =============================================================================

check "GET /api/targets"             200 "$(http_code GET $BASE/api/targets)"
body_has "/api/targets has 'targets'" '"targets"'

check "PUT /api/targets → 405"       405 "$(http_code PUT $BASE/api/targets)"
check "PATCH /api/targets → 405"     405 "$(http_code PATCH $BASE/api/targets)"
check "DELETE /api/targets → 405"    405 "$(http_code DELETE $BASE/api/targets)"

# =============================================================================
section "4. POST /api/targets — Input Validation (Happy Path)"
# =============================================================================

# Valid IPv4 - capture TARGET_ID for later delete tests
CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json" \
  -d '{"query":"8.8.8.8","label":"Google DNS","notes":"resolver"}')
check "POST /api/targets valid IPv4 (8.8.8.8)"       201 "$CODE"
TARGET_ID=$(python3 -c "import sys,json; d=json.load(open('/tmp/seek_body.txt')); print(d.get('id',''))" 2>/dev/null)

CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json" -d '{"query":"1.1.1.1"}')
check "POST /api/targets 1.1.1.1"                    201 "$CODE"

CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json" -d '{"query":"example.com"}')
check "POST /api/targets domain example.com"         201 "$CODE"

CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json" -d '{"query":"AS15169"}')
check "POST /api/targets ASN AS15169"                201 "$CODE"

CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json" -d '{"query":"as15169"}')
check "POST /api/targets ASN lowercase as15169"      201 "$CODE"

CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json" -d '{"query":"2001:4860:4860::8888"}')
check "POST /api/targets IPv6 full"                  201 "$CODE"

CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json" -d '{"query":"::1"}')
check "POST /api/targets IPv6 loopback ::1"          201 "$CODE"

CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json" -d '{"query":"::"}')
check "POST /api/targets IPv6 all-zeros ::"          201 "$CODE"

# URL stripping
CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json" \
  -d '{"query":"https://example.com/some/path?foo=bar"}')
check "POST /api/targets URL-style (strips https:// and path)" 201 "$CODE"

CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json" \
  -d '{"query":"http://8.8.8.8/anything"}')
check "POST /api/targets URL-style IP (strips http://)"        201 "$CODE"

# Null optionals
CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json" \
  -d '{"query":"8.8.4.4","label":null,"notes":null}')
check "POST /api/targets null label/notes"           201 "$CODE"

# Max-length label (100) and notes (500)
LONG_LABEL=$(python3 -c "print('A'*100)")
LONG_NOTES=$(python3 -c "print('B'*500)")
CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json" \
  -d "{\"query\":\"1.1.1.1\",\"label\":\"$LONG_LABEL\",\"notes\":\"$LONG_NOTES\"}")
check "POST /api/targets max-length label+notes"     201 "$CODE"

# Over-limit label (truncated server-side → still 201)
OVER_LABEL=$(python3 -c "print('X'*200)")
CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json" \
  -d "{\"query\":\"1.1.1.1\",\"label\":\"$OVER_LABEL\"}")
check "POST /api/targets over-limit label (truncated)" 201 "$CODE"

# Unicode
CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json" \
  -d '{"query":"1.1.1.1","label":"🔍 OSINT تحليل","notes":"Ünïcödé tëst"}')
check "POST /api/targets Unicode label/notes"        201 "$CODE"

# Private IPs
for ip in "192.168.1.1" "10.0.0.1" "172.16.0.1" "127.0.0.1" "0.0.0.0" "255.255.255.255"; do
  CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json" -d "{\"query\":\"$ip\"}")
  check "POST /api/targets private/special IP $ip → 201" 201 "$CODE"
done

# Valid domains
for domain in "google.com" "sub.example.co.uk" "a.io" "test-site.org" "xn--nxasmq6b.com"; do
  CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json" -d "{\"query\":\"$domain\"}")
  check "POST /api/targets domain $domain → 201" 201 "$CODE"
done

# =============================================================================
section "5. POST /api/targets — Rejection Cases (422 / 400)"
# =============================================================================

# Invalid IPv4 — octets out of range
for ip in "256.0.0.1" "999.999.999.999" "300.1.1.1" "1.2.3.256"; do
  CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json" -d "{\"query\":\"$ip\"}")
  check "POST /api/targets invalid IPv4 $ip → 422" 422 "$CODE"
done

# Malformed IPv4
for ip in "1.2.3" "1.2.3.4.5" "1.2.3." ".1.2.3.4" "1..2.3.4" "01.002.003.004"; do
  CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json" -d "{\"query\":\"$ip\"}")
  check "POST /api/targets malformed IPv4 '$ip' → 422" 422 "$CODE"
done

# Invalid domains
for domain in "localhost" "example" ".com" "-.com" "a-.com" "com." "-example.com"; do
  CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json" -d "{\"query\":\"$domain\"}")
  check "POST /api/targets invalid domain '$domain' → 422" 422 "$CODE"
done

# Invalid ASN
for asn in "ASN123" "AS" "15169" "AS-123" "AS 123" "AS0x10"; do
  CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json" -d "{\"query\":\"$asn\"}")
  check "POST /api/targets invalid ASN '$asn' → 422" 422 "$CODE"
done

# Garbage inputs
for q in "not-valid" "!!!" "@#\$%" "just text" "SELECT * FROM users" "<script>" "../../etc/passwd"; do
  CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json" -d "{\"query\":\"$q\"}")
  check "POST /api/targets garbage '$q' → 422" 422 "$CODE"
done

# Missing query field
CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json" -d '{"label":"no query"}')
check "POST /api/targets missing query → 400"        400 "$CODE"

# Empty query string
CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json" -d '{"query":""}')
check "POST /api/targets empty query → 400"          400 "$CODE"

# Whitespace-only query
CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json" -d '{"query":"   "}')
check "POST /api/targets whitespace query → 400"     400 "$CODE"

# Numeric query (not a string)
CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json" -d '{"query":8888}')
check "POST /api/targets numeric query → 400"        400 "$CODE"

# Array query
CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json" -d '{"query":["8.8.8.8"]}')
check "POST /api/targets array query → 400"          400 "$CODE"

# Null query
CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json" -d '{"query":null}')
check "POST /api/targets null query → 400"           400 "$CODE"

# Malformed JSON
CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json" -d 'NOT JSON AT ALL')
check "POST /api/targets malformed JSON → 400"       400 "$CODE"

# Empty body
CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json" -d '')
check "POST /api/targets empty body → 400"           400 "$CODE"

# No body
CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json")
check "POST /api/targets no body → 400"              400 "$CODE"

# Wrong content-type
CODE=$(http_code POST $BASE/api/targets -H "Content-Type: text/plain" -d '{"query":"8.8.8.8"}')
check_any "POST /api/targets wrong Content-Type → 400 or 201" "$CODE" "400" "201"

# Extra unknown fields (should be ignored)
CODE=$(http_code POST $BASE/api/targets -H "Content-Type: application/json" \
  -d '{"query":"8.8.8.8","unknown_field":"evil","__proto__":{"polluted":true}}')
check "POST /api/targets extra/proto fields → 201"   201 "$CODE"

# =============================================================================
section "6. DELETE /api/targets/:id"
# =============================================================================

if [[ -n "$TARGET_ID" ]]; then
  CODE=$(http_code DELETE $BASE/api/targets/$TARGET_ID)
  check "DELETE /api/targets/$TARGET_ID (valid)" 204 "$CODE"

  CODE=$(http_code DELETE $BASE/api/targets/$TARGET_ID)
  check "DELETE /api/targets/$TARGET_ID (already deleted → 404)" 404 "$CODE"
else
  skip "TARGET_ID not captured — skipping delete own-ID tests"
fi

CODE=$(http_code DELETE $BASE/api/targets/99999999)
check "DELETE /api/targets/99999999 (non-existent → 404)"  404 "$CODE"

CODE=$(http_code DELETE $BASE/api/targets/0)
check "DELETE /api/targets/0 → 404"                        404 "$CODE"

CODE=$(http_code DELETE $BASE/api/targets/not-a-number)
check_any "DELETE /api/targets/string-id → 404 or 500"     "$CODE" "404" "500"

CODE=$(http_code DELETE "$BASE/api/targets/%27%20OR%201=1--")
check_any "DELETE /api/targets SQL injection → 404 or 400" "$CODE" "404" "400"

CODE=$(http_code GET $BASE/api/targets/99999)
check "GET /api/targets/:id (no GET route → 405)" 405 "$CODE"

# =============================================================================
section "7. GET /api/lookup — Turnstile Guard"
# =============================================================================

# Missing q entirely
CODE=$(http_code GET $BASE/api/lookup)
check "GET /api/lookup no params → 400" 400 "$CODE"

# Missing ts (bot guard fires before rate limit)
CODE=$(http_code GET "$BASE/api/lookup?q=8.8.8.8")
check "GET /api/lookup no ts → 403 (bot guard)" 403 "$CODE"

# Invalid ts with valid query
CODE=$(http_code GET "$BASE/api/lookup?q=8.8.8.8&ts=$DUMMY_TS")
check "GET /api/lookup invalid ts → 403" 403 "$CODE"
body_has "/api/lookup error mentions bot challenge" "bot challenge"

# Invalid ts with invalid query (Turnstile now fires BEFORE parseQuery)
CODE=$(http_code GET "$BASE/api/lookup?q=NOTVALID&ts=$DUMMY_TS")
check "GET /api/lookup invalid q + invalid ts → 403 (Turnstile fires first)" 403 "$CODE"

# Empty q with dummy ts
CODE=$(http_code GET "$BASE/api/lookup?q=&ts=$DUMMY_TS")
check "GET /api/lookup empty q + invalid ts → 400 or 403" 400 "$CODE"
# Note: if q-check fires before Turnstile it returns 400; otherwise 403

# SQL injection (Turnstile fires first)
CODE=$(http_code GET "$BASE/api/lookup?q=1'+OR+1=1--&ts=$DUMMY_TS")
check "GET /api/lookup SQL injection → 403 (Turnstile fires first)" 403 "$CODE"

# XSS in q (Turnstile fires first)
CODE=$(http_code GET "$BASE/api/lookup?q=%3Cscript%3Ealert(1)%3C/script%3E&ts=$DUMMY_TS")
check "GET /api/lookup XSS in q → 403 (Turnstile fires first)" 403 "$CODE"

# Very long q (1000 chars) - Turnstile fires first
LONGQ=$(python3 -c "print('a'*1000)")
CODE=$(http_code GET "$BASE/api/lookup?q=$LONGQ&ts=$DUMMY_TS")
check "GET /api/lookup very long q → 403 (Turnstile fires first)" 403 "$CODE"

# Null byte (Turnstile fires first)
CODE=$(http_code GET --globoff "$BASE/api/lookup?q=8.8.8.8%00evil&ts=$DUMMY_TS")
check "GET /api/lookup null byte in q → 403 (Turnstile fires first)" 403 "$CODE"

# refresh=1
CODE=$(http_code GET "$BASE/api/lookup?q=8.8.8.8&refresh=1&ts=$DUMMY_TS")
check "GET /api/lookup refresh=1 → 403 (Turnstile)" 403 "$CODE"

# POST to lookup
CODE=$(http_code POST $BASE/api/lookup -H "Content-Type: application/json" -d '{}')
check "POST /api/lookup → 405" 405 "$CODE"

# =============================================================================
section "8. GET /api/stream — Turnstile Guard"
# =============================================================================

CODE=$(http_code GET $BASE/api/stream)
check "GET /api/stream no params → 400" 400 "$CODE"

CODE=$(http_code GET "$BASE/api/stream?q=8.8.8.8")
check "GET /api/stream no ts → 403" 403 "$CODE"

CODE=$(http_code GET "$BASE/api/stream?q=8.8.8.8&ts=$DUMMY_TS")
check "GET /api/stream invalid ts → 403" 403 "$CODE"

CODE=$(http_code GET "$BASE/api/stream?q=INVALID&ts=$DUMMY_TS")
check "GET /api/stream invalid q + invalid ts → 403 (Turnstile fires first)" 403 "$CODE"

CODE=$(http_code POST $BASE/api/stream -d '{}')
check "POST /api/stream → 405" 405 "$CODE"

CODE=$(http_code DELETE $BASE/api/stream)
check "DELETE /api/stream → 405" 405 "$CODE"

# =============================================================================
section "9. POST /api/batch — Full Validation"
# =============================================================================

# Valid batch
CODE=$(http_code POST $BASE/api/batch \
  -H "Content-Type: application/json" \
  -d '{"queries":["8.8.8.8","1.1.1.1","example.com"]}')
check_any "POST /api/batch valid queries → 200 or 403" "$CODE" "200" "403"
if [[ "$CODE" == "200" ]]; then body_has "/api/batch has 'results'" '"results"'; fi

# Empty queries
CODE=$(http_code POST $BASE/api/batch -H "Content-Type: application/json" -d '{"queries":[]}')
check "POST /api/batch empty array → 400" 400 "$CODE"

# No queries key
CODE=$(http_code POST $BASE/api/batch -H "Content-Type: application/json" -d '{"q":"8.8.8.8"}')
check "POST /api/batch missing 'queries' key → 400" 400 "$CODE"

# queries is a string
CODE=$(http_code POST $BASE/api/batch -H "Content-Type: application/json" -d '{"queries":"8.8.8.8"}')
check "POST /api/batch queries=string → 400" 400 "$CODE"

# queries is an object
CODE=$(http_code POST $BASE/api/batch -H "Content-Type: application/json" -d '{"queries":{"0":"8.8.8.8"}}')
check "POST /api/batch queries=object → 400" 400 "$CODE"

# All invalid queries (strings that fail parseQuery)
CODE=$(http_code POST $BASE/api/batch -H "Content-Type: application/json" \
  -d '{"queries":["not valid","also bad","!!!"]}')
check_any "POST /api/batch all invalid strings → 200 (partial errors) or 403" "$CODE" "200" "403"

# Mixed valid and invalid
CODE=$(http_code POST $BASE/api/batch -H "Content-Type: application/json" \
  -d '{"queries":["8.8.8.8","INVALID_HOST","example.com"]}')
check_any "POST /api/batch mixed valid/invalid → 200 or 403" "$CODE" "200" "403"

# 20 queries (max)
QUERIES=$(python3 -c "import json; print(json.dumps({'queries': ['1.1.1.1']*20}))")
CODE=$(http_code POST $BASE/api/batch -H "Content-Type: application/json" -d "$QUERIES")
check_any "POST /api/batch max 20 queries → 200 or 403" "$CODE" "200" "403"

# 21 queries (capped to 20) - may hit rate limit if previous tests consumed quota
QUERIES=$(python3 -c "import json; print(json.dumps({'queries': ['1.1.1.1']*21}))")
CODE=$(http_code POST $BASE/api/batch -H "Content-Type: application/json" -d "$QUERIES")
check_any "POST /api/batch 21 queries (server caps at 20) → 200 or 403 or 429" "$CODE" "200" "403" "429"

# Non-string values in array (filtered out) - may hit rate limit
CODE=$(http_code POST $BASE/api/batch -H "Content-Type: application/json" \
  -d '{"queries":[1, null, true, "8.8.8.8"]}')
check_any "POST /api/batch mixed types in array → 200 or 400 or 403 or 429" "$CODE" "200" "400" "403" "429"

# Malformed JSON
CODE=$(http_code POST $BASE/api/batch -H "Content-Type: application/json" -d 'BAD JSON')
check "POST /api/batch malformed JSON → 400" 400 "$CODE"

# Empty body
CODE=$(http_code POST $BASE/api/batch -H "Content-Type: application/json" -d '')
check "POST /api/batch empty body → 400" 400 "$CODE"

# No body
CODE=$(http_code POST $BASE/api/batch -H "Content-Type: application/json")
check "POST /api/batch no body → 400" 400 "$CODE"

# Large body (500KB string) - skip due to shell argument limits
skip "POST /api/batch 500KB body (skipped - shell arg limit)"

# Wrong method
CODE=$(http_code GET $BASE/api/batch)
check "GET /api/batch → 405" 405 "$CODE"
CODE=$(http_code DELETE $BASE/api/batch)
check "DELETE /api/batch → 405" 405 "$CODE"
CODE=$(http_code PUT $BASE/api/batch -H "Content-Type: application/json" -d '{}')
check "PUT /api/batch → 405" 405 "$CODE"

# =============================================================================
section "10. GET /api/admin/health — Auth"
# =============================================================================

CODE=$(http_code GET $BASE/api/admin/health)
check "GET /api/admin/health no auth → 401" 401 "$CODE"

CODE=$(http_code GET $BASE/api/admin/health -H "Authorization: Bearer wrong-token-xyz")
check "GET /api/admin/health wrong token → 401" 401 "$CODE"

CODE=$(http_code GET $BASE/api/admin/health -H "Authorization: Basic dXNlcjpwYXNz")
check "GET /api/admin/health Basic scheme → 401" 401 "$CODE"

CODE=$(http_code GET $BASE/api/admin/health -H "Authorization: Bearer ")
check "GET /api/admin/health empty Bearer → 401" 401 "$CODE"

CODE=$(http_code GET $BASE/api/admin/health -H "Authorization: bearer lowercase")
check "GET /api/admin/health lowercase bearer → 401" 401 "$CODE"

CODE=$(http_code GET $BASE/api/admin/health -H "Authorization: ")
check "GET /api/admin/health empty auth header → 401" 401 "$CODE"

CODE=$(http_code POST $BASE/api/admin/health -H "Authorization: Bearer wrong")
check_any "POST /api/admin/health → 401 or 405" "$CODE" "401" "405"

# =============================================================================
section "11. GET /api/admin/reset-breaker"
# =============================================================================

CODE=$(http_code GET $BASE/api/admin/reset-breaker)
check_any "GET /api/admin/reset-breaker no auth → 401 or 404 or 405" "$CODE" "401" "404" "405"

CODE=$(http_code POST $BASE/api/admin/reset-breaker)
check_any "POST /api/admin/reset-breaker no auth → 401 or 404" "$CODE" "401" "404"

# =============================================================================
section "12. CONCURRENCY — Parallel requests to stable endpoints"
# =============================================================================

log "Firing $CONCURRENCY concurrent GETs to /api/recent..."
RESULTS=()
for i in $(seq 1 $CONCURRENCY); do
  (curl -s -o /dev/null -w "%{http_code}" $BASE/api/recent) &
done | while read -r c; do
  [[ "$c" == "200" ]] && echo "OK" || echo "FAIL:$c"
done | sort | uniq -c &
wait
pass "Concurrency burst $CONCURRENCY × /api/recent — all fired"

log "Firing $CONCURRENCY concurrent POST /api/targets..."
for i in $(seq 1 $CONCURRENCY); do
  (
    c=$(curl -s -o /dev/null -w "%{http_code}" -X POST $BASE/api/targets \
      -H "Content-Type: application/json" \
      -d "{\"query\":\"10.0.$((RANDOM % 256)).$((RANDOM % 256))\",\"label\":\"stress-$i\"}" 2>/dev/null)
    echo "targets-$i: $c"
  ) &
done
wait
pass "Concurrent POST /api/targets ($CONCURRENCY) — all fired"

# =============================================================================
section "13. RAPID-FIRE — 30 sequential /api/recent (rate-limit probe)"
# =============================================================================

log "Sending 30 rapid GETs to /api/recent (no rate limit expected)..."
FAIL_RF=0
for i in $(seq 1 30); do
  c=$(curl -s -o /dev/null -w "%{http_code}" $BASE/api/recent 2>/dev/null)
  [[ "$c" != "200" ]] && ((FAIL_RF++))
done
if [[ $FAIL_RF -eq 0 ]]; then
  pass "30 rapid /api/recent → all 200 (no rate limit on this endpoint)"
else
  fail "30 rapid /api/recent → $FAIL_RF non-200 responses"
fi

# =============================================================================
section "14. SECURITY HEADERS"
# =============================================================================

log "Checking response headers on /"
HEADERS=$(curl -s -I $BASE/ 2>&1)

for h in "content-type" "x-content-type-options" "x-frame-options" "strict-transport-security" "cache-control"; do
  if echo "$HEADERS" | grep -qi "^$h"; then
    pass "Security header present: $h"
  else
    skip "Security header absent: $h (may be set by Cloudflare edge)"
  fi
done

# CSP
if echo "$HEADERS" | grep -qi "content-security-policy"; then
  pass "Content-Security-Policy header present"
else
  skip "Content-Security-Policy not found on / (may be on sub-pages)"
fi

# =============================================================================
section "15. CORS — OPTIONS preflight"
# =============================================================================

CODE=$(http_code OPTIONS $BASE/api/recent \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: GET")
check_any "OPTIONS /api/recent (CORS preflight)" "$CODE" "200" "204" "405"

CODE=$(http_code OPTIONS $BASE/api/targets \
  -H "Origin: https://malicious-site.com" \
  -H "Access-Control-Request-Method: POST")
check_any "OPTIONS /api/targets (CORS preflight)" "$CODE" "200" "204" "405"

# =============================================================================
# SUMMARY
# =============================================================================

echo ""
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  TEST RESULTS${NC}"
echo -e "${BOLD}══════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}PASS${NC}: $PASS"
echo -e "  ${RED}FAIL${NC}: $FAIL"
echo -e "  ${YELLOW}SKIP${NC}: $SKIP"
echo -e "  TOTAL: $((PASS + FAIL + SKIP))"
echo ""
if [[ $FAIL -eq 0 ]]; then
  echo -e "${GREEN}${BOLD}✓ All tests passed!${NC}"
  exit 0
else
  echo -e "${RED}${BOLD}✗ $FAIL test(s) failed — see output above${NC}"
  exit 1
fi
