#!/usr/bin/env bash
#
# Brings the demo stack up and asserts the decisions, so CI catches a change
# that quietly turns a deny into an allow. Every case here is one an operator
# would care about being wrong.

set -euo pipefail

GATEWAY="${GATEWAY:-http://localhost:10000}"
IDP="${IDP:-http://localhost:9800}"

cd "$(dirname "${BASH_SOURCE[0]}")/.."

failures=0

mint() {
  curl -sfG "${IDP}/token" \
    --data-urlencode "sub=${1}" \
    --data-urlencode "tenant=${2}" \
    --data-urlencode "scope=${3}" \
    --data-urlencode "ttl=${4:-15m}"
}

# expect <name> <want-status> <want-error> <method> <path> [token]
expect() {
  local name="$1" want_status="$2" want_error="$3" method="$4" path="$5" token="${6:-}"
  local args=(-s -o /tmp/smoke-body -w '%{http_code}' -X "${method}")
  [ -n "${token}" ] && args+=(-H "Authorization: Bearer ${token}")

  local status
  status="$(curl "${args[@]}" "${GATEWAY}${path}")"

  local error=""
  if [ "${status}" != "200" ]; then
    error="$(python3 -c 'import json;print(json.load(open("/tmp/smoke-body")).get("error",""))' 2>/dev/null || true)"
  fi

  if [ "${status}" != "${want_status}" ] || [ "${error}" != "${want_error}" ]; then
    printf 'FAIL  %-40s got %s/%s, want %s/%s\n' "${name}" "${status}" "${error}" "${want_status}" "${want_error}"
    failures=$((failures + 1))
    return
  fi
  printf 'ok    %-40s %s %s\n' "${name}" "${status}" "${error}"
}

# expect_header <name> <header> <want> <token> [extra curl args...]
expect_header() {
  local name="$1" header="$2" want="$3" token="$4"; shift 4
  local got
  got="$(curl -s -H "Authorization: Bearer ${token}" "$@" "${GATEWAY}/v1/events" |
    python3 -c "import json,sys;print(json.load(sys.stdin)['identity'].get('${header}',''))")"
  if [ "${got}" != "${want}" ]; then
    printf 'FAIL  %-40s %s = %q, want %q\n' "${name}" "${header}" "${got}" "${want}"
    failures=$((failures + 1))
    return
  fi
  printf 'ok    %-40s %s=%s\n' "${name}" "${header}" "${got}"
}

echo "==> starting the stack"
docker compose -f deploy/docker/docker-compose.yaml up -d --build --wait --wait-timeout 180 >/dev/null

echo "==> waiting for the gateway"
for _ in $(seq 1 60); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "${GATEWAY}/healthz")" = "200" ] && break
  sleep 1
done

reader="$(mint svc-reporting acme events.read)"
admin_acme="$(mint ops acme 'admin events.read')"
admin_other="$(mint ops initech admin)"
expired="$(mint svc-reporting acme events.read -1m)"
no_tenant="$(mint svc-reporting '' events.read)"

echo
expect "public route needs no token"        200 ""                   GET  /healthz
expect "protected route needs a token"      401 "missing_token"      GET  /v1/events
expect "valid token is allowed"             200 ""                   GET  /v1/events "${reader}"
expect "read scope cannot write"            403 "insufficient_scope" POST /v1/events "${reader}"
expect "expired token is rejected"          401 "invalid_token"      GET  /v1/events "${expired}"
expect "a tenant is required"               403 "wrong_tenant"       GET  /v1/events "${no_tenant}"
expect "allowed tenant reaches admin"       200 ""                   GET  /v1/admin/users "${admin_acme}"
expect "other tenant does not"              403 "wrong_tenant"       GET  /v1/admin/users "${admin_other}"
expect "reader has no admin scope"          403 "insufficient_scope" GET  /v1/admin/users "${reader}"
expect "rule with no allow block denies"    403 "rule_denies"        GET  /internal/debug "${admin_acme}"
expect "unmatched path is denied"           403 "no_matching_rule"   GET  /v2/anything "${admin_acme}"

echo
expect_header "identity reaches the upstream" x-portcullis-tenant acme "${reader}"
expect_header "forged identity is replaced"   x-portcullis-tenant acme "${reader}" \
  -H 'x-portcullis-tenant: globex'
expect_header "forged identity on a fresh key is dropped" x-portcullis-claim-role "" "${reader}" \
  -H 'x-portcullis-claim-role: admin'

echo
if [ "${failures}" -ne 0 ]; then
  echo "${failures} check(s) failed"
  docker compose -f deploy/docker/docker-compose.yaml logs portcullis | tail -40
  exit 1
fi
echo "all checks passed"
