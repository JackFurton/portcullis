#!/usr/bin/env bash
#
# The whole authorization path on a laptop: Envoy calling this service for
# every request, a stand-in identity provider minting tokens, and an upstream
# that reports what actually arrived.
#
#   hack/demo.sh up      build and start the stack
#   hack/demo.sh try     walk through allow and deny cases
#   hack/demo.sh token   mint a token, e.g. hack/demo.sh token --tenant acme --scope admin
#   hack/demo.sh logs    follow the decisions
#   hack/demo.sh down    stop everything

set -euo pipefail

GATEWAY="${GATEWAY:-http://localhost:10000}"
IDP="${IDP:-http://localhost:9800}"
ADMIN="${ADMIN:-http://localhost:9812}"

cd "$(dirname "${BASH_SOURCE[0]}")/../deploy/docker"

compose() { docker compose "$@"; }

# mint returns a signed token from the demo identity provider.
mint() {
  local sub="demo-user" tenant="" scope="" ttl="15m"
  while [ $# -gt 0 ]; do
    case "$1" in
      --sub) sub="$2"; shift 2 ;;
      --tenant) tenant="$2"; shift 2 ;;
      --scope) scope="$2"; shift 2 ;;
      --ttl) ttl="$2"; shift 2 ;;
      *) echo "unknown flag: $1" >&2; return 1 ;;
    esac
  done
  curl -sfG "${IDP}/token" \
    --data-urlencode "sub=${sub}" \
    --data-urlencode "tenant=${tenant}" \
    --data-urlencode "scope=${scope}" \
    --data-urlencode "ttl=${ttl}"
}

# call prints the status and the reason portcullis gave, if it denied.
call() {
  local label="$1" method="$2" path="$3" token="${4:-}"
  local args=(-s -o /tmp/portcullis-body -w '%{http_code}' -X "${method}")
  [ -n "${token}" ] && args+=(-H "Authorization: Bearer ${token}")

  local code
  code="$(curl "${args[@]}" "${GATEWAY}${path}")"

  local detail=""
  if [ "${code}" != "200" ]; then
    detail=" $(python3 -c 'import json,sys; print(json.load(open("/tmp/portcullis-body")).get("error",""))' 2>/dev/null || true)"
  fi
  printf '  %-3s  %-6s %-28s %s%s\n' "${code}" "${method}" "${path}" "${label}" "${detail}"
}

up() {
  compose up -d --build
  # Wait on a real request through Envoy, not on the service's own health
  # endpoint. Recreating a container gives it a new address, and Envoy needs a
  # moment to re-resolve the cluster before it stops answering 403 on its own.
  echo "==> waiting for the gateway"
  for _ in $(seq 1 60); do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' "${GATEWAY}/healthz")" = "200" ]; then break; fi
    sleep 1
  done
  echo
  echo "Up. Walk through the cases with:"
  echo
  echo "    hack/demo.sh try"
  echo
}

try() {
  local reader admin_acme admin_other expired noscope

  reader="$(mint --sub svc-reporting --tenant acme --scope events.read)"
  admin_acme="$(mint --sub ops --tenant acme --scope 'admin events.read')"
  admin_other="$(mint --sub ops --tenant initech --scope admin)"
  expired="$(mint --sub svc-reporting --tenant acme --scope events.read --ttl -1m)"
  noscope="$(mint --sub svc-reporting --tenant acme)"

  echo
  echo "Open route, no token:"
  call "public rule" GET /healthz

  echo
  echo "Protected route:"
  call "no token"                     GET /v1/events
  call "valid, events.read"           GET /v1/events "${reader}"
  call "read token, write route"      POST /v1/events "${reader}"
  call "no scope on the token"        GET /v1/events "${noscope}"
  call "expired token"                GET /v1/events "${expired}"

  echo
  echo "Tenant scoped route:"
  call "acme is allowed"              GET /v1/admin/users "${admin_acme}"
  call "initech is not"               GET /v1/admin/users "${admin_other}"
  call "reader has no admin scope"    GET /v1/admin/users "${reader}"

  echo
  echo "Rules that deny by construction:"
  call "rule with no allow block"     GET /internal/debug "${admin_acme}"
  call "no rule matches"              GET /v2/anything "${admin_acme}"

  echo
  echo "Identity the upstream received:"
  curl -s -H "Authorization: Bearer ${reader}" "${GATEWAY}/v1/events" |
    python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["identity"], indent=2))'

  echo
  echo "The same request with a forged identity header:"
  curl -s -H "Authorization: Bearer ${reader}" -H 'x-portcullis-tenant: globex' \
    -H 'x-portcullis-subject: root' "${GATEWAY}/v1/events" |
    python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin)["identity"], indent=2))'
  echo "  (the forged values never reach the upstream)"
  echo
}

case "${1:-up}" in
  up) up ;;
  try) try ;;
  token) shift; mint "$@" ;;
  logs) compose logs -f portcullis envoy ;;
  down) compose down -v ;;
  *) echo "usage: $0 {up|try|token|logs|down}" >&2; exit 1 ;;
esac
