#!/usr/bin/env bash
# acmesh_runner.sh -- run one acme.sh dnsapi/dns_XXX.sh function in isolation.
#
# Usage: acmesh_runner.sh <script_path> <func_prefix> <add|rm> <fqdn> <value>
#
# acme.sh's dnsapi scripts assume a bunch of helper functions (normally defined by
# the main acme.sh script) are already in scope. This file reimplements the common
# subset of that helper surface from scratch -- see README.md "The acme.sh shim" for
# what is and isn't covered. If a dnsapi script fails with "command not found" for
# some `_xxx` function, that's a helper this shim doesn't provide yet; add it below.
# NOTE: deliberately no `set -euo pipefail` here. Real acme.sh does not run under
# nounset/errexit either, and its dnsapi scripts rely on that: they reference
# possibly-unset optional variables and treat non-zero exits from grep/curl etc. as
# ordinary control flow, not fatal errors. Adding strict mode here breaks scripts that
# work perfectly fine under acme.sh's own (non-strict) shell.
set -o pipefail

SCRIPT_PATH="$1"
PREFIX="$2"
ACTION="$3"
FQDN="$4"
VALUE="$5"

# ---------------------------------------------------------------------------
# logging (acme.sh uses these liberally; we just send everything to stderr so
# it ends up in this process's stderr, which the Python backend captures)
# ---------------------------------------------------------------------------
_info()          { echo "[INFO] $*" >&2; }
_err()           { echo "[ERROR] $*" >&2; return 1; }
_debug()         { echo "[DEBUG] $*" >&2; }
_debug2()        { :; }
_debug3()        { :; }
_secure_debug()  { :; }
_secure_debug2() { :; }
_secure_debug3() { :; }

# ---------------------------------------------------------------------------
# encoding helpers
# ---------------------------------------------------------------------------
_base64() {
  if [ -n "${1:-}" ]; then
    openssl base64 -e
  else
    openssl base64 -e | tr -d '\r\n'
  fi
}

_dbase64() {
  if [ -n "${1:-}" ]; then
    openssl base64 -d
  else
    openssl base64 -d 2>/dev/null
  fi
}

_url_encode() {
  local raw
  raw="$(cat)"
  python3 -c "import sys, urllib.parse; sys.stdout.write(urllib.parse.quote(sys.stdin.read(), safe=''))" <<<"$raw"
}

_url_decode() {
  local raw
  raw="$(cat)"
  python3 -c "import sys, urllib.parse; sys.stdout.write(urllib.parse.unquote(sys.stdin.read()))" <<<"$raw"
}

_hex_dump() {
  od -A n -t x1 | tr -d " \n"
}

# _h2b -- hex string on stdin -> raw binary on stdout. Real acme.sh helper, needed by
# _hmac's fallback path for openssl versions without `-mac HMAC -macopt hexkey:...`.
_h2b() {
  if command -v xxd >/dev/null 2>&1; then
    xxd -r -p
  else
    local hex
    hex="$(cat)"
    # shellcheck disable=SC2059
    printf "$(echo "$hex" | tr 'a-f' 'A-F' | sed 's/\([0-9A-F]\{2\}\)/\\x\1/g')"
  fi
}

# _hmac <alg: sha256|sha1> <secret_hex> [outputhex]
# reads the data to be signed from stdin. Matches real acme.sh's parameter order and
# semantics exactly -- notably that the secret is HEX-ENCODED (callers pass it through
# `_hex_dump` first), not a literal passphrase; getting either of those wrong produces
# a wrong signature (or, if the argument positions are swapped, an outright
# "Unknown option or message digest" openssl error).
_hmac() {
  local alg="$1" secret_hex="$2" outputhex="$3"
  if [ -n "$outputhex" ]; then
    { openssl dgst "-${alg}" -mac HMAC -macopt "hexkey:${secret_hex}" 2>/dev/null \
      || openssl dgst "-${alg}" -hmac "$(printf '%s' "$secret_hex" | _h2b)"; } | cut -d = -f2 | tr -d ' '
  else
    openssl dgst "-${alg}" -mac HMAC -macopt "hexkey:${secret_hex}" -binary 2>/dev/null \
      || openssl dgst "-${alg}" -hmac "$(printf '%s' "$secret_hex" | _h2b)" -binary
  fi
}

_utc_date() { date -u "+%Y-%m-%d %H:%M:%S"; }
_time()     { date -u "+%s"; }

_lower_case() { tr 'A-Z' 'a-z'; }
_upper_case() { tr 'a-z' 'A-Z'; }

# real acme.sh implements these with grep, so $2 is a REGEX, not a literal/glob --
# matters for any dnsapi script that passes regex metacharacters.
_startswith() { echo "$1" | grep -- "^$2" >/dev/null 2>&1; }
_endswith()   { echo "$1" | grep -- "$2\$" >/dev/null 2>&1; }
_contains()   { echo "$1" | grep -- "$2" >/dev/null 2>&1; }

# text-processing helpers used by many providers' record-parsing logic
_egrep_o() { grep -E -o "$1"; }
_head_n()  { head -n "$1"; }
_math()    { echo "$(( $* ))"; }

# ---------------------------------------------------------------------------
# account-config persistence stubs.
#
# Real acme.sh caches provider credentials in ~/.acme.sh/account.conf so you don't
# have to re-export them on every renewal. This proxy is stateless by design: the
# operator supplies full credentials via config.yaml's backend `env` block on every
# single invocation (see AcmeShDNSApiBackend), so there is nothing useful to persist
# here. These are safe no-ops -- note that dnsapi scripts read config with
# `${VAR:-$(_readaccountconf_mutable VAR)}`, which in POSIX shell only evaluates the
# command substitution when $VAR is unset/empty, so as long as your config.yaml sets
# every credential the provider needs, _readaccountconf_mutable is never even called.
# ---------------------------------------------------------------------------
_readaccountconf_mutable()  { :; }
_saveaccountconf_mutable()  { :; }
_savedomainconf()           { :; }
_clearaccountconf_mutable() { :; }
_clearaccountconf()         { :; }
_readdomainconf()           { :; }
_savedeployconf()           { :; }
_readaccountconf()          { :; }
_saveaccountconf()          { :; }

# ---------------------------------------------------------------------------
# HTTP helpers -- support the common `_H1`.."_H5" custom-header convention used
# throughout dnsapi/*.sh, e.g.:
#   export _H1="Content-Type: application/json"
#   export _H2="Authorization: Bearer $TOKEN"
#   response="$(_post "$body" "$url")"
# ---------------------------------------------------------------------------
_curl_headers() {
  local args=()
  for h in "${_H1:-}" "${_H2:-}" "${_H3:-}" "${_H4:-}" "${_H5:-}"; do
    [ -n "$h" ] && args+=(-H "$h")
  done
  # Guard needed because `printf '%s\0'` with a truly empty "$@" still runs once,
  # substituting an empty string for the missing %s -- producing one phantom NUL byte
  # instead of no output at all. Callers' read loops would then pick up a bogus empty
  # argument even when no _H1.._H5 headers are set, which recent curl (8.18+) rejects
  # outright as "option : blank argument where content is expected".
  [ "${#args[@]}" -gt 0 ] && printf '%s\0' "${args[@]}"
  return 0
}

_post() {
  # _post body url [needbase64] [httpmethod] [postContentType]
  # Matches real acme.sh's _post signature -- notably $5, the request Content-Type.
  # Some dnsapi scripts (e.g. dns_acmedns.sh) rely on it to get "application/json"
  # set explicitly; without it curl defaults to
  # "application/x-www-form-urlencoded" for -d/--data, which breaks JSON APIs that
  # validate Content-Type strictly.
  local body="$1" url="$2" needbase64="$3" method="${4:-POST}" content_type="$5"
  local -a headers=()
  while IFS= read -r -d '' arg; do headers+=("$arg"); done < <(_curl_headers)
  [ -n "$content_type" ] && headers=(-H "Content-Type: $content_type" "${headers[@]}")
  if [ -n "$needbase64" ]; then
    curl -sS --max-time 30 -X "$method" "${headers[@]}" -d "$body" "$url" | _base64
  else
    curl -sS --max-time 30 -X "$method" "${headers[@]}" -d "$body" "$url"
  fi
}

_get() {
  # _get url [onlyheader] [timeout]
  local url="$1" timeout="${3:-30}"
  local -a headers=()
  while IFS= read -r -d '' arg; do headers+=("$arg"); done < <(_curl_headers)
  curl -sS --max-time "$timeout" "${headers[@]}" "$url"
}

_head() {
  local url="$1"
  local -a headers=()
  while IFS= read -r -d '' arg; do headers+=("$arg"); done < <(_curl_headers)
  curl -sSI --max-time 30 "${headers[@]}" "$url"
}

# ---------------------------------------------------------------------------
# _get_root <fulldomain> -- best-effort zone-apex walker.
# Sets $_domain (zone apex) and $_sub_domain (record name within that zone).
# Real acme.sh providers frequently implement their OWN zone lookup against
# their API instead of using this, so this is a fallback for providers that
# do rely on the shared helper.
# ---------------------------------------------------------------------------
_get_root() {
  local full="$1"
  local i=1
  local domain
  while true; do
    domain="$(echo "$full" | cut -d. -f"$i"-)"
    [ -z "$domain" ] && return 1
    if host -t SOA "$domain" >/dev/null 2>&1; then
      _domain="$domain"
      _sub_domain="${full%".$domain"}"
      return 0
    fi
    i=$((i + 1))
    [ "$i" -gt 10 ] && return 1
  done
}

# ---------------------------------------------------------------------------
# load the real dnsapi script, then invoke it
# ---------------------------------------------------------------------------
# shellcheck disable=SC1090
source "$SCRIPT_PATH"

case "$ACTION" in
  add) "${PREFIX}_add" "$FQDN" "$VALUE" ;;
  rm)  "${PREFIX}_rm"  "$FQDN" "$VALUE" ;;
  *)   echo "[ERROR] unknown action: $ACTION" >&2; exit 2 ;;
esac
