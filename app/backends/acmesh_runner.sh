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
  if [ "${1:-}" = "multiline" ]; then
    openssl base64 -e
  else
    openssl base64 -e | tr -d '\n'
  fi
}

_dbase64() {
  if [ "${1:-}" = "multiline" ]; then
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

# _hmac <key> <alg: sha256|sha1|md5> [hex output flag - ignored, always hex]
# reads the data to be signed from stdin, mirroring acme.sh's usage pattern.
_hmac() {
  local key="$1" alg="${2:-sha256}"
  openssl dgst "-${alg}" -hmac "$key" | awk '{print $NF}'
}

_utc_date() { date -u "+%a, %d %b %Y %H:%M:%S GMT"; }
_time()     { date -u "+%s"; }

_lower_case() { tr 'A-Z' 'a-z'; }
_upper_case() { tr 'a-z' 'A-Z'; }

_startswith() { case "$1" in "$2"*) return 0 ;; *) return 1 ;; esac; }
_endswith()   { case "$1" in *"$2") return 0 ;; *) return 1 ;; esac; }
_contains()   { case "$1" in *"$2"*) return 0 ;; *) return 1 ;; esac; }

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
  printf '%s\0' "${args[@]}"
}

_post() {
  # _post body url [needbase64] [httpmethod]
  local body="$1" url="$2" method="${4:-POST}"
  local -a headers=()
  while IFS= read -r -d '' arg; do headers+=("$arg"); done < <(_curl_headers)
  curl -sS --max-time 30 -X "$method" "${headers[@]}" -d "$body" "$url"
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
