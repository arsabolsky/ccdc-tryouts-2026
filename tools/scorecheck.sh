#!/usr/bin/env bash
# scorecheck.sh - check scored services from outside, like the scoring engine.
# Run from your laptop (over the VPN) or from another box.
#
# Usage: ./scorecheck.sh <team#> [user] [password]      one pass
#        WATCH=60 ./scorecheck.sh <team#> steve 'pw'   repeat every 60s
# Env overrides: IRON, LAPIS, REDSTONE (IPs), DOMAIN (AD DNS name for DNS test)
set -u

TEAM=${1:?usage: $0 <team#> [user] [password]}
USER_=${2:-}
PASS=${3:-}
NET="192.168.$((200 + TEAM))"
IRON=${IRON:-$NET.10}
LAPIS=${LAPIS:-$NET.11}
REDSTONE=${REDSTONE:-$NET.12}
T=${T:-5}   # per-check timeout (seconds)
STATE_DIR=${STATE_DIR:-$HOME/.scorecheck}
mkdir -p "$STATE_DIR"

if [ -t 1 ]; then G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; N=$'\e[0m'; else G='' R='' Y='' N=''; fi
ok()   { printf '  %-28s %sUP%s   %s\n'   "$1" "$G" "$N" "${2:-}"; }
bad()  { printf '  %-28s %sDOWN%s %s\n'   "$1" "$R" "$N" "${2:-}"; }
warn() { printf '  %-28s %sWARN%s %s\n'   "$1" "$Y" "$N" "${2:-}"; }

port_open() {  # host port
  # macOS nc ignores -w while connecting (a dead host takes ~75s); -G bounds it.
  if [ "$(uname)" = Darwin ]; then nc -z -G "$T" -w "$T" "$1" "$2" >/dev/null 2>&1
  elif command -v nc >/dev/null 2>&1; then nc -z -w "$T" "$1" "$2" >/dev/null 2>&1
  else timeout "$T" bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; fi
}

check_http() {  # host scheme port
  local h=$1 s=$2 p=$3 name body code hash f
  name="HTTP $s://$h:$p"
  port_open "$h" "$p" || { bad "$name" "port closed"; return; }
  body=$(mktemp)
  code=$(curl -sk -m "$T" -o "$body" -w '%{http_code}' "$s://$h:$p/")
  if command -v md5sum >/dev/null 2>&1; then hash=$(md5sum "$body" | cut -d' ' -f1)
  else hash=$(md5 -q "$body"); fi
  f="$STATE_DIR/http-$h-$p.md5"
  if [ "${code:0:1}" != 2 ] && [ "${code:0:1}" != 3 ]; then
    bad "$name" "status $code"
  elif [ ! -f "$f" ]; then
    echo "$hash" >"$f"; ok "$name" "status $code, baseline md5 saved ($hash)"
  elif [ "$(cat "$f")" != "$hash" ]; then
    warn "$name" "status $code, CONTENT CHANGED (md5 $hash, baseline $(cat "$f"))"
  else
    ok "$name" "status $code, content matches baseline"
  fi
  rm -f "$body"
}

check_ftp() {
  local h=$1
  port_open "$h" 21 || { bad "FTP $h:21" "port closed"; return; }
  if [ -n "$USER_" ]; then
    if curl -s -m "$T" --list-only "ftp://$h/" --user "$USER_:$PASS" >/dev/null; then
      ok "FTP $h:21" "login + passive listing as $USER_"
    else bad "FTP $h:21" "port open but login/listing failed"; fi
  else ok "FTP $h:21" "port open (no creds given)"; fi
}

pop3_login() {  # host -> 0 if USER/PASS accepted
  if curl -V 2>/dev/null | grep -qi pop3; then
    curl -s -m "$T" "pop3://$1/" --user "$USER_:$PASS" >/dev/null; return
  fi
  # This curl lacks POP3 (e.g. Rocky curl-minimal): speak the protocol directly.
  local n
  n=$( { sleep 1; printf 'USER %s\r\n' "$USER_"; sleep 1; printf 'PASS %s\r\n' "$PASS"; sleep 1; printf 'QUIT\r\n'; } \
       | nc -w "$T" "$1" 110 2>/dev/null | grep -c '^+OK')
  [ "${n:-0}" -ge 3 ]   # greeting, USER, PASS all +OK
}

check_pop3() {
  local h=$1
  port_open "$h" 110 || { bad "POP3 $h:110" "port closed"; return; }
  if [ -n "$USER_" ]; then
    if pop3_login "$h"; then
      ok "POP3 $h:110" "login as $USER_"
    else bad "POP3 $h:110" "port open but login failed"; fi
  else ok "POP3 $h:110" "port open (no creds given)"; fi
}

check_ssh() {
  local h=$1 banner
  port_open "$h" 22 || { bad "SSH $h:22" "port closed"; return; }
  banner=$(nc -w "$T" "$h" 22 </dev/null 2>/dev/null | head -c 64 | tr -d '\r\n')
  case $banner in SSH-*) ok "SSH $h:22" "$banner";; *) bad "SSH $h:22" "no SSH banner";; esac
}

check_dns() {
  local h=$1
  if ! command -v dig >/dev/null 2>&1; then
    port_open "$h" 53 && ok "DNS $h:53/tcp" "(install dig for a real query)" || bad "DNS $h:53" "closed"; return
  fi
  local q=${DOMAIN:-}
  if [ -z "$q" ]; then
    # Discover the AD domain from the rootDSE (anonymous read is allowed on AD).
    q=$(curl -s -m "$T" "ldap://$h/?defaultNamingContext?base" 2>/dev/null \
        | awk -F': ' '/defaultNamingContext/{print $2}' | sed 's/DC=//g; s/,/./g')
  fi
  if [ -z "$q" ]; then warn "DNS $h:53" "set DOMAIN=<ad.domain> to test"; return; fi
  if [ -n "$(dig +short +time=$T +tries=1 @"$h" "$q" SOA)" ]; then ok "DNS $h:53" "resolves $q"
  else bad "DNS $h:53" "no answer for $q"; fi
}

check_ldap() {
  local h=$1
  port_open "$h" 389 || { bad "LDAP $h:389" "port closed"; return; }
  if [ -n "$USER_" ] && command -v ldapwhoami >/dev/null 2>&1 && [ -n "${DOMAIN:-}" ]; then
    if ldapwhoami -x -H "ldap://$h" -D "$USER_@$DOMAIN" -w "$PASS" >/dev/null 2>&1; then
      ok "LDAP $h:389" "bind as $USER_@$DOMAIN"
    else bad "LDAP $h:389" "port open but bind failed"; fi
  else ok "LDAP $h:389" "port open (bind test needs ldapwhoami + DOMAIN + creds)"; fi
}

run_once() {
  echo "=== $(date '+%H:%M:%S')  team $TEAM"
  local h p exp
  for h in "$IRON" "$LAPIS"; do
    echo "-- $h"
    exp="$STATE_DIR/expected-$h"
    # First run: record which scored ports exist. Later runs check those
    # ports even when closed, so a service that dies shows as DOWN.
    if [ ! -s "$exp" ]; then
      for p in 22 80 443 21 110 53 389; do port_open "$h" "$p" && echo "$p"; done >"$exp"
      echo "  (recorded expected ports: $(tr '\n' ' ' <"$exp"); delete $exp to re-learn)"
    fi
    while read -r p; do
      case $p in
        22)  check_ssh "$h" ;;
        80)  check_http "$h" http 80 ;;
        443) check_http "$h" https 443 ;;
        21)  check_ftp "$h" ;;
        110) check_pop3 "$h" ;;
        53)  check_dns "$h" ;;
        389) check_ldap "$h" ;;
      esac
    done <"$exp"
  done
  echo "-- $REDSTONE (Splunk, not scored)"
  if port_open "$REDSTONE" 8000; then ok "Splunk web :8000"; else warn "Splunk web :8000" "unreachable"; fi
}

if [ -n "${WATCH:-}" ]; then
  while true; do clear 2>/dev/null; run_once; sleep "$WATCH"; done
else
  run_once
fi
