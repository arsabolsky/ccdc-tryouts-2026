#!/usr/bin/env bash
# share.sh - upload files (reports, logs, configs) to a paste service and print the URL.
# Works on Linux, VyOS (as vyos) and macOS. Needs curl (or nc for termbin).
#
#   ./share.sh /root/ccdc-backup/hunt-*.txt          one paste per file
#   ./share.sh --one /etc/ssh/sshd_config /etc/vsftpd.conf   all files in one paste
#   ./share.sh /var/www/html                          a directory: its text files, one paste
#   some-command | ./share.sh -                       stdin
#
# Options:
#   --one        combine everything into a single paste
#   --raw        skip redaction (see below)
#   --service S  paste.rs (default), termbin, or pastebin
#
# Pastes are PUBLIC to anyone with the link. By default this script refuses
# shadow files and private keys, and blanks password hashes and password values,
# so a pasted config does not hand out your new passwords. --raw turns that off.
#
# pastebin.com needs an account API key (PASTEBIN_DEV_KEY). Services that need an
# account are against rule 7 of the tryout packet, so it is not the default.
# PASTE_URL overrides the paste.rs endpoint (used for testing).
set -uo pipefail

SERVICE=paste.rs; ONE=0; RAW=0; FILES=()
while [ $# -gt 0 ]; do
  case $1 in
    --one) ONE=1;; --raw) RAW=1;; --service) SERVICE=${2:?}; shift;;
    -h|--help) sed -n '2,23p' "$0"; exit 0;;
    *) FILES+=("$1");;
  esac; shift
done
[ ${#FILES[@]} -gt 0 ] || { sed -n '2,23p' "$0"; exit 2; }
PASTE_URL=${PASTE_URL:-https://paste.rs/}

refused() {  # path -> 0 if this file must never be pasted (unless --raw)
  [ "$RAW" = 1 ] && return 1
  case $(basename "$1") in shadow|shadow-|gshadow|gshadow-|*.key|*.pem|id_rsa|id_ecdsa|id_ed25519|id_dsa|ssh_host_*_key) return 0;; esac
  grep -q -- '-----BEGIN [A-Z ]*PRIVATE KEY-----' "$1" 2>/dev/null
}

redact() {  # stdin -> stdout with secrets blanked
  if [ "$RAW" = 1 ]; then cat; return; fi
  # Only "=" or ":" mark a value (plus VyOS "*-password '...'"), so log lines
  # like "Failed password for root from ..." stay intact.
  sed -E \
    -e 's/\$(1|2[abxy]?|5|6|7|y|gy|sha1|md5)\$[^:[:space:]]+/<hash-redacted>/g' \
    -e "s/((plaintext|encrypted)-password +)['\"]?[^'\"[:space:]]+['\"]?/\1'<redacted>'/Ig" \
    -e "s/(password|passwd|secret|pass|pwd)([\"' ]*[=:][\"' ]*)[^\"'[:space:],;<]+/\1\2<redacted>/Ig"
}

is_text() { [ ! -s "$1" ] || LC_ALL=C grep -Iq . "$1" 2>/dev/null; }

# Build the list of (label, file) pairs; directories expand to their text files.
ITEMS=()
for f in "${FILES[@]}"; do
  if [ "$f" = - ]; then ITEMS+=("-"); continue; fi
  if [ -d "$f" ]; then
    # Skip big files (e.g. /etc/ssh/moduli, ~550 KB of key-exchange numbers) in directory uploads.
    while IFS= read -r g; do
      if [ "$(wc -c <"$g")" -gt 204800 ]; then echo "skip (over 200 KB; upload it by name to include it): $g" >&2; continue; fi
      ITEMS+=("$g")
    done < <(find "$f" -type f 2>/dev/null | sort)
  elif [ -f "$f" ]; then ITEMS+=("$f")
  else echo "skip (not found): $f" >&2; fi
done

body_of() {  # item -> redacted text on stdout; returns 1 if refused/binary
  local f=$1
  if [ "$f" = - ]; then redact; return 0; fi
  if refused "$f"; then echo "refused (secret material; use --raw to override): $f" >&2; return 1; fi
  if ! is_text "$f"; then echo "skip (binary): $f" >&2; return 1; fi
  redact <"$f"
}

CHUNK=60000   # paste.rs rejects bodies over about 64 KB (HTTP 500/503)

post_one() {  # file -> prints one URL; retries, then falls back to termbin
  local f=$1 url code out; out=$(mktemp)
  case $SERVICE in
    paste.rs)
      for try in 1 2; do
        code=$(curl -sS -m 30 -o "$out" -w '%{http_code}' --data-binary @"$f" "$PASTE_URL" 2>/dev/null)
        url=$(head -c 200 "$out" | tr -d '\r\n')
        case $code in 2*) break;; esac
        url=""; [ $try = 1 ] && sleep 2
      done
      if [ -z "$url" ] && command -v nc >/dev/null 2>&1; then
        echo "paste.rs failed (HTTP ${code:-none}); trying termbin" >&2
        url=$(nc -w 10 termbin.com 9999 <"$f" | tr -d '\0\r\n')
      fi
      [ -n "$url" ] || echo "upload failed: paste.rs HTTP ${code:-none}" >&2 ;;
    termbin)
      url=$(nc -w 10 termbin.com 9999 <"$f" | tr -d '\0\r\n') ;;
    pastebin)
      if [ -z "${PASTEBIN_DEV_KEY:-}" ]; then echo "set PASTEBIN_DEV_KEY (needs a pastebin account; see rule 7)" >&2
      else url=$(curl -fsS -m 30 https://pastebin.com/api/api_post.php -d api_option=paste \
            -d api_dev_key="$PASTEBIN_DEV_KEY" -d api_paste_private=1 -d api_paste_expire_date=1D \
            --data-urlencode api_paste_code@"$f"); fi ;;
    *) echo "unknown service: $SERVICE" >&2 ;;
  esac
  rm -f "$out"
  case $url in http*) echo "$url";; *) [ -n "$url" ] && echo "upload failed: $url" >&2; return 1;; esac
}

upload() {  # stdin -> prints one URL per part (large input is split at line boundaries)
  local tmp rc=0 n i part; tmp=$(mktemp); cat >"$tmp"
  if [ ! -s "$tmp" ]; then echo "nothing to upload" >&2; rm -f "$tmp"; return 1; fi
  if [ "$(wc -c <"$tmp")" -le "$CHUNK" ] || [ "$SERVICE" != paste.rs ]; then
    post_one "$tmp" || rc=1; rm -f "$tmp"; return $rc
  fi
  # Split into parts of at most CHUNK bytes without cutting a line.
  awk -v max="$CHUNK" -v pre="$tmp.part" '
    { len = length($0) + 1
      if (n == 0 || size + len > max) { n++; size = 0; out = sprintf("%s%03d", pre, n) }
      print > out; size += len }' "$tmp"
  n=$(ls "$tmp".part* | wc -l | tr -d ' '); i=0
  echo "large upload: splitting into $n parts" >&2
  for part in "$tmp".part*; do
    i=$((i+1))
    { printf '[part %d/%d]\n' "$i" "$n"; cat "$part"; } >"$part.h"
    post_one "$part.h" | sed "s|\$| (part $i/$n)|" || rc=1
    rm -f "$part" "$part.h"
  done
  rm -f "$tmp"; return $rc
}

# Box hostnames (iron, redstone) help; a laptop hostname often contains your name.
host=$(hostname 2>/dev/null || echo host); [ "$(uname)" = Darwin ] && host=laptop
# A directory argument is always pasted as one combined paste.
COMBINE=$ONE
for f in "${FILES[@]}"; do [ -d "$f" ] && COMBINE=1; done
if [ "$COMBINE" = 1 ]; then
  # One combined paste with a header per file.
  { for f in "${ITEMS[@]}"; do
      b=$(body_of "$f") || continue
      printf '===== %s:%s =====\n%s\n\n' "$host" "$f" "$b"
    done; } | upload
else
  rc=0
  for f in "${ITEMS[@]}"; do
    b=$(body_of "$f") || { rc=1; continue; }
    printf '%s\n' "$b" | upload | sed "s|\$|  $f|" || rc=1
  done
  exit $rc
fi
