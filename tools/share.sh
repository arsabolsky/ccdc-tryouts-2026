#!/usr/bin/env bash
# share.sh - upload files (reports, logs, configs) to a paste service.
# Works on Linux, VyOS (as vyos) and macOS. Needs curl (or nc for termbin).
#
#   ./share.sh /root/ccdc-backup/hunt-*.txt     files
#   ./share.sh /etc/ssh/ /var/www/html          folders (their text files, up to 1 MB each)
#   some-command | ./share.sh -                 stdin
#   ./share.sh --one /etc/ssh/sshd_config ...   everything in ONE readable paste (no index)
#
# Each file is its own paste, split into parts of at most 60 KB (paste.rs refuses
# bigger bodies). When there is more than one paste, a final INDEX paste lists every
# file with its size, SHA-256 and part links in order. Rebuild everything on the
# laptop with:   ./fetch.sh <index-link>
#
# Options:
#   --one        combine everything into a single paste (split if large, no index)
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
    -h|--help) sed -n '2,27p' "$0"; exit 0;;
    *) FILES+=("$1");;
  esac; shift
done
[ ${#FILES[@]} -gt 0 ] || { sed -n '2,27p' "$0"; exit 2; }
PASTE_URL=${PASTE_URL:-https://paste.rs/}
CHUNK=60000      # paste.rs rejects bodies over about 64 KB (HTTP 500/503)
DIR_MAX=1048576  # folder uploads skip files over 1 MB (name a file to include it)

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

sha() {  # file -> sha256 hex
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
  else openssl dgst -sha256 "$1" | awk '{print $NF}'; fi
}

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

# Expand folders; "-" (stdin) is read now so it can be hashed and split like a file.
ITEMS=()
for f in "${FILES[@]}"; do
  if [ "$f" = - ]; then cat >"$WORK/stdin.txt"; ITEMS+=("$WORK/stdin.txt"); continue; fi
  if [ -d "$f" ]; then
    while IFS= read -r g; do
      if [ "$(wc -c <"$g")" -gt "$DIR_MAX" ]; then echo "skip (over 1 MB; name it to include it): $g" >&2; continue; fi
      ITEMS+=("$g")
    done < <(find "$f" -type f 2>/dev/null | sort)
  elif [ -f "$f" ]; then ITEMS+=("$f")
  else echo "skip (not found): $f" >&2; fi
done

label_of() { case $1 in "$WORK/stdin.txt") echo stdin.txt;; *) echo "$1";; esac; }

body_to() {  # item outfile -> redacted text in outfile (ends with a newline); 1 if refused/binary
  local f=$1 o=$2
  if [ "$f" != "$WORK/stdin.txt" ]; then
    if refused "$f"; then echo "refused (secret material; use --raw to override): $f" >&2; return 1; fi
    if ! is_text "$f"; then echo "skip (binary): $f" >&2; return 1; fi
  fi
  redact <"$f" >"$o"
  # Normalize to end with a newline so line-based splitting is byte-exact.
  if [ -s "$o" ] && [ "$(tail -c 1 "$o" | od -An -c | tr -d ' ')" != '\n' ]; then echo >>"$o"; fi
}

post_one() {  # file -> prints one URL; retries with backoff, then falls back to termbin
  local f=$1 url="" code="" out="$WORK/resp" try
  case $SERVICE in
    paste.rs)
      for try in 1 2 3; do
        code=$(curl -sS -m 30 -o "$out" -w '%{http_code}' --data-binary @"$f" "$PASTE_URL" 2>/dev/null)
        case $code in 2*) url=$(head -c 200 "$out" | tr -d '\r\n'); break;; esac
        [ $try -lt 3 ] && sleep $((try * 2))
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
  case $url in http*) echo "$url";; *) [ -n "$url" ] && echo "upload failed: $url" >&2; return 1;; esac
}

split_file() {  # file prefix -> parts prefix.0001 ...; at line boundaries, byte-exact
  local f=$1 pre=$2
  # A single line longer than CHUNK (e.g. minified JS) cannot be split by line; cut by bytes.
  if [ "$(LC_ALL=C awk '{ if (length($0) + 1 > m) m = length($0) + 1 } END { print m + 0 }' "$f")" -gt "$CHUNK" ]; then
    split -b "$CHUNK" -a 4 "$f" "$pre."
    return
  fi
  LC_ALL=C awk -v max="$CHUNK" -v pre="$pre" '
    { len = length($0) + 1
      if (n == 0 || size + len > max) { if (out) close(out); n++; size = 0; out = sprintf("%s.%04d", pre, n) }
      print > out; size += len }' "$f"
}

post_parts() {  # file -> prints the part URLs in order, space separated; 1 on any failure
  local f=$1 urls="" u p
  rm -f "$WORK"/p.*
  if [ "$(wc -c <"$f")" -le "$CHUNK" ] || [ "$SERVICE" != paste.rs ]; then post_one "$f"; return; fi
  split_file "$f" "$WORK/p"
  for p in "$WORK"/p.*; do
    u=$(post_one "$p") || return 1
    urls="$urls $u"; sleep 0.3
  done
  echo "${urls# }"
}

# Box hostnames (iron, redstone) help; a laptop hostname often contains your name.
host=$(hostname 2>/dev/null || echo host); [ "$(uname)" = Darwin ] && host=laptop

# --one: a single readable paste with a header per file (no index).
if [ "$ONE" = 1 ]; then
  : >"$WORK/all"
  for f in "${ITEMS[@]}"; do
    body_to "$f" "$WORK/b" || continue
    { printf '===== %s:%s =====\n' "$host" "$(label_of "$f")"; cat "$WORK/b"; echo; } >>"$WORK/all"
  done
  [ -s "$WORK/all" ] || { echo "nothing to upload" >&2; exit 1; }
  urls=$(post_parts "$WORK/all") || exit 1
  set -- $urls
  if [ $# -eq 1 ]; then echo "$1"; else i=0; for u in "$@"; do i=$((i+1)); echo "$u (part $i/$#)"; done; fi
  exit 0
fi

# Default: one paste (or parts) per file, then an index paste if there is more than one.
INDEX="$WORK/index"; rc=0; nposts=0; nfiles=0; first=""
for f in "${ITEMS[@]}"; do
  label=$(label_of "$f")
  body_to "$f" "$WORK/b" || { rc=1; continue; }
  bytes=$(wc -c <"$WORK/b" | tr -d ' ')
  if [ "$bytes" -eq 0 ]; then urls="-"
  else
    urls=$(post_parts "$WORK/b") || { echo "FAILED: $label" >&2; rc=1; continue; }
  fi
  set -- $urls; [ "$urls" = - ] && set --
  nposts=$((nposts + $#)); nfiles=$((nfiles + 1)); [ -z "$first" ] && first=$urls
  echo "  $label  ($bytes bytes, $# part(s))" >&2
  printf '%s\t%s\t%s\t%s\n' "$label" "$bytes" "$(sha "$WORK/b")" "$urls" >>"$INDEX.body"
done
[ "$nfiles" -gt 0 ] || { echo "nothing uploaded" >&2; exit 1; }

if [ "$nposts" -le 1 ] && [ "$nfiles" -eq 1 ]; then
  echo "$first"     # one small file: its own link is enough
  exit $rc
fi

{ echo "# ccdc-share index v1"
  echo "# host=$host created=$(date -u +%Y-%m-%dT%H:%M:%SZ) files=$nfiles pastes=$nposts"
  echo "# rebuild with: fetch.sh <this-link>"
  echo "# file<TAB>bytes<TAB>sha256<TAB>part links in order"
  cat "$INDEX.body"; } >"$INDEX"
iurls=$(post_parts "$INDEX") || { echo "index upload failed; per-file lines are in the output above" >&2; exit 1; }
set -- $iurls
echo "INDEX: $*"
echo "rebuild on the laptop: ./fetch.sh $*"
exit $rc
