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
  sed -E \
    -e 's/\$(1|2[abxy]?|5|6|7|y|gy|sha1|md5)\$[^:[:space:]]+/<hash-redacted>/g' \
    -e "s/((plaintext|encrypted)-password|password|passwd|secret|pass|pwd)([\"' ]*[=: ][\"' ]*)[^\"'[:space:],;]+/\1\3<redacted>/Ig"
}

is_text() { [ ! -s "$1" ] || LC_ALL=C grep -Iq . "$1" 2>/dev/null; }

# Build the list of (label, file) pairs; directories expand to their text files.
ITEMS=()
for f in "${FILES[@]}"; do
  if [ "$f" = - ]; then ITEMS+=("-"); continue; fi
  if [ -d "$f" ]; then
    while IFS= read -r g; do ITEMS+=("$g"); done < <(find "$f" -type f -size -2M 2>/dev/null | sort)
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

upload() {  # stdin -> prints URL
  local tmp url; tmp=$(mktemp); cat >"$tmp"
  if [ ! -s "$tmp" ]; then echo "nothing to upload" >&2; rm -f "$tmp"; return 1; fi
  if [ "$(wc -c <"$tmp")" -gt 1000000 ]; then echo "warning: over 1 MB, the service may truncate or refuse it" >&2; fi
  case $SERVICE in
    paste.rs)
      url=$(curl -fsS -m 30 --data-binary @"$tmp" "$PASTE_URL") ;;
    termbin)
      url=$(nc -w 10 termbin.com 9999 <"$tmp" | tr -d '\0\r\n') ;;
    pastebin)
      [ -n "${PASTEBIN_DEV_KEY:-}" ] || { echo "set PASTEBIN_DEV_KEY (needs a pastebin account; see rule 7)" >&2; rm -f "$tmp"; return 1; }
      url=$(curl -fsS -m 30 https://pastebin.com/api/api_post.php -d api_option=paste \
            -d api_dev_key="$PASTEBIN_DEV_KEY" -d api_paste_private=1 -d api_paste_expire_date=1D \
            --data-urlencode api_paste_code@"$tmp") ;;
    *) echo "unknown service: $SERVICE" >&2; rm -f "$tmp"; return 1 ;;
  esac
  rm -f "$tmp"
  case $url in http*) echo "$url";; *) echo "upload failed: ${url:-no response}" >&2; return 1;; esac
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
    u=$(printf '%s\n' "$b" | upload) && printf '%s  %s\n' "$u" "$f" || rc=1
  done
  exit $rc
fi
