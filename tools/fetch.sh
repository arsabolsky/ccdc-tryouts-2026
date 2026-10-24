#!/usr/bin/env bash
# fetch.sh - rebuild files uploaded with share.sh / share.ps1 from their INDEX link.
# Runs on your laptop (macOS/Linux). Needs curl.
#
#   ./fetch.sh https://paste.rs/AbCd                 rebuild into ./ccdc-fetch-<host>-<time>/
#   ./fetch.sh -o ./iron-ssh https://paste.rs/AbCd   choose the output folder
#   ./fetch.sh <index-part-1> <index-part-2>         an index that was itself split
#
# Each file is reassembled from its parts in order and checked against the size and
# SHA-256 recorded in the index; a file that does not match is reported, not written.
# A plain (non-index) paste link is simply saved as a file.
set -uo pipefail

OUT=""
while [ $# -gt 0 ]; do
  case $1 in -o) OUT=${2:?}; shift;; -h|--help) sed -n '2,12p' "$0"; exit 0;; *) break;; esac; shift
done
[ $# -gt 0 ] || { sed -n '2,12p' "$0"; exit 2; }

sha() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
  else openssl dgst -sha256 "$1" | awk '{print $NF}'; fi
}
get() {  # url outfile -> 0 on success; retries
  local try
  for try in 1 2 3; do curl -fsS -m 30 -o "$2" "$1" 2>/dev/null && return 0; sleep $((try * 2)); done
  return 1
}

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
: >"$WORK/index"
for u in "$@"; do
  get "$u" "$WORK/i" || { echo "could not download $u" >&2; exit 1; }
  cat "$WORK/i" >>"$WORK/index"
done

# Not an index: save the paste as-is.
if ! head -1 "$WORK/index" | grep '^# ccdc-share index v1' >/dev/null; then
  name="paste-$(basename "$1" | tr -cd 'A-Za-z0-9._-').txt"
  OUT=${OUT:-.}; mkdir -p "$OUT"; cp "$WORK/index" "$OUT/$name"
  echo "not a share.sh index; saved the paste as $OUT/$name"; exit 0
fi

# The index comes from the network: keep the host name to safe characters.
host=$(sed -n 's/^# host=\([^ ]*\).*/\1/p' "$WORK/index" | head -1 | tr -cd 'A-Za-z0-9_-')
OUT=${OUT:-./ccdc-fetch-${host:-box}-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$OUT"
echo "rebuilding into $OUT"

ok=0; bad=0
while IFS=$'\t' read -r path bytes want urls; do
  case $path in ''|'#'*) continue;; esac
  # Never write outside OUT: drop leading slashes, refuse any ".." component.
  rel=${path#"${path%%[!/]*}"}
  case "/$rel/" in *'/../'*|'//') echo "  REFUSED (unsafe path): $path"; bad=$((bad+1)); continue;; esac
  : >"$WORK/f"; fail=""
  if [ "$urls" != - ]; then
    for u in $urls; do
      case $u in http://*|https://*) ;; *) fail="bad link $u"; break;; esac
      get "$u" "$WORK/p" || { fail="part missing: $u"; break; }
      cat "$WORK/p" >>"$WORK/f"
    done
  fi
  if [ -z "$fail" ]; then
    got=$(wc -c <"$WORK/f" | tr -d ' ')
    if [ "$got" != "$bytes" ]; then fail="size $got, expected $bytes"
    elif [ "$(sha "$WORK/f")" != "$want" ]; then fail="SHA-256 mismatch"; fi
  fi
  if [ -n "$fail" ]; then echo "  BAD  $path  ($fail)"; bad=$((bad+1)); continue; fi
  mkdir -p "$OUT/$(dirname "$rel")" && cp "$WORK/f" "$OUT/$rel"
  echo "  ok   $path  ($bytes bytes)"; ok=$((ok+1))
done <"$WORK/index"

echo "$ok file(s) rebuilt and verified, $bad problem(s). Output: $OUT"
[ "$bad" -eq 0 ]
