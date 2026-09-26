#!/usr/bin/env bash
# backup.sh - snapshot configs and service data on Ubuntu 18.04 / Rocky 9.
# Read-only on the system except for writing the backup directory.
# Usage: sudo ./backup.sh [--share] [dest_dir]
#   --share uploads the state snapshot (state.txt) with share.sh (redacted, public link)
set -uo pipefail

[ "$EUID" -eq 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }
SHARE=0; [ "${1:-}" = --share ] && { SHARE=1; shift; }

TS=$(date +%Y%m%d-%H%M%S)
DEST=${1:-/root/ccdc-backup}/$TS
mkdir -p "$DEST" && chmod 700 "${DEST%/*}" "$DEST"

log() { printf '[%s] %s\n' "$(date +%T)" "$*"; }

# Paths worth keeping if present. Missing ones are skipped.
PATHS=(/etc /var/www /srv /var/ftp /var/mail /var/spool/mail /home /root/.ssh
       /opt/splunkforwarder/etc /opt/splunk/etc /var/spool/cron)

EXISTING=()
for p in "${PATHS[@]}"; do [ -e "$p" ] && EXISTING+=("$p"); done

log "Archiving: ${EXISTING[*]}"
# Exclude the backup dir itself and large Splunk data.
tar --exclude="${DEST%/*}" --exclude='/opt/splunk/var' \
    -czpf "$DEST/files.tar.gz" "${EXISTING[@]}" 2>"$DEST/tar-warnings.txt"
log "Archive: $(du -h "$DEST/files.tar.gz" | cut -f1)"

# Databases (best effort; socket auth as root works on default installs).
if command -v mysqldump >/dev/null 2>&1; then
  if mysqldump --all-databases --single-transaction >"$DEST/mysql-all.sql" 2>/dev/null; then
    log "MySQL/MariaDB dumped"
  else
    rm -f "$DEST/mysql-all.sql"; log "MySQL present but dump failed (needs credentials?)"
  fi
fi
if command -v pg_dumpall >/dev/null 2>&1 && id postgres >/dev/null 2>&1; then
  su - postgres -c pg_dumpall >"$DEST/postgres-all.sql" 2>/dev/null \
    && log "PostgreSQL dumped" || rm -f "$DEST/postgres-all.sql"
fi

# State snapshot for comparing later.
{
  echo "== listeners";  ss -tulpn
  echo "== services";   systemctl list-units --type=service --state=running --no-pager
  echo "== users";      getent passwd
  echo "== groups";     getent group
  echo "== crontabs";   for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | sed "s/^/$u: /"; done
  echo "== firewall";   iptables-save 2>/dev/null; nft list ruleset 2>/dev/null
} >"$DEST/state.txt" 2>&1

( cd "$DEST" && sha256sum ./* >SHA256SUMS )
log "Done: $DEST"
log "Copy off-box:  scp -r root@<ip>:$DEST ."
log "Restore one file:  tar -xzpf $DEST/files.tar.gz -C / etc/ssh/sshd_config"

if [ "$SHARE" = 1 ]; then
  S="$(cd "$(dirname "$0")" && pwd)/share.sh"
  if [ -x "$S" ]; then "$S" "$DEST/state.txt" || log "upload failed"
  else log "share.sh not found next to backup.sh; run: share.sh $DEST/state.txt"; fi
fi
