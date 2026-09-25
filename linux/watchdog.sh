#!/usr/bin/env bash
# watchdog.sh - keep protected services running. Installed by harden.sh as
# /usr/local/sbin/ccdc-watchdog and run every minute by a systemd timer.
# Can also be run by hand: sudo ./watchdog.sh
LIST=/root/ccdc-backup/protected-units.txt
LOG=/var/log/ccdc-watchdog.log
[ -f "$LIST" ] || exit 0

while read -r u; do
  [ -n "$u" ] || continue
  systemctl is-active -q "$u" && continue
  # Something stopped it; if it was also disabled or masked, undo that first.
  systemctl unmask "$u" >/dev/null 2>&1
  systemctl enable "$u" >/dev/null 2>&1
  systemctl restart "$u"
  if systemctl is-active -q "$u"; then r=recovered; else r="STILL DOWN"; fi
  echo "$(date '+%F %T') $u was down -> $r" >>"$LOG"
done <"$LIST"
