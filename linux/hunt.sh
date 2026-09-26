#!/usr/bin/env bash
# hunt.sh - read-only threat hunt for Ubuntu 18.04 / Rocky 9. Changes nothing
# except writing its report and a hash baseline under /root/ccdc-backup.
#
#   sudo ./hunt.sh                 everything, "recent" = last 24 hours
#   sudo ./hunt.sh --since 3       "recent" = last 3 hours
#   sudo ./hunt.sh --full          also verify every installed package (slow)
#   add --share to upload the report with share.sh (redacted, public link)
#
# Checks: tampered binaries (package checksums, wrapper scripts, hash baseline),
# PAM and shell hijacks, immutable files, shell history, login and auth logs,
# log tampering, web logs, recently changed files.
set -uo pipefail

SINCE=24; FULL=0; SHARE=0
while [ $# -gt 0 ]; do
  case $1 in --since) SINCE=${2:?}; shift;; --full) FULL=1;; --share) SHARE=1;; esac; shift
done
HERE=$(cd "$(dirname "$0")" && pwd)
[ "$EUID" -eq 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }

STATE=/root/ccdc-backup
mkdir -p "$STATE" && chmod 700 "$STATE"
REPORT=$STATE/hunt-$(date +%Y%m%d-%H%M%S).txt
# A bad /etc/ld.so.preload makes every command print an ld.so error; it is
# flagged once below, so drop the repeats from the report.
exec > >(grep --line-buffered -v 'ld.so: object' | tee -a "$REPORT") 2>&1

if [ -t 1 ]; then R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[1m'; N=$'\e[0m'; else R='' G='' Y='' B='' N=''; fi
hdr()  { printf '\n%s== %s ==%s\n' "$B" "$*" "$N"; }
good() { printf '  %s[ok]%s %s\n' "$G" "$N" "$*"; }
# flag() is often called inside "| while read" subshells, so count in a file.
FLAGFILE=$(mktemp); trap 'rm -f "$FLAGFILE" "${AUTHCACHE:-}"' EXIT
flag() { printf '  %s[!!]%s %s\n' "$R" "$N" "$*"; echo x >>"$FLAGFILE"; }
note() { printf '  %s[--]%s %s\n' "$Y" "$N" "$*"; }

. /etc/os-release
case $ID in ubuntu|debian) FAM=deb;; *) FAM=rpm;; esac
MIN=$((SINCE*60))

# Commands red team likes to replace or wrap.
CRITICAL="passwd su sudo login sshd ssh chpasswd useradd usermod userdel chage gpasswd
          ps ls ss netstat top find lsof bash sh dash systemctl crontab id who w last
          getent kill pkill cat grep awk sed tar curl wget ip iptables nft"

alt_path() {  # merged /usr: dpkg may list /usr/bin/x as /bin/x (or the reverse)
  case $1 in /usr/bin/*|/usr/sbin/*|/usr/lib*) echo "${1#/usr}";; /bin/*|/sbin/*|/lib*) echo "/usr$1";; *) echo "$1";; esac
}
owner_pkg() {  # path -> package name or empty
  if [ $FAM = deb ]; then
    { dpkg -S "$1" 2>/dev/null || dpkg -S "$(alt_path "$1")" 2>/dev/null; } | head -1 | cut -d: -f1
  else rpm -qf "$1" 2>/dev/null | grep -v 'not owned' | head -1; fi
}
verify_file() {  # path -> prints the verify line if the file differs from its package
  if [ $FAM = deb ]; then
    local pkg; pkg=$(owner_pkg "$1"); [ -n "$pkg" ] || return
    dpkg --verify "$pkg" 2>/dev/null | awk -v f="$1" -v g="$(alt_path "$1")" '($NF==f || $NF==g) && $2!="c"'
  else
    rpm -Vf "$1" 2>/dev/null | awk -v f="$1" '$NF==f && $2!="c"'
  fi
}

pkg_unmodified() {  # file -> 0 if a package owns it and it is byte-for-byte unchanged (config files included)
  local pkg; pkg=$(owner_pkg "$1"); [ -n "$pkg" ] || return 1
  if [ $FAM = deb ]; then [ -z "$(dpkg --verify "$pkg" 2>/dev/null | awk -v f="$1" -v g="$(alt_path "$1")" '$NF==f || $NF==g')" ]
  else [ -z "$(rpm -Vf "$1" 2>/dev/null | awk -v f="$1" '$NF==f')" ]; fi
}
drop_distro_defaults() {  # stdin "file:line:text" -> only lines from edited or unpackaged files
  local l f
  while IFS= read -r l; do f=${l%%:*}; pkg_unmodified "$f" || printf '%s\n' "$l"; done
}

# ------------------------------------------------------------- binaries ----
hunt_binaries() {
  hdr "Critical binaries (package checksum, file type, owner)"
  local c p real line
  for c in $CRITICAL; do
    p=$(type -P "$c" 2>/dev/null) || continue
    real=$(readlink -f "$p")
    # A script where an ELF binary belongs is a classic wrapper backdoor.
    if [ "$(head -c4 "$real" 2>/dev/null | od -An -c | tr -d ' ')" != '177ELF' ]; then
      # coreutils-single (minimal RHEL/Rocky) ships these stubs; the checksum check below still verifies them.
      if ! head -1 "$real" | grep -qx "#!/usr/bin/coreutils --coreutils-prog-shebang=$(basename "$real")"; then
        case $c in sh|dash|bash) ;; *) flag "$c ($real) is not an ELF binary: $(head -c 60 "$real" | tr '\n' ' ')";; esac
      fi
    fi
    if [ -z "$(owner_pkg "$real")" ] && [ -z "$(owner_pkg "$p")" ]; then
      flag "$c ($real) is not owned by any package"; continue
    fi
    line=$(verify_file "$real"); [ -n "$line" ] || line=$(verify_file "$p")
    [ -n "$line" ] && flag "$c differs from its package: $line"
    [ -u "$real" ] && case $c in passwd|su|sudo|chage|gpasswd|mount|umount|newgrp|chsh|chfn|pkexec|crontab) ;; *) flag "$c ($real) is setuid";; esac
  done
  good "checked: $(echo $CRITICAL | wc -w) commands (lines above are problems)"

  hdr "Hash baseline of critical binaries"
  local base=$STATE/binhash.txt now; now=$(mktemp)
  for c in $CRITICAL; do p=$(type -P "$c" 2>/dev/null) && sha256sum "$(readlink -f "$p")"; done 2>/dev/null | sort -k2 -u >"$now"
  if [ ! -s "$base" ]; then
    cp "$now" "$base"; note "baseline saved to $base. Later runs compare against it."
  else
    local d; d=$(diff <(sort -k2 "$base") "$now" | grep '^>' | awk '{print $3}')
    if [ -n "$d" ]; then for f in $d; do flag "changed since baseline: $f"; done; else good "no changes since baseline"; fi
  fi
  rm -f "$now"

  hdr "Files in bin/sbin dirs not owned by any package"
  local n=0 f
  while read -r f; do
    case $f in /usr/local/*) note "local file: $f"; continue;; esac
    if [ -z "$(owner_pkg "$f")" ]; then flag "unowned: $f ($(stat -c '%y' "$f" | cut -d. -f1))"; n=$((n+1)); fi
    [ $n -ge 40 ] && { note "stopping after 40"; break; }
  done < <(find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -maxdepth 1 -type f 2>/dev/null)
  [ $n = 0 ] && good "none"

  hdr "SUID/SGID files not owned by a package"
  n=0
  while read -r f; do
    [ -z "$(owner_pkg "$f")" ] && { flag "setuid/setgid and unowned: $f"; n=$((n+1)); }
  done < <(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null)
  [ $n = 0 ] && good "none"

  if [ $FULL = 1 ]; then
    hdr "Full package verification (binaries and libraries only)"
    if [ $FAM = deb ]; then dpkg --verify 2>/dev/null; else rpm -Va 2>/dev/null; fi \
      | awk '$2!="c"' | grep -E ' /(usr/)?(s?bin|lib[^ ]*)/' | grep -v '^\.\.\.\.\.\.\.T' | while read -r l; do flag "$l"; done
  fi
}

# ----------------------------------------------------------- hijacks -------
hunt_hijacks() {
  hdr "PAM (login stack backdoors)"
  local f
  grep -HnE '^\s*[^#].*pam_exec\.so' /etc/pam.d/* 2>/dev/null | drop_distro_defaults | while read -r l; do flag "pam_exec: $l"; done
  grep -HnE '^\s*auth\s+.*pam_permit\.so' /etc/pam.d/* 2>/dev/null | drop_distro_defaults | while read -r l; do
    note "pam_permit in an auth stack (normal only in a few distro files): $l"; done
  while read -r f; do
    [ -z "$(owner_pkg "$f")" ] && flag "PAM module not from a package: $f"
    local v; v=$(verify_file "$f"); [ -n "$v" ] && flag "PAM module modified: $v"
  done < <(find /lib/security /lib64/security /usr/lib64/security /lib/x86_64-linux-gnu/security /usr/lib/x86_64-linux-gnu/security /lib/aarch64-linux-gnu/security /usr/lib/aarch64-linux-gnu/security -name '*.so' 2>/dev/null)
  good "PAM checked"

  hdr "Preload and environment hijacks"
  [ -s /etc/ld.so.preload ] && flag "/etc/ld.so.preload: $(tr '\n' ' ' </etc/ld.so.preload)" || good "/etc/ld.so.preload empty"
  grep -HnE 'LD_PRELOAD|LD_LIBRARY_PATH' /etc/environment /etc/profile /etc/profile.d/* /etc/bash.bashrc /etc/bashrc \
    /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile 2>/dev/null | while read -r l; do flag "$l"; done

  hdr "Aliases/functions that shadow commands, PROMPT_COMMAND, traps"
  local rc=(/etc/profile /etc/profile.d/*.sh /etc/bash.bashrc /etc/bashrc /root/.bashrc /root/.bash_profile /root/.profile
            /home/*/.bashrc /home/*/.bash_profile /home/*/.profile /home/*/.bash_logout /root/.bash_logout)
  local pat='^\s*(alias\s+(sudo|su|passwd|ls|ps|ss|netstat|cat|cd|ssh|who|w|last|kill|systemctl|crontab)=|(function\s+)?(sudo|su|passwd|ls|ps|ss|netstat|cat|cd|ssh|who|w|last|kill|systemctl|crontab)\s*\(\)|PROMPT_COMMAND=|trap\s)'
  local hit
  hit=$(grep -HnE "$pat" "${rc[@]}" 2>/dev/null | grep -vE "alias ls='ls --color|alias ls='ls -" | drop_distro_defaults)
  if [ -n "$hit" ]; then echo "$hit" | while read -r l; do flag "$l"; done; else good "none"; fi

  hdr "Immutable/append-only files (can block your fixes)"
  if command -v lsattr >/dev/null; then
    hit=$(lsattr -d /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/ssh/sshd_config /root/.ssh /root/.ssh/* \
          /home/*/.ssh /home/*/.ssh/* /etc/crontab /etc/ld.so.preload 2>/dev/null | awk '$1 ~ /[ia]/')
    if [ -n "$hit" ]; then echo "$hit" | while read -r l; do flag "$l  (clear with: chattr -i -a <file>)"; done; else good "none"; fi
  fi
}

# ----------------------------------------------------------- history -------
SUS='(wget|curl)[^|]*\|\s*(ba)?sh|/dev/tcp/|/dev/udp/|\bnc\b.*-[a-z]*e|ncat|socat|bash -i|python[23]? -c|perl -e|base64 (-d|--decode)|chmod [0-7]*[4-7][0-7]{3}|chmod [ug]\+s|useradd|adduser|usermod|passwd|chpasswd|visudo|/etc/sudoers|authorized_keys|ssh-keygen|crontab|systemctl (stop|disable|mask)|iptables -F|nft flush|ufw disable|setenforce 0|history -c|unset HISTFILE|HISTFILE=|HISTSIZE=0|rm .*(\.bash_history|/var/log)|shred|> ?/var/log|chattr|insmod|LD_PRELOAD|/tmp/|/dev/shm/'

hunt_history() {
  hdr "Shell history files"
  local h f u sz
  for h in /root /home/*; do
    [ -d "$h" ] || continue
    u=$(stat -c %U "$h")
    for f in "$h"/.bash_history "$h"/.zsh_history "$h"/.sh_history "$h"/.ash_history "$h"/.python_history "$h"/.mysql_history "$h"/.lesshst; do
      if [ -L "$f" ]; then flag "$f is a symlink to $(readlink "$f") (history disabled)"; continue; fi
      [ -e "$f" ] || continue
      sz=$(stat -c %s "$f")
      if [ "$sz" -eq 0 ]; then note "$f is empty (modified $(stat -c %y "$f" | cut -d. -f1))"; continue; fi
      echo "  -- $f ($u, $(wc -l <"$f") lines, modified $(stat -c %y "$f" | cut -d. -f1))"
      grep -nE "$SUS" "$f" 2>/dev/null | tail -40 | while read -r l; do flag "$(basename "$h"):$l"; done
    done
    [ -e "$h/.bash_history" ] || note "$h has no .bash_history"
  done

  hdr "History disabled in shell startup files"
  local hit
  hit=$(grep -HnE 'HISTFILE=/dev/null|unset HISTFILE|HISTSIZE=0|HISTFILESIZE=0|set \+o history' \
        /etc/profile /etc/profile.d/* /etc/bash.bashrc /etc/bashrc /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile 2>/dev/null | drop_distro_defaults)
  if [ -n "$hit" ]; then echo "$hit" | while read -r l; do flag "$l"; done; else good "none"; fi

  hdr "Last 15 commands of root and admins"
  for h in /root /home/steve /home/alex; do
    [ -s "$h/.bash_history" ] || continue
    echo "  -- $h"; tail -15 "$h/.bash_history" | sed 's/^/     /'
  done
}

# -------------------------------------------------------------- logs -------
AUTH=/var/log/auth.log; [ -f $AUTH ] || AUTH=/var/log/secure

# Read the auth log once, in the main shell (authlog runs inside pipelines).
AUTHCACHE=$(mktemp)
if [ -s "$AUTH" ]; then cat "$AUTH" "$AUTH.1" >"$AUTHCACHE" 2>/dev/null
else journalctl --no-pager -q --since "-${SINCE}h" _COMM=sshd + _COMM=sudo + _COMM=su + _COMM=useradd \
       + _COMM=usermod + _COMM=passwd + _COMM=chpasswd >"$AUTHCACHE" 2>/dev/null; fi
authlog() { cat "$AUTHCACHE"; }

hunt_logs() {
  hdr "Log health (tampering checks)"
  local f
  for f in "$AUTH" /var/log/wtmp /var/log/btmp /var/log/lastlog /var/log/syslog /var/log/messages; do
    [ -e "$f" ] || { case $f in /var/log/syslog|/var/log/messages) ;; *) note "$f missing";; esac; continue; }
    if [ ! -s "$f" ]; then
      case $f in /var/log/btmp) note "$f is empty (normal if no failed logins yet)";; *) flag "$f is empty (cleared?)";; esac
    else good "$f $(du -h "$f" | cut -f1), last written $(stat -c %y "$f" | cut -d. -f1)"; fi
  done
  for s in rsyslog systemd-journald auditd; do
    systemctl cat "$s.service" >/dev/null 2>&1 || continue   # not installed
    systemctl is-active -q "$s" && good "$s running" || flag "$s is not running"
  done
  [ -d /var/log/journal ] || note "journal is not persistent (lost on reboot)"
  local first; first=$(journalctl --no-pager -q -o short-iso 2>/dev/null | head -1 | cut -d' ' -f1)
  [ -n "$first" ] && note "oldest journal entry: $first (a very recent oldest entry can mean the journal was wiped)"

  hdr "Failed logins by user and source (top 15)"
  authlog | grep -E 'Failed password|authentication failure|Invalid user' \
    | sed -nE 's/.*(Failed password for (invalid user )?|Invalid user )([^ ]+) from ([0-9a-fA-F:.]+).*/\3 \4/p' \
    | sort | uniq -c | sort -rn | head -15 | sed 's/^/  /'

  hdr "Successful logins"
  authlog | grep -E 'Accepted (password|publickey|keyboard)' | tail -25 \
    | sed -nE 's/^(.{15}).*Accepted ([a-z-]+) for ([^ ]+) from ([^ ]+).*/  \1  \3 from \4 (\2)/p'
  grep -qE 'Accepted publickey' "$AUTHCACHE" && note "key-based logins seen: check for planted authorized_keys"

  hdr "Failed-then-successful from the same source (brute force that worked)"
  local ips; ips=$(authlog | sed -nE 's/.*Failed password.* from ([0-9a-fA-F:.]+).*/\1/p' | sort | uniq -c | awk '$1>=5{print $2}')
  local hit=0 ip
  for ip in $ips; do
    grep -q "Accepted .* from $ip " "$AUTHCACHE" && { flag "$ip: 5+ failures then a successful login"; hit=1; }
  done
  [ $hit = 0 ] && good "none"

  hdr "sudo and su"
  authlog | grep -E 'sudo:.*COMMAND=' | tail -25 | sed -nE 's/^(.{15}).*sudo:\s+([^ ]+) :.*USER=([^ ;]+).*COMMAND=(.*)/  \1  \2 -> \3: \4/p'
  authlog | grep -E "su(\[[0-9]+\])?: .*(session opened|Successful su)" | tail -10 | sed 's/^/  /'

  hdr "Account and password changes"
  authlog | grep -E 'useradd|userdel|usermod|groupadd|gpasswd|passwd\[|chpasswd|password changed|new user|new group|add .* to group' \
    | tail -30 | sed 's/^/  /'

  hdr "Login history (wtmp) and failed logins (btmp)"
  last -F -n 20 2>/dev/null | sed 's/^/  /'
  echo "  -- lastb (top sources)"; lastb 2>/dev/null | awk 'NF>2{print $1, $3}' | sort | uniq -c | sort -rn | head -10 | sed 's/^/  /'
  echo "  -- lastlog (users who have ever logged in)"; lastlog 2>/dev/null | grep -v 'Never logged in' | sed 's/^/  /'

  hdr "Web access logs"
  local wl
  for wl in /var/log/apache2/access.log /var/log/httpd/access_log /var/log/nginx/access.log; do
    [ -s "$wl" ] || continue
    echo "  -- $wl: top clients"; awk '{print $1}' "$wl" | sort | uniq -c | sort -rn | head -5 | sed 's/^/  /'
    # wget/curl only inside the request line: a curl user agent is normal (scorecheck.sh uses curl).
    grep -iE 'cmd=|exec=|system\(|passthru|shell_exec|base64_|/\.\./|%2e%2e|union.*select|/etc/passwd|\.php\?[a-z]=|"[a-z]+ [^"]*(wget|curl)|nikto|sqlmap|gobuster|dirb' "$wl" \
      | tail -20 | while read -r l; do flag "${l:0:180}"; done
    echo "  -- POSTs to scripts"; grep -E '"POST [^"]*\.(php|cgi|jsp|aspx?)' "$wl" | awk '{print $1, $7}' | sort | uniq -c | sort -rn | head -10 | sed 's/^/  /'
  done
}

# ------------------------------------------------------- recent files ------
hunt_recent() {
  hdr "Files changed in the last ${SINCE}h in sensitive places"
  find /etc /bin /sbin /usr/bin /usr/sbin /usr/local /lib/systemd /usr/lib/systemd /etc/systemd \
       /var/spool/cron /etc/cron* /root /home /var/www /srv /tmp /var/tmp /dev/shm \
       -xdev -type f -mmin -"$MIN" 2>/dev/null \
    | grep -vE '/ccdc-backup/|\.cache/|/\.bash_history$|/etc/ld\.so\.cache$|/etc/mtab$' \
    | head -80 | while read -r f; do printf '  %s  %s\n' "$(stat -c '%y' "$f" | cut -d. -f1)" "$f"; done

  hdr "Executables in temp dirs"
  local hit
  hit=$(find /tmp /var/tmp /dev/shm -xdev -type f \( -perm -u+x -o -name '*.sh' -o -name '*.elf' -o -name '.*' \) 2>/dev/null | head -30)
  if [ -n "$hit" ]; then echo "$hit" | while read -r f; do flag "$f ($(stat -c %U "$f"), $(file -b "$f" 2>/dev/null | cut -c1-40))"; done; else good "none"; fi
}

hunt_binaries
hunt_hijacks
hunt_history
hunt_logs
hunt_recent
hdr "Summary"
FLAGS=$(wc -l <"$FLAGFILE" | tr -d ' ')
if [ "$FLAGS" -gt 0 ]; then flag "$FLAGS item(s) flagged. Screenshot the evidence before removing anything (for incident reports)."
else good "nothing flagged"; fi
echo "  Report saved: $REPORT"

if [ "$SHARE" = 1 ]; then
  hdr "Share report (--share)"
  sleep 1   # let tee finish writing the report
  if [ -x "$HERE/share.sh" ]; then "$HERE/share.sh" "$REPORT" || note "upload failed; the report is still at $REPORT"
  else note "share.sh not found in $HERE; download it there and run: $HERE/share.sh $REPORT"; fi
fi
