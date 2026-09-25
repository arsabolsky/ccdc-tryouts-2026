#!/usr/bin/env bash
# harden.sh - audit and harden Ubuntu 18.04 / Rocky 9 for the tryout.
#
#   sudo ./harden.sh audit                 read-only report (default)
#   sudo ./harden.sh harden                asks before every step
#   sudo ./harden.sh harden --yes          runs the safe steps without asking
#   sudo ./harden.sh harden --yes --firewall   ...also applies the host firewall
#   sudo ./harden.sh restore-firewall      undo the firewall step
#
# Rules this script follows (from the team packet):
#   - never deletes the listed users, never blocks by source IP
#   - never touches Splunk forwarder outputs; outbound traffic stays open
#   - never changes auth settings of scored services (no forced TLS, no chroot)
set -uo pipefail

MODE=${1:-audit}; shift || true
YES=0; FIREWALL=0
for a in "$@"; do case $a in --yes) YES=1;; --firewall) FIREWALL=1;; esac; done

[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)." >&2; exit 1; }

HERE=$(cd "$(dirname "$0")" && pwd)
STATE=/root/ccdc-backup
mkdir -p "$STATE" && chmod 700 "$STATE"
LOG=$STATE/harden-$(date +%Y%m%d-%H%M%S).log
exec > >(tee -a "$LOG") 2>&1

ADMINS="steve alex"
USERS="steve alex enderman creeper villager zombie enderdragon irongolem chickenjockey ghast"
# Accounts that may have a shell but must not be locked (services).
SERVICE_OK="root splunk splunkfwd sync"
# Ports that belong to scored services (plus Splunk on redstone).
SCORED_TCP="21 22 53 80 110 443 995 8000 9997"
SCORED_UDP="53"

if [ -t 1 ]; then R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[1m'; N=$'\e[0m'; else R='' G='' Y='' B='' N=''; fi
hdr()  { printf '\n%s== %s ==%s\n' "$B" "$*" "$N"; }
info() { printf '  %s\n' "$*"; }
good() { printf '  %s[ok]%s %s\n' "$G" "$N" "$*"; }
flag() { printf '  %s[!!]%s %s\n' "$R" "$N" "$*"; }
note() { printf '  %s[--]%s %s\n' "$Y" "$N" "$*"; }

# ask "question" -> 0 to proceed. Audit mode never proceeds.
ask() {
  [ "$MODE" = harden ] || return 1
  [ "$YES" = 1 ] && { info "-> $1 (auto)"; return 0; }
  local r; read -r -p "  ?? $1 [y/N] " r </dev/tty; [[ $r =~ ^[Yy] ]]
}

. /etc/os-release
case $ID in ubuntu|debian) FAM=deb;; rocky|rhel|centos|almalinux|fedora) FAM=rpm;; *) FAM=unknown;; esac
SUDO_GRP=$([ $FAM = rpm ] && echo wheel || echo sudo)

# ---------------------------------------------------------------- audit ----
listeners() { ss -H -tulpn 2>/dev/null; }

audit_all() {
  hdr "System: $PRETTY_NAME  ($(hostname))"

  hdr "Listening ports"
  listeners | awk '{printf "  %-5s %-28s %s\n",$1,$5,$7}'

  hdr "Users with a login shell"
  while IFS=: read -r u _ uid _ _ _ shell; do
    case $shell in */nologin|*/false|"") continue;; esac
    if [ "$uid" = 0 ] && [ "$u" != root ]; then flag "$u has UID 0 (root equivalent)"; continue; fi
    if [[ " $USERS $SERVICE_OK " == *" $u "* ]]; then good "$u (uid $uid)"
    elif [ "$uid" -ge 1000 ] || [ "$uid" = 0 ]; then flag "$u (uid $uid) is not on the packet's user list"
    else note "$u (uid $uid, system account with shell $shell)"; fi
  done </etc/passwd

  hdr "Admin group members ($SUDO_GRP, admin, root)"
  for g in $SUDO_GRP admin root; do
    local m; m=$(getent group "$g" | cut -d: -f4); [ -n "$m" ] || continue
    for u in ${m//,/ }; do
      if [[ " $ADMINS " == *" $u "* ]]; then good "$g: $u"; else flag "$g: $u should not be an admin"; fi
    done
  done

  hdr "Sudoers entries"
  grep -hEv '^\s*(#|$|Defaults)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | sed 's/^/  /'
  grep -qhE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/* 2>/dev/null && flag "NOPASSWD entries present"

  hdr "SSH authorized_keys files"
  local found=0
  for f in /root/.ssh/authorized_keys* /home/*/.ssh/authorized_keys*; do
    [ -s "$f" ] || continue; found=1; flag "$f ($(grep -c . "$f") keys)"
  done
  [ $found = 0 ] && good "none"

  hdr "sshd effective settings"
  sshd -T 2>/dev/null | grep -Ei '^(permitrootlogin|passwordauthentication|permitemptypasswords|authorizedkeysfile|port) ' | sed 's/^/  /'

  hdr "Scheduled jobs"
  for u in $(cut -d: -f1 /etc/passwd); do
    crontab -l -u "$u" 2>/dev/null | grep -Ev '^\s*(#|$)' | sed "s/^/  [$u] /"
  done
  grep -hEv '^\s*(#|$|SHELL|PATH|MAILTO)' /etc/crontab /etc/cron.d/* 2>/dev/null | sed 's/^/  [system] /'
  systemctl list-timers --all --no-pager 2>/dev/null | sed -n '2,20p' | sed 's/^/  /'

  hdr "Common persistence spots"
  [ -s /etc/ld.so.preload ] && flag "/etc/ld.so.preload is set: $(cat /etc/ld.so.preload)" || good "/etc/ld.so.preload empty"
  [ -s /etc/rc.local ] && note "/etc/rc.local has content (review it)"
  local recent
  recent=$(find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system -type f -name '*.service' -mtime -7 2>/dev/null)
  [ -n "$recent" ] && { note "service units changed in the last 7 days:"; echo "$recent" | sed 's/^/     /'; }

  hdr "Processes running from temp dirs or deleted binaries"
  local hit=0
  for p in /proc/[0-9]*; do
    local exe; exe=$(readlink "$p/exe" 2>/dev/null) || continue
    case $exe in /tmp/*|/var/tmp/*|/dev/shm/*|*"(deleted)") hit=1
      flag "pid ${p#/proc/} $exe  [$(tr '\0' ' ' <"$p/cmdline" | cut -c1-80)]";; esac
  done
  [ $hit = 0 ] && good "none"

  hdr "Package integrity of login-critical files"
  if [ $FAM = deb ]; then
    dpkg --verify openssh-server libpam-modules libpam-runtime passwd login sudo 2>/dev/null | grep -v ' c ' | grep -v ' /usr/share/' | sed 's/^/  [!!] /' || true
  else
    rpm -V openssh-server pam passwd sudo shadow-utils 2>/dev/null | grep -v ' c ' | grep -v ' /usr/share/' | sed 's/^/  [!!] /' || true
  fi
  info "(no lines above = binaries match the packages)"

  hdr "Scored-service login settings (the scorer needs plain logins)"
  if command -v doveconf >/dev/null 2>&1; then
    local d; d=$(doveconf -h disable_plaintext_auth 2>/dev/null)
    [ "$d" = yes ] && flag "dovecot disable_plaintext_auth=yes: remote POP3 logins without TLS are refused" \
                   || good "dovecot allows plaintext POP3 logins"
    [ "$(doveconf -h ssl 2>/dev/null)" = required ] && flag "dovecot ssl=required: plain POP3 logins are refused"
  fi
  local c
  for c in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do
    [ -f $c ] || continue
    grep -qE '^\s*force_local_(logins|data)_ssl\s*=\s*YES' $c && flag "vsftpd forces TLS ($c): plain FTP logins fail" \
      || good "vsftpd does not force TLS"
    grep -qE '^\s*local_enable\s*=\s*YES' $c || flag "vsftpd local_enable is not YES: user logins disabled"
  done

  hdr "Splunk forwarder"
  if [ -x /opt/splunkforwarder/bin/splunk ]; then
    pgrep -f splunkd >/dev/null && good "splunkd running" || flag "forwarder installed but not running"
  else note "no forwarder at /opt/splunkforwarder"; fi
}

# ------------------------------------------------------------- harden ------
PROTECTED=$STATE/protected-units.txt

record_protected() {
  # Services that own a listening port now; the verify step and the
  # watchdog keep these running.
  : >"$PROTECTED.tmp"
  listeners | grep -oP 'pid=\K[0-9]+' | sort -u | while read -r pid; do
    local u; u=$(ps -o unit= -p "$pid" 2>/dev/null | tr -d ' ')
    case $u in *.service) echo "$u";; esac
  done | sort -u >"$PROTECTED.tmp"
  for u in splunk.service splunkd.service SplunkForwarder.service splunkforwarder.service; do
    systemctl is-active -q "$u" 2>/dev/null && echo "$u" >>"$PROTECTED.tmp"
  done
  sort -u "$PROTECTED.tmp" >"$PROTECTED"; rm -f "$PROTECTED.tmp"
  info "protected services: $(tr '\n' ' ' <"$PROTECTED")"
}

step_backup() {
  hdr "Backup"
  "$HERE/backup.sh" "$STATE" | sed 's/^/  /'
  BK=$(ls -dt "$STATE"/20* | head -1)
}

step_passwords() {
  hdr "Passwords"
  ask "Set one new password for all listed users (and root)?" || return
  local p1 p2
  while [ -n "${CCDC_PASSWORD:-}" ]; do p1=$CCDC_PASSWORD; break; done
  while [ -z "${CCDC_PASSWORD:-}" ]; do
    read -r -s -p "  New password: " p1 </dev/tty; echo
    read -r -s -p "  Again:        " p2 </dev/tty; echo
    [ "$p1" = "$p2" ] || { flag "did not match"; continue; }
    [ ${#p1} -ge 12 ] || { flag "use at least 12 characters"; continue; }
    [[ $p1 == *:* ]] && { flag "no colons (chpasswd uses them)"; continue; }
    break
  done
  local changed=""
  for u in $USERS root; do
    if ! grep -q "^$u:" /etc/passwd; then
      getent passwd "$u" >/dev/null && note "$u is a domain/remote account; change it on the DC" \
                                     || note "$u does not exist here"
      continue
    fi
    if printf '%s:%s\n' "$u" "$p1" | chpasswd; then changed="$changed $u"; else flag "failed for $u"; fi
  done
  good "changed:$changed"
  if command -v doveconf >/dev/null 2>&1; then
    doveconf -n 2>/dev/null | grep -A3 '^passdb' | grep -q 'passwd-file' \
      && flag "Dovecot uses a passwd-file, not system passwords. Update that file too or POP3 logins keep the old password."
  fi
  printf '\n  %sPCR for Quotient (box %s):%s\n' "$B" "$(hostname)" "$N"
  for u in $changed; do [ "$u" = root ] || echo "    $u"; done
  echo "  (all set to the password you just typed)"
  PW=$p1
}

step_users() {
  hdr "Unexpected accounts"
  while IFS=: read -r u _ uid _ _ _ shell; do
    case $shell in */nologin|*/false|"") continue;; esac
    [[ " $USERS $SERVICE_OK " == *" $u "* ]] && continue
    if [ "$uid" = 0 ] || [ "$uid" -ge 1000 ]; then
      ask "Lock account '$u' (uid $uid)? It is kept, not deleted." || continue
      usermod -L "$u" && chage -E 0 "$u" && usermod -s /usr/sbin/nologin "$u" 2>/dev/null \
        || usermod -s /sbin/nologin "$u"
      good "locked $u (undo: usermod -U $u; chage -E -1 $u; usermod -s /bin/bash $u)"
    fi
  done </etc/passwd
  for g in $SUDO_GRP admin; do
    local m; m=$(getent group "$g" | cut -d: -f4)
    for u in ${m//,/ }; do
      [[ " $ADMINS " == *" $u "* ]] && continue
      ask "Remove '$u' from group $g?" && gpasswd -d "$u" "$g" >/dev/null && good "removed $u from $g"
    done
  done
}

step_keys() {
  hdr "SSH authorized_keys"
  local q=$STATE/quarantine-keys; local any=0
  for f in /root/.ssh/authorized_keys* /home/*/.ssh/authorized_keys*; do
    [ -s "$f" ] || continue; any=1
    ask "Move $f to quarantine? (scoring uses passwords, not keys)" || continue
    mkdir -p "$q$(dirname "$f")"; mv "$f" "$q$f" && good "moved $f -> $q$f"
  done
  [ $any = 0 ] && good "no keys present"
}

step_sshd() {
  hdr "sshd"
  local c=/etc/ssh/sshd_config
  [ -f $c ] || { note "no sshd_config"; return; }
  ask "Set PermitRootLogin no and PermitEmptyPasswords no (password logins stay on)?" || return
  cp -p $c "$c.ccdc-bak"
  # sshd uses the first value it reads, so put ours at the top.
  { echo "# ccdc-harden"; echo "PermitRootLogin no"; echo "PermitEmptyPasswords no"
    echo "PasswordAuthentication yes"; grep -v '^# ccdc-harden' $c \
      | grep -Ev '^(PermitRootLogin no|PermitEmptyPasswords no|PasswordAuthentication yes)$'; } >"$c.new"
  if sshd -t -f "$c.new"; then
    mv "$c.new" $c; chmod 600 $c
    systemctl reload sshd 2>/dev/null || systemctl reload ssh
    good "sshd updated and reloaded (backup: $c.ccdc-bak)"
  else
    rm -f "$c.new"; flag "new config failed validation; left unchanged"
  fi
}

step_ftp() {
  local c
  for c in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do
    [ -f $c ] || continue
    hdr "vsftpd ($c)"
    grep -qE '^\s*anonymous_enable\s*=\s*YES' $c || { good "anonymous login already off"; return; }
    ask "Turn off anonymous FTP? (scoring logs in as a named user)" || return
    cp -p $c "$c.ccdc-bak"
    sed -i -E 's/^\s*anonymous_enable\s*=.*/anonymous_enable=NO/' $c
    systemctl restart vsftpd
    if systemctl is-active -q vsftpd; then good "anonymous FTP off"
    else cp -p "$c.ccdc-bak" $c; systemctl restart vsftpd; flag "vsftpd failed to start; config restored"; fi
  done
}

step_unneeded() {
  hdr "Unneeded network services"
  local s
  for s in telnet.socket inetd xinetd rsh.socket rlogin.socket tftp.socket avahi-daemon cups; do
    systemctl is-active -q "$s" 2>/dev/null || continue
    grep -qx "$s" "$PROTECTED" 2>/dev/null && { note "$s owns a listening port; leaving it"; continue; }
    ask "Stop and disable $s?" && systemctl disable --now "$s" >/dev/null 2>&1 && good "disabled $s"
  done
}

ftp_pasv_range() {  # prints "min:max" if vsftpd/proftpd pins a passive range
  local c lo hi
  for c in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do
    [ -f $c ] || continue
    lo=$(grep -oP '^\s*pasv_min_port\s*=\s*\K[0-9]+' $c); hi=$(grep -oP '^\s*pasv_max_port\s*=\s*\K[0-9]+' $c)
    [ -n "$lo" ] && [ -n "$hi" ] && { echo "$lo:$hi"; return; }
  done
  for c in /etc/proftpd.conf /etc/proftpd/proftpd.conf; do
    [ -f $c ] || continue
    read -r lo hi < <(grep -oP '^\s*PassivePorts\s+\K[0-9]+\s+[0-9]+' $c)
    [ -n "$lo" ] && [ -n "$hi" ] && { echo "$lo:$hi"; return; }
  done
}

step_firewall() {
  hdr "Host firewall (inbound only; outbound stays open)"
  if [ "$YES" = 1 ] && [ "$FIREWALL" = 0 ]; then note "skipped (add --firewall to include)"; return; fi
  # Allow every scored port plus every port something listens on now,
  # so an unusual port for a scored service is not cut off.
  local tcp udp
  tcp=$( { echo $SCORED_TCP | tr ' ' '\n'; listeners | awk '$1=="tcp"{print $5}' | grep -oE '[0-9]+$'; } | sort -nu | tr '\n' ' ')
  udp=$( { echo $SCORED_UDP | tr ' ' '\n'; listeners | awk '$1=="udp"{print $5}' | grep -oE '[0-9]+$'; } | sort -nu | tr '\n' ' ')
  local pasv; pasv=$(ftp_pasv_range)
  info "TCP allowed: $tcp"; info "UDP allowed: $udp"
  if [ -n "$pasv" ]; then info "FTP passive range allowed: $pasv"
  else info "FTP passive ports: handled by the FTP connection-tracking helper"; fi
  info "Review the list: any port above that is not a real service can be closed later."
  ask "Apply these inbound rules (all source IPs allowed)?" || return

  # Keep the very first snapshot so a second run cannot overwrite it.
  [ -f "$STATE/iptables-before.rules" ] || iptables-save >"$STATE/iptables-before.rules" 2>/dev/null
  if [ $FAM = rpm ] && systemctl is-active -q firewalld; then
    firewall-cmd --list-all >"$STATE/firewalld-before.txt"
    for p in $tcp; do firewall-cmd -q --permanent --add-port="$p/tcp"; done
    # The ftp service loads the FTP helper so passive data connections work.
    firewall-cmd -q --permanent --add-service=ftp
    [ -n "$pasv" ] && firewall-cmd -q --permanent --add-port="${pasv/:/-}/tcp"
    for p in $udp; do firewall-cmd -q --permanent --add-port="$p/udp"; done
    firewall-cmd -q --reload && good "firewalld updated (ports added, nothing removed)"
    return
  fi
  modprobe nf_conntrack_ftp 2>/dev/null
  iptables -N CCDC-IN 2>/dev/null || iptables -F CCDC-IN
  iptables -A CCDC-IN -i lo -j ACCEPT
  iptables -A CCDC-IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -A CCDC-IN -p icmp -j ACCEPT
  for p in $tcp; do iptables -A CCDC-IN -p tcp --dport "$p" -j ACCEPT; done
  for p in $udp; do iptables -A CCDC-IN -p udp --dport "$p" -j ACCEPT; done
  [ -n "$pasv" ] && iptables -A CCDC-IN -p tcp --dport "$pasv" -j ACCEPT
  # Passive FTP data ports: let the FTP conntrack helper mark them RELATED.
  iptables -t raw -C PREROUTING -p tcp --dport 21 -j CT --helper ftp 2>/dev/null \
    || iptables -t raw -A PREROUTING -p tcp --dport 21 -j CT --helper ftp 2>/dev/null
  iptables -C INPUT -j CCDC-IN 2>/dev/null || iptables -I INPUT 1 -j CCDC-IN
  iptables -A CCDC-IN -j DROP
  good "iptables applied. Undo: sudo $HERE/harden.sh restore-firewall"
  [ $FAM = deb ] && command -v netfilter-persistent >/dev/null && netfilter-persistent save >/dev/null 2>&1
}

step_verify() {
  hdr "Verify protected services"
  local u bad=0
  while read -r u; do
    [ -n "$u" ] || continue
    if systemctl is-active -q "$u"; then good "$u active"
    else
      flag "$u is not active, restarting"; systemctl restart "$u"
      systemctl is-active -q "$u" && good "$u recovered" || { flag "$u still down: check journalctl -xeu $u"; bad=1; }
    fi
  done <"$PROTECTED"
  if [ -n "${PW:-}" ] && command -v curl >/dev/null; then
    local who; who=$(for u in $USERS; do grep -q "^$u:" /etc/passwd && { echo "$u"; break; }; done)
    if [ -n "$who" ]; then
      listeners | grep -q ':21 ' && { curl -s -m 5 --list-only ftp://127.0.0.1/ --user "$who:$PW" >/dev/null \
        && good "FTP login works as $who (local test)" || flag "FTP login as $who FAILED"; }
      listeners | grep -q ':110 ' && ! curl -V | grep -qi pop3 && note "POP3 local test skipped (this curl has no POP3); use scorecheck.sh"
      listeners | grep -q ':110 ' && curl -V | grep -qi pop3 && { curl -s -m 5 pop3://127.0.0.1/ --user "$who:$PW" >/dev/null \
        && good "POP3 login works as $who (local test; dovecot trusts localhost, confirm with scorecheck.sh)" || flag "POP3 login as $who FAILED"; }
    fi
  fi
  return $bad
}

step_watchdog() {
  hdr "Service watchdog"
  ask "Install a watchdog that restarts protected services every minute?" || return
  install -m 700 "$HERE/watchdog.sh" /usr/local/sbin/ccdc-watchdog
  cat >/etc/systemd/system/ccdc-watchdog.service <<EOF
[Unit]
Description=CCDC service watchdog
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/ccdc-watchdog
EOF
  cat >/etc/systemd/system/ccdc-watchdog.timer <<EOF
[Unit]
Description=Run CCDC watchdog every minute
[Timer]
OnBootSec=30
OnUnitActiveSec=60
[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload && systemctl enable --now ccdc-watchdog.timer >/dev/null 2>&1 \
    && good "watchdog on (log: /var/log/ccdc-watchdog.log)"
}

# ------------------------------------------------------------------ main ---
case $MODE in
  audit)
    audit_all
    echo; info "Audit only. Nothing was changed. Log: $LOG" ;;
  harden)
    [ "$YES" = 1 ] && info "Auto mode: safe steps run without prompts." || info "Confirm mode: you approve each step."
    step_backup
    record_protected
    step_passwords
    step_users
    step_keys
    step_sshd
    step_ftp
    step_unneeded
    step_firewall
    step_verify
    step_watchdog
    hdr "Done"
    info "Backup: ${BK:-none}   Log: $LOG"
    info "Next: run 'sudo $0 audit' and review every [!!] line."
    info "Remember to submit the PCR list above in Quotient." ;;
  restore-firewall)
    # Remove what this script added, then load the original snapshot.
    while iptables -D INPUT -j CCDC-IN 2>/dev/null; do :; done
    iptables -F CCDC-IN 2>/dev/null; iptables -X CCDC-IN 2>/dev/null
    iptables -t raw -D PREROUTING -p tcp --dport 21 -j CT --helper ftp 2>/dev/null
    if [ -s "$STATE/iptables-before.rules" ]; then
      iptables-restore <"$STATE/iptables-before.rules" && good "original iptables rules restored"
    fi
    good "script firewall rules removed"
    [ $FAM = deb ] && command -v netfilter-persistent >/dev/null && netfilter-persistent save >/dev/null 2>&1
    if [ -f "$STATE/firewalld-before.txt" ]; then
      note "firewalld: ports were only added. Remove with firewall-cmd --permanent --remove-port=P/tcp"
    fi ;;
  *) echo "usage: $0 {audit|harden [--yes] [--firewall]|restore-firewall}"; exit 2 ;;
esac
