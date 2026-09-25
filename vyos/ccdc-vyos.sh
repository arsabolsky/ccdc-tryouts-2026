#!/bin/vbash
# ccdc-vyos.sh - audit and harden the VyOS router (bedrock).
#
#   ./ccdc-vyos.sh audit            read-only report (default)
#   ./ccdc-vyos.sh harden           password, SSH on LAN only, remove extra users/keys/tasks
#   ./ccdc-vyos.sh firewall         add a WAN->LAN filter that allows scored ports
#
# Every change is applied with commit-confirm: if you do not type
#   configure; confirm; save; exit
# within the window, VyOS rolls the change back by itself.
# Test with tools/scorecheck.sh from outside before confirming.
#
# Run as the vyos user:  chmod +x ccdc-vyos.sh && ./ccdc-vyos.sh audit
source /opt/vyatta/etc/functions/script-template

MODE=${1:-audit}
CONFIRM_MIN=10
LAN_IP=172.16.1.1
SERVERS="172.16.1.10 172.16.1.11 172.16.1.12"
SCORED_TCP="21 22 53 80 88 110 135 389 443 445 464 636 995 3268 3269 3389 8000 9997"
SCORED_UDP="53 88 123 389 464"

hdr()  { echo; echo "== $* =="; }
cfg()  { run show configuration commands; }

WAN_IF=$(ip -o -4 addr show | awk '$4 ~ /^192\.168\.2[0-9][0-9]\./ {print $2; exit}')

audit() {
  hdr "Interfaces (WAN guess: ${WAN_IF:-unknown})"
  run show interfaces
  hdr "Login users and keys (should be only: vyos, no unknown keys)"
  cfg | grep -E 'system login user' | grep -Ev 'encrypted-password|plaintext-password'
  hdr "NAT rules (expect 1:1 NAT for .10 .11 .12 only)"
  cfg | grep -E '^set nat '
  hdr "Firewall"
  cfg | grep -E '^set firewall ' | head -80
  hdr "Services listening on the router"
  cfg | grep -E '^set service '
  hdr "Scheduled tasks (red team persistence spot)"
  cfg | grep -E 'system task-scheduler' || echo "  none"
  hdr "Boot scripts (red team persistence spot)"
  for f in /config/scripts/vyos-preconfig-bootup.script /config/scripts/vyos-postconfig-bootup.script; do
    echo "--- $f"; grep -Ev '^\s*(#|$)' "$f" 2>/dev/null || echo "  (empty)"
  done
  ls -la /config/scripts/ 2>/dev/null
  hdr "Current sessions"
  who
}

ensure_reload_action() {
  # commit-confirm reads the rollback action from the RUNNING config, and the
  # default is "reboot". Commit "reload" on its own first so an unconfirmed
  # change only reloads the previous config instead of rebooting the router.
  if ! cfg | grep -q "commit-confirm action 'reload'"; then
    set system config-management commit-confirm action reload
    commit && echo "  rollback action set to reload"
  fi
}

commit_safely() {
  if commit-confirm $CONFIRM_MIN no-prompt; then
    echo
    echo "  Committed with a $CONFIRM_MIN-minute rollback timer."
    echo "  1) From your laptop:  tools/scorecheck.sh <team#> steve '<password>'"
    echo "  2) If every service is UP:   configure; confirm; save; exit"
    echo "  3) If anything broke: do nothing - the previous config reloads in $CONFIRM_MIN minutes"
  else
    echo "  commit failed; discarding changes"; discard
  fi
  exit
}

harden() {
  configure
  ensure_reload_action
  hdr "Router password"
  local p1 p2
  while true; do
    read -r -s -p "  New password for vyos: " p1; echo
    read -r -s -p "  Again: " p2; echo
    [ "$p1" = "$p2" ] && [ ${#p1} -ge 12 ] && break
    echo "  mismatch or shorter than 12 characters"
  done
  set system login user vyos authentication plaintext-password "$p1"

  hdr "Extra login users"
  for u in $(cfg | awk '$1=="set" && $3=="login" && $4=="user" {print $5}' | tr -d "'" | sort -u); do
    [ "$u" = vyos ] && continue
    read -r -p "  Delete router login user '$u'? [y/N] " r
    [[ $r =~ ^[Yy] ]] && delete system login user "$u" && echo "  deleted $u"
  done

  hdr "SSH keys on vyos user"
  if cfg | grep -q "login user vyos authentication public-keys"; then
    read -r -p "  Remove all SSH public keys from vyos? [y/N] " r
    [[ $r =~ ^[Yy] ]] && delete system login user vyos authentication public-keys && echo "  removed"
  else echo "  none"; fi

  hdr "SSH: listen on LAN only ($LAN_IP)"
  if cfg | grep -q '^set service ssh'; then
    delete service ssh listen-address 2>/dev/null
    set service ssh listen-address $LAN_IP
    echo "  set (manage the router from the Proxmox console or from a LAN box)"
  fi

  hdr "HTTPS API"
  if cfg | grep -q '^set service https'; then
    read -r -p "  The HTTPS API is enabled. Delete it? [y/N] " r
    [[ $r =~ ^[Yy] ]] && delete service https && echo "  deleted"
  else echo "  not enabled"; fi

  hdr "Scheduled tasks"
  for t in $(cfg | awk '/system task-scheduler task/ {print $5}' | tr -d "'" | sort -u); do
    cfg | grep "task-scheduler task $t "
    read -r -p "  Delete task '$t'? [y/N] " r
    [[ $r =~ ^[Yy] ]] && delete system task-scheduler task "$t" && echo "  deleted $t"
  done

  commit_safely
}

firewall() {
  [ -n "$WAN_IF" ] || { echo "Could not find the WAN interface (192.168.2xx.x)."; exit 1; }
  echo "WAN interface: $WAN_IF. Allowing TCP $SCORED_TCP and UDP $SCORED_UDP"
  echo "to $SERVERS from ANY source. Everything else new from WAN is dropped."
  read -r -p "Continue? [y/N] " r; [[ $r =~ ^[Yy] ]] || exit 0
  configure
  ensure_reload_action
  delete firewall ipv4 name CCDC-WAN-IN 2>/dev/null
  delete firewall group port-group CCDC-TCP 2>/dev/null
  delete firewall group port-group CCDC-UDP 2>/dev/null
  delete firewall group address-group CCDC-SERVERS 2>/dev/null
  for a in $SERVERS;    do set firewall group address-group CCDC-SERVERS address "$a"; done
  for p in $SCORED_TCP; do set firewall group port-group CCDC-TCP port "$p"; done
  for p in $SCORED_UDP; do set firewall group port-group CCDC-UDP port "$p"; done
  # FTP passive data connections are tracked as RELATED by the ftp helper.
  set system conntrack modules ftp 2>/dev/null
  N="firewall ipv4 name CCDC-WAN-IN"
  set $N default-action drop
  set $N rule 10 action accept
  set $N rule 10 state established
  set $N rule 10 state related
  set $N rule 20 action drop
  set $N rule 20 state invalid
  set $N rule 30 action accept
  set $N rule 30 protocol tcp
  set $N rule 30 destination group address-group CCDC-SERVERS
  set $N rule 30 destination group port-group CCDC-TCP
  set $N rule 40 action accept
  set $N rule 40 protocol udp
  set $N rule 40 destination group address-group CCDC-SERVERS
  set $N rule 40 destination group port-group CCDC-UDP
  set $N rule 50 action accept
  set $N rule 50 protocol icmp
  set firewall ipv4 forward filter rule 5 action jump
  set firewall ipv4 forward filter rule 5 jump-target CCDC-WAN-IN
  set firewall ipv4 forward filter rule 5 inbound-interface name "$WAN_IF"
  commit_safely
}

case $MODE in
  audit)    audit ;;
  harden)   harden ;;
  firewall) firewall ;;
  *) echo "usage: $0 {audit|harden|firewall}"; exit 2 ;;
esac
